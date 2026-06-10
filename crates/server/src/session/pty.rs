//! PTY-backed tmux session runtime.
//
//! Each `PtyHandle` holds one PTY attached to a tmux session via
//! `tmux new-session -A`. Output is broadcast to all subscribers; any
//! caller may write input or resize the terminal.

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use portable_pty::{CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use tokio::sync::broadcast;

use super::modes::ModeState;

#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("pty error: {0}")]
    Pty(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct PtyHandle {
    /// Broadcast channel carrying raw bytes from the PTY reader thread.
    pub output: broadcast::Sender<Vec<u8>>,
    writer: Mutex<Box<dyn std::io::Write + Send>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    /// Unix seconds of most recent output activity.
    pub last_activity: Arc<AtomicI64>,
    /// Session-level DEC private mode tracker (spec §4.3), fed by the reader
    /// thread before broadcast so every client sees a consistent view.
    pub modes: Arc<Mutex<ModeState>>,
    child: Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
    /// Signals true once the PTY reader thread exits (child process ended).
    exited: tokio::sync::watch::Sender<bool>,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl PtyHandle {
    /// Spawn a tmux attach PTY for `name` in `data_dir` running `shell`.
    pub fn spawn(
        data_dir: &Path,
        name: &str,
        shell: &str,
        rows: u16,
        cols: u16,
    ) -> Result<Arc<Self>, PtyError> {
        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::Pty(e.to_string()))?;

        // Build the tmux attach command using args from the tmux crate.
        let attach_args = tmux::attach_args(data_dir, name, shell);
        let mut cmd = CommandBuilder::new("tmux");
        for arg in &attach_args {
            cmd.arg(arg);
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env_remove("TMUX");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| PtyError::Pty(e.to_string()))?;
        // Drop the slave end -- the child now owns it.
        drop(pair.slave);

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::Pty(e.to_string()))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::Pty(e.to_string()))?;

        let (tx, _rx) = broadcast::channel(1024);
        let last_activity = Arc::new(AtomicI64::new(unix_now()));
        let modes = Arc::new(Mutex::new(ModeState::new()));
        let (exited_tx, _exited_rx) = tokio::sync::watch::channel(false);

        let handle = Arc::new(PtyHandle {
            output: tx.clone(),
            writer: Mutex::new(writer),
            master: Mutex::new(pair.master),
            last_activity: Arc::clone(&last_activity),
            modes: Arc::clone(&modes),
            child: Mutex::new(child),
            exited: exited_tx,
        });

        // Reader thread: forward PTY output to the broadcast channel.
        // Signals `exited` watch when the loop ends (EOF or error).
        let tx_reader = tx;
        let activity = Arc::clone(&last_activity);
        let exited_signal = handle.exited.clone();
        let mut reader = reader;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match std::io::Read::read(&mut reader, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        activity.store(unix_now(), Ordering::Relaxed);
                        // Mode scan runs before broadcast so a client attaching
                        // right after this chunk replays an up-to-date set.
                        modes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .feed(&buf[..n]);
                        tx_reader.send(buf[..n].to_vec()).ok();
                    }
                }
            }
            exited_signal.send_replace(true);
        });

        Ok(handle)
    }

    /// Returns a receiver that fires (true) when the PTY child process exits.
    pub fn exited_rx(&self) -> tokio::sync::watch::Receiver<bool> {
        self.exited.subscribe()
    }

    /// Write bytes to the PTY (stdin of the tmux client).
    pub fn write(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        w.write_all(bytes)?;
        w.flush()
    }

    /// Resize the PTY window.
    ///
    /// Serialization (spec §4.4): the `master` mutex makes each TIOCSWINSZ
    /// atomic per session, so a storm of resize frames — even from multiple
    /// clients — cannot interleave and tmux converges on the last size.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        let master = self.master.lock().unwrap_or_else(|e| e.into_inner());
        master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::Pty(e.to_string()))
    }

    /// Kill the PTY child process. The tmux session itself survives on the server.
    pub fn detach(&self) {
        let mut child = self.child.lock().unwrap_or_else(|e| e.into_inner());
        child.kill().ok();
        // Reap: kill() doesnt wait, and std Child doesnt reap on drop --
        // without this every detach leaves a zombie until server exit.
        child.wait().ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    /// Collect broadcast frames until predicate returns true or timeout expires.
    async fn collect_until(
        rx: &mut broadcast::Receiver<Vec<u8>>,
        timeout: Duration,
        pred: impl Fn(&[u8]) -> bool,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut accumulated = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(chunk)) => {
                    accumulated.extend_from_slice(&chunk);
                    if pred(&accumulated) {
                        return true;
                    }
                }
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                _ => return false,
            }
        }
    }

    #[tokio::test]
    async fn pty_echo_roundtrip() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let id = "ptyt1";
        let name = tmux::session_name(id);

        let handle =
            PtyHandle::spawn(data_dir, &name, "/bin/sh", 24, 80).expect("spawn should succeed");

        let mut rx = handle.output.subscribe();

        // Give tmux a moment to attach.
        tokio::time::sleep(Duration::from_millis(300)).await;

        handle
            .write(b"echo m2proof\n")
            .expect("write should succeed");

        let found = collect_until(&mut rx, Duration::from_secs(5), |buf| {
            buf.windows(7).any(|w| w == b"m2proof")
        })
        .await;

        // Cleanup.
        handle.detach();
        tmux::kill_session(data_dir, &name).await.ok();

        assert!(found, "broadcast should contain m2proof");
    }

    #[tokio::test]
    async fn pty_resize_reflects_in_tmux() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let id = "ptyt2";
        let name = tmux::session_name(id);

        let handle =
            PtyHandle::spawn(data_dir, &name, "/bin/sh", 24, 80).expect("spawn should succeed");

        tokio::time::sleep(Duration::from_millis(300)).await;

        handle.resize(40, 120).expect("resize should succeed");

        // Poll tmux display-message for the new width.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut width_ok = false;
        while std::time::Instant::now() < deadline {
            if let Ok(out) = tmux::run(
                data_dir,
                &["display-message", "-p", "-t", &name, "#{window_width}"],
            )
            .await
            {
                let s = String::from_utf8_lossy(&out);
                if s.trim() == "120" {
                    width_ok = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        handle.detach();
        tmux::kill_session(data_dir, &name).await.ok();

        assert!(width_ok, "tmux window_width should become 120");
    }

    #[tokio::test]
    async fn detach_leaves_tmux_session_alive() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let id = "ptyt3";
        let name = tmux::session_name(id);

        let handle =
            PtyHandle::spawn(data_dir, &name, "/bin/sh", 24, 80).expect("spawn should succeed");

        tokio::time::sleep(Duration::from_millis(300)).await;

        handle.detach();

        // Give the child time to die.
        tokio::time::sleep(Duration::from_millis(400)).await;

        let alive = tmux::has_session(data_dir, &name).await;

        tmux::kill_session(data_dir, &name).await.ok();

        assert!(alive, "tmux session should still exist after PTY detach");
    }

    #[tokio::test]
    async fn exited_rx_fires_when_child_exits() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let id = "ptyt4";
        let name = tmux::session_name(id);

        let handle =
            PtyHandle::spawn(data_dir, &name, "/bin/sh", 24, 80).expect("spawn should succeed");

        let mut exited_rx = handle.exited_rx();
        // Should not yet be true.
        assert!(!*exited_rx.borrow());

        tokio::time::sleep(Duration::from_millis(300)).await;
        // Kill the tmux session, which causes the PTY child to exit.
        tmux::kill_session(data_dir, &name).await.ok();
        handle.detach();

        // Wait up to 3s for the exited signal.
        let fired = tokio::time::timeout(Duration::from_secs(3), exited_rx.changed()).await;
        assert!(fired.is_ok(), "exited_rx should fire within 3s");
        assert!(*exited_rx.borrow(), "exited value must be true");
    }
}
