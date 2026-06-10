use std::path::{Path, PathBuf};
use tokio::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum TmuxError {
    #[error("tmux io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tmux failed: {stderr}")]
    Failed { stderr: String },
    #[error("tmux output parse error: {0}")]
    Parse(String),
}

pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("tmux.sock")
}

pub fn session_name(id: &str) -> String {
    format!("aidc_{id}")
}

/// Run `tmux -S <socket> <args...>`; returns Ok(stdout bytes) on success, else Err(Failed { stderr }).
pub async fn run(data_dir: &Path, args: &[&str]) -> Result<Vec<u8>, TmuxError> {
    let sock = socket_path(data_dir);
    let output = Command::new("tmux")
        .env_remove("TMUX")
        .env("TERM", "xterm-256color")
        .arg("-S")
        .arg(&sock)
        .args(args)
        .output()
        .await?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(TmuxError::Failed {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub async fn has_session(data_dir: &Path, name: &str) -> bool {
    run(data_dir, &["has-session", "-t", name]).await.is_ok()
}

pub async fn kill_session(data_dir: &Path, name: &str) -> Result<(), TmuxError> {
    run(data_dir, &["kill-session", "-t", name]).await?;
    Ok(())
}

pub async fn list_sessions(data_dir: &Path) -> Vec<String> {
    match run(data_dir, &["list-sessions", "-F", "#{session_name}"]).await {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            text.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        }
        Err(_) => vec![],
    }
}

pub async fn capture_pane(data_dir: &Path, name: &str, lines: u32) -> Result<Vec<u8>, TmuxError> {
    run(
        data_dir,
        &[
            "capture-pane",
            "-t",
            name,
            "-e",
            "-p",
            "-S",
            &format!("-{lines}"),
        ],
    )
    .await
}

/// PID of the shell running in the session's pane. Used to resolve the
/// session's working directory via `/proc/<pid>/cwd`, since the server only
/// holds the tmux client process, not the shell itself (Go: tmuxPanePID).
pub async fn pane_pid(data_dir: &Path, name: &str) -> Result<u32, TmuxError> {
    let out = run(
        data_dir,
        &["display-message", "-p", "-t", name, "#{pane_pid}"],
    )
    .await?;
    let text = String::from_utf8_lossy(&out);
    text.trim()
        .parse()
        .map_err(|_| TmuxError::Parse(format!("pane_pid not a number: {:?}", text.trim())))
}

pub fn attach_args(data_dir: &Path, name: &str, shell: &str) -> Vec<String> {
    let sock = socket_path(data_dir);
    vec![
        "-S".to_string(),
        sock.to_string_lossy().into_owned(),
        "new-session".to_string(),
        "-A".to_string(),
        "-s".to_string(),
        name.to_string(),
        "--".to_string(),
        shell.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_pure_functions() {
        let dir = tempdir().unwrap();
        let sock = socket_path(dir.path());
        assert_eq!(sock, dir.path().join("tmux.sock"));

        let name = session_name("abc123");
        assert_eq!(name, "aidc_abc123");
    }

    #[tokio::test]
    async fn test_has_session_create_and_check() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let sess = "aidc_t1";

        // Create a detached session
        run(
            data_dir,
            &["new-session", "-d", "-s", sess, "--", "/bin/sh"],
        )
        .await
        .expect("new-session should succeed");

        // has_session should be true for it
        assert!(has_session(data_dir, sess).await, "session should exist");

        // has_session should be false for a nonexistent session
        assert!(
            !has_session(data_dir, "aidc_nope").await,
            "nonexistent session should not exist"
        );

        // Cleanup
        kill_session(data_dir, sess)
            .await
            .expect("kill should succeed");
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let sess = "aidc_t2";

        // Fresh tempdir: no server, should return empty vec
        let empty = list_sessions(data_dir).await;
        assert!(empty.is_empty(), "no server yet → empty list");

        // Create a session
        run(
            data_dir,
            &["new-session", "-d", "-s", sess, "--", "/bin/sh"],
        )
        .await
        .expect("new-session should succeed");

        let sessions = list_sessions(data_dir).await;
        assert!(
            sessions.contains(&sess.to_string()),
            "list should contain our session"
        );

        // Cleanup
        kill_session(data_dir, sess)
            .await
            .expect("kill should succeed");
    }

    #[tokio::test]
    async fn test_capture_pane() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let sess = "aidc_t3";

        // Create a detached session
        run(
            data_dir,
            &["new-session", "-d", "-s", sess, "--", "/bin/sh"],
        )
        .await
        .expect("new-session should succeed");

        // Send echo command
        run(
            data_dir,
            &["send-keys", "-t", sess, "echo captureproof", "Enter"],
        )
        .await
        .expect("send-keys should succeed");

        // Poll up to ~2s for output to appear
        let mut found = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let output = capture_pane(data_dir, sess, 100)
                .await
                .expect("capture-pane should succeed");
            let text = String::from_utf8_lossy(&output);
            if text.contains("captureproof") {
                found = true;
                break;
            }
        }

        // Cleanup
        kill_session(data_dir, sess)
            .await
            .expect("kill should succeed");

        assert!(found, "capture_pane should eventually contain captureproof");
    }

    #[tokio::test]
    async fn test_kill_session() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let sess = "aidc_t4";

        // Create a detached session
        run(
            data_dir,
            &["new-session", "-d", "-s", sess, "--", "/bin/sh"],
        )
        .await
        .expect("new-session should succeed");

        assert!(
            has_session(data_dir, sess).await,
            "should exist before kill"
        );

        kill_session(data_dir, sess)
            .await
            .expect("kill should succeed");

        assert!(
            !has_session(data_dir, sess).await,
            "should not exist after kill"
        );
        assert!(
            list_sessions(data_dir).await.is_empty(),
            "list should be empty after kill"
        );
    }

    #[tokio::test]
    async fn test_run_failure_path() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let sess = "aidc_t5_live";

        // Start a live server by creating a session
        run(
            data_dir,
            &["new-session", "-d", "-s", sess, "--", "/bin/sh"],
        )
        .await
        .expect("new-session should succeed");

        // Attempt to kill a nonexistent session on a live server → should fail
        let result = run(data_dir, &["kill-session", "-t", "nonexistent"]).await;
        assert!(result.is_err(), "kill nonexistent should error");
        if let Err(TmuxError::Failed { stderr }) = result {
            assert!(!stderr.is_empty(), "stderr should be non-empty");
        } else {
            panic!("expected TmuxError::Failed");
        }

        // Cleanup
        kill_session(data_dir, sess)
            .await
            .expect("kill should succeed");
    }

    #[tokio::test]
    async fn test_pane_pid() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let sess = "aidc_t6";

        // Create a detached session
        run(
            data_dir,
            &["new-session", "-d", "-s", sess, "--", "/bin/sh"],
        )
        .await
        .expect("new-session should succeed");

        let pid = pane_pid(data_dir, sess).await.expect("pane_pid Ok");
        assert!(pid > 0, "pane pid must be positive");
        // The pane's process must exist and its /proc cwd link must resolve.
        let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"));
        assert!(cwd.is_ok(), "/proc/{pid}/cwd must be readable: {cwd:?}");

        // Nonexistent session on a live server → Err.
        assert!(
            pane_pid(data_dir, "aidc_nope").await.is_err(),
            "pane_pid of nonexistent session must error"
        );

        // Cleanup
        kill_session(data_dir, sess)
            .await
            .expect("kill should succeed");
    }

    #[test]
    fn test_attach_args() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let name = "aidc_test";
        let shell = "/bin/bash";

        let args = attach_args(data_dir, name, shell);
        assert_eq!(args[0], "-S");
        assert!(args[1].ends_with("tmux.sock"));
        assert_eq!(args[2], "new-session");
        assert_eq!(args[3], "-A");
        assert_eq!(args[4], "-s");
        assert_eq!(args[5], name);
        assert_eq!(args[6], "--");
        assert_eq!(args[7], shell);
    }
}
