//! Image paste delivery (Go parity: internal/session/paste.go).
//!
//! Primary path: write the image to the server's system clipboard and send
//! Ctrl+V so a clipboard-aware program (e.g. Claude Code) reads it.
//!
//! Fallback (no display / no clipboard tool): save the image to a file under
//! the store dir and type its absolute path into the terminal, so the program
//! can read the image from disk.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::session::Session;

/// The byte produced by Ctrl+V (SYN). Claude Code reads the system clipboard
/// (and attaches any image it finds) when it receives this.
const CTRL_V: u8 = 0x16;

const CLIPBOARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Environment lookup, injectable for tests (same pattern as Config::from_lookup).
pub type EnvLookup<'a> = &'a (dyn Fn(&str) -> Option<String> + Sync);

#[derive(Debug, thiserror::Error)]
pub enum PasteError {
    #[error("empty image data")]
    EmptyData,
    #[error("save pasted image: {0}")]
    Save(#[source] std::io::Error),
    #[error("write to pty: {0}")]
    PtyWrite(#[source] std::io::Error),
}

impl Session {
    /// Deliver a pasted image to the program running in the PTY.
    ///
    /// Clipboard first (then Ctrl+V to the pty); on any clipboard error, save
    /// under `<store_dir>/<id>/pastes/` and type the absolute path instead.
    pub async fn paste_image(
        &self,
        data: &[u8],
        mime: &str,
        store_dir: &Path,
    ) -> Result<(), PasteError> {
        self.paste_image_with_env(data, mime, store_dir, &|key| std::env::var(key).ok())
            .await
    }

    /// [`Self::paste_image`] with an injectable environment lookup so tests can
    /// force the no-display fallback without mutating process-global env vars.
    pub async fn paste_image_with_env(
        &self,
        data: &[u8],
        mime: &str,
        store_dir: &Path,
        env: EnvLookup<'_>,
    ) -> Result<(), PasteError> {
        if data.is_empty() {
            return Err(PasteError::EmptyData);
        }
        let mime = if mime.is_empty() { "image/png" } else { mime };

        match copy_image_to_clipboard(data, mime, env).await {
            Ok(()) => return self.pty.write(&[CTRL_V]).map_err(PasteError::PtyWrite),
            Err(e) => tracing::info!(
                "session {}: clipboard unavailable ({e}), falling back to file path",
                self.id
            ),
        }

        let path = save_image_file(data, mime, store_dir, &self.id)
            .await
            .map_err(PasteError::Save)?;
        // Trailing space delimits the path from anything typed next.
        self.pty
            .write(format!("{} ", path.display()).as_bytes())
            .map_err(PasteError::PtyWrite)
    }
}

/// Push image bytes onto the system clipboard using wl-copy (Wayland) or
/// xclip (X11). Returns an error if no display server or clipboard tool is
/// available.
async fn copy_image_to_clipboard(
    data: &[u8],
    mime: &str,
    env: EnvLookup<'_>,
) -> std::io::Result<()> {
    let wayland = env("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
    let x11 = env("DISPLAY").is_some_and(|v| !v.is_empty());
    if !wayland && !x11 {
        return Err(std::io::Error::other("no display available"));
    }

    let mut cmd = if wayland && has_bin("wl-copy") {
        let mut c = Command::new("wl-copy");
        c.args(["--type", mime]);
        c
    } else if x11 && has_bin("xclip") {
        let mut c = Command::new("xclip");
        c.args(["-selection", "clipboard", "-t", mime, "-i"]);
        c
    } else {
        return Err(std::io::Error::other(
            "no clipboard tool (install wl-clipboard or xclip)",
        ));
    };

    // Route stdout/stderr to /dev/null. These tools fork a background process
    // to own the selection; if it inherited our pipes, wait() would block on
    // them until the daemon exits.
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = cmd.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("no stdin pipe"))?;

    let run = tokio::time::timeout(CLIPBOARD_TIMEOUT, async {
        stdin.write_all(data).await?;
        // Close stdin so the tool sees EOF before we wait on it.
        drop(stdin);
        child.wait().await
    })
    .await;

    match run {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(std::io::Error::other(format!(
            "clipboard tool exited with {status}"
        ))),
        Ok(Err(e)) => Err(e),
        // Timeout: dropping `child` kills it (kill_on_drop).
        Err(_) => Err(std::io::Error::other("clipboard tool timed out")),
    }
}

/// Save image bytes under `<store_dir>/<id>/pastes/paste-<unix_nanos><ext>`
/// and return the absolute path.
async fn save_image_file(
    data: &[u8],
    mime: &str,
    store_dir: &Path,
    id: &str,
) -> std::io::Result<PathBuf> {
    let dir = store_dir.join(id).join("pastes");
    tokio::fs::create_dir_all(&dir).await?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = dir.join(format!("paste-{nanos}{}", ext_for_mime(mime)));
    tokio::fs::write(&path, data).await?;
    // Go parity (filepath.Abs): on failure, fall back to the path as-is.
    Ok(std::path::absolute(&path).unwrap_or(path))
}

/// True when `name` resolves to an executable regular file on PATH
/// (Go exec.LookPath equivalent).
fn has_bin(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        std::fs::metadata(dir.join(name))
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

fn ext_for_mime(mime: &str) -> &'static str {
    match mime {
        "image/png" => ".png",
        "image/jpeg" | "image/jpg" => ".jpg",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "image/bmp" => ".bmp",
        _ => ".png",
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;

    use crate::session::Manager;

    #[test]
    fn ext_for_mime_covers_all_cases_and_default() {
        assert_eq!(ext_for_mime("image/png"), ".png");
        assert_eq!(ext_for_mime("image/jpeg"), ".jpg");
        assert_eq!(ext_for_mime("image/jpg"), ".jpg");
        assert_eq!(ext_for_mime("image/gif"), ".gif");
        assert_eq!(ext_for_mime("image/webp"), ".webp");
        assert_eq!(ext_for_mime("image/bmp"), ".bmp");
        assert_eq!(ext_for_mime("image/tiff"), ".png", "unknown mime → .png");
        assert_eq!(ext_for_mime(""), ".png", "empty mime → .png");
    }

    #[tokio::test]
    async fn clipboard_errors_without_display() {
        let err = copy_image_to_clipboard(b"x", "image/png", &|_| None)
            .await
            .expect_err("no display vars must error");
        assert!(
            err.to_string().contains("no display"),
            "unexpected error: {err}"
        );
    }

    fn make_manager(dir: &std::path::Path) -> Manager {
        let store = Arc::new(store::Store::open(&dir.join("conductor.db")).expect("store open"));
        Manager::new(
            dir.to_path_buf(),
            "/bin/sh".into(),
            store,
            Duration::ZERO,
            0,
            Duration::from_secs(15),
        )
    }

    #[tokio::test]
    async fn paste_image_empty_data_errors() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let sess = mgr.create(None).await.expect("create");

        let err = sess
            .paste_image_with_env(&[], "image/png", dir.path(), &|_| None)
            .await;
        assert!(
            matches!(err, Err(PasteError::EmptyData)),
            "expected EmptyData, got: {err:?}"
        );
        // Nothing must have been saved.
        assert!(!dir.path().join(&sess.id).join("pastes").exists());

        mgr.delete(&sess.id).await.expect("delete");
    }

    /// No display in env → fallback: file saved under pastes/ with default
    /// .png extension (mime ""), bytes intact, absolute path typed to the pty.
    #[tokio::test]
    async fn paste_image_fallback_saves_file_and_types_path() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let sess = mgr.create(None).await.expect("create");
        // Give tmux a moment for the shell to be ready to echo input.
        tokio::time::sleep(Duration::from_millis(400)).await;

        let payload: &[u8] = b"\x89PNG\r\n\x1a\nfakepayload";
        sess.paste_image_with_env(payload, "", dir.path(), &|_| None)
            .await
            .expect("fallback paste must succeed");

        let pastes = dir.path().join(&sess.id).join("pastes");
        let entries: Vec<_> = std::fs::read_dir(&pastes)
            .expect("pastes dir must exist")
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1, "exactly one saved paste");
        let path = entries[0].path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("paste-") && name.ends_with(".png"),
            "mime \"\" must default to .png: {name}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), payload, "bytes must match");

        // The absolute path (typed with a trailing space) appears in the pane.
        let needle = std::path::absolute(&path).unwrap().display().to_string();
        let tmux_name = tmux::session_name(&sess.id);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut found = false;
        while std::time::Instant::now() < deadline {
            if let Ok(bytes) = tmux::capture_pane(dir.path(), &tmux_name, 50).await {
                if String::from_utf8_lossy(&bytes).contains(&needle) {
                    found = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(found, "pane must contain the typed path {needle}");

        mgr.delete(&sess.id).await.expect("delete");
    }
}
