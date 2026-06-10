//! File transfer handlers: upload into / download from the session's working
//! directory.
//!
//! Go parity notes (api/handlers.go, feat/file-transfer):
//!
//! **Working directory** (`sessionCWD`):
//!   Go looks the session up via `mgr.Get(id)` (live sessions only) -- 404
//!   `{"error":"session not found"}` if absent -- then resolves the shell's
//!   cwd via `/proc/<pane_pid>/cwd` (Linux only); a resolution failure is 503
//!   `{"error":"cannot resolve working directory"}`. We match both bodies.
//!
//! **Upload** (`POST /api/sessions/:id/upload`):
//!   Go wraps the body in `http.MaxBytesReader` and calls `ParseMultipartForm`,
//!   so an over-limit body AND a malformed/non-multipart body both yield the
//!   same 413 `{"error":"upload too large or malformed"}`. We match that
//!   conflation: any multipart extraction/read error (including axum's
//!   `DefaultBodyLimit` length error, which axum itself surfaces as 413) maps
//!   to that exact body. Filenames collapse to their base name
//!   (`filepath.Base(filepath.Clean("/" + name))`) so traversal can never
//!   escape the working directory.
//!
//! **Download** (`GET /api/sessions/:id/download?path=rel`):
//!   `?path=` is joined onto the cwd and confined via a relative-back check
//!   (`filepath.Rel` must not start with ".."); note Go's `filepath.Join`
//!   treats an absolute `rel` as *relative* (joined under base), so we do too.
//!   A directory or missing file is 404 `{"error":"file not found"}`.

use std::path::{Component, Path as FsPath, PathBuf};

use axum::extract::multipart::MultipartRejection;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use tokio::io::AsyncWriteExt;

use crate::app::SharedState;
use crate::handlers::json_error;

// ---- Pure helpers -----------------------------------------------------------

/// Collapse a client-supplied filename to a safe base name, mirroring Go's
/// `filepath.Base(filepath.Clean("/" + name))` plus its reject conditions
/// (".", "/", empty or whitespace-only). Returns None when the name is invalid.
pub fn sanitize_filename(name: &str) -> Option<String> {
    // Lexical clean of "/<name>": "." and empty segments drop, ".." pops.
    let mut stack: Vec<&str> = Vec::new();
    for seg in name.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    // Base of the cleaned path = last surviving segment; none left means the
    // cleaned path is "/" (Go rejects "." and "/").
    let base = (*stack.last()?).to_string();
    if base.trim().is_empty() {
        return None;
    }
    Some(base)
}

/// Quote a filename like Go's `fmt.Sprintf("%q", name)` (strconv.Quote), as
/// used by the Go download handler for the Content-Disposition filename:
/// wrap in double quotes; escape `"` and `\` with a backslash; named escapes
/// for \a \b \f \n \r \t \v; remaining ASCII control chars and DEL become
/// `\xNN` (lowercase hex). Printable non-ASCII passes through literally, as
/// in Go. Documented divergence: Go additionally \u-escapes *non-printable*
/// non-ASCII runes (per unicode.IsPrint); those never appear in real
/// filenames and Rust has no IsPrint table, so they pass through here.
pub fn go_quote(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    out.push('"');
    for c in name.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c == '\x7f' => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Join `rel` onto `base` and guarantee the result stays within `base`,
/// defeating "../" traversal (Go: confinedPath). Like Go's `filepath.Join`,
/// an absolute `rel` is treated as relative and lands under `base`.
pub fn confine_path(base: &FsPath, rel: &str) -> Option<PathBuf> {
    let mut out = base.to_path_buf();
    for comp in FsPath::new(rel).components() {
        match comp {
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                // Lexical pop, like filepath.Join's Clean. Popping past "/"
                // is a no-op (Clean("/..") == "/"); the starts_with check
                // below still rejects anything that left `base`.
                out.pop();
            }
            Component::Normal(c) => out.push(c),
        }
    }
    if out.starts_with(base) {
        Some(out)
    } else {
        None
    }
}

// ---- Session cwd ------------------------------------------------------------

/// Working directory of the session's shell, resolved via the tmux pane PID
/// and /proc/<pid>/cwd (Linux only; Go: Session.CWD). Tracks `cd` live.
async fn session_cwd(data_dir: &FsPath, session_id: &str) -> Option<PathBuf> {
    let pid = tmux::pane_pid(data_dir, &tmux::session_name(session_id))
        .await
        .ok()?;
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// Shared 404/503 preamble for both handlers (Go: sessionCWD).
async fn resolve_cwd(state: &SharedState, session_id: &str) -> Result<PathBuf, Response> {
    if state.manager.get(session_id).await.is_none() {
        return Err(json_error(StatusCode::NOT_FOUND, "session not found"));
    }
    match session_cwd(&state.cfg.data_dir, session_id).await {
        Some(cwd) => Ok(cwd),
        None => Err(json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cannot resolve working directory",
        )),
    }
}

// ---- Handlers -----------------------------------------------------------------

/// POST /api/sessions/:id/upload -- multipart field "file" written into the
/// session's working directory. 201 {"name","size"} on success.
pub async fn upload(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    multipart: Result<Multipart, MultipartRejection>,
) -> Response {
    let cwd = match resolve_cwd(&state, &id).await {
        Ok(cwd) => cwd,
        Err(resp) => return resp,
    };

    // Non-multipart content type: Go's ParseMultipartForm fails the same way
    // as an over-limit body -- 413 with the conflated message.
    let Ok(mut multipart) = multipart else {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "upload too large or malformed",
        );
    };

    // Walk the form for the "file" field. Stream errors here are either the
    // DefaultBodyLimit cap firing or a malformed body -- 413 either way.
    let (filename, data) = loop {
        match multipart.next_field().await {
            Ok(Some(field)) if field.name() == Some("file") => {
                let filename = field.file_name().unwrap_or_default().to_string();
                match field.bytes().await {
                    Ok(data) => break (filename, data),
                    Err(_) => {
                        return json_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "upload too large or malformed",
                        )
                    }
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => return json_error(StatusCode::BAD_REQUEST, "missing file field"),
            Err(_) => {
                return json_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "upload too large or malformed",
                )
            }
        }
    };

    let Some(name) = sanitize_filename(&filename) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid filename");
    };
    let dest = cwd.join(&name);

    // Go opens with O_CREATE|O_WRONLY|O_TRUNC 0644 and distinguishes the
    // create failure from the write failure; File::create matches the flags.
    let mut out = match tokio::fs::File::create(&dest).await {
        Ok(f) => f,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "cannot create file"),
    };
    // Flush before responding: tokio::fs::File buffers through a blocking
    // task, and dropping it leaves the final write in flight.
    if out.write_all(&data).await.is_err() || out.flush().await.is_err() {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "write failed");
    }

    (
        StatusCode::CREATED,
        Json(json!({"name": name, "size": data.len()})),
    )
        .into_response()
}

/// GET /api/sessions/:id/download?path=rel -- serve a file confined to the
/// session's working directory with an attachment disposition.
pub async fn download(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let cwd = match resolve_cwd(&state, &id).await {
        Ok(cwd) => cwd,
        Err(resp) => return resp,
    };

    // Go's r.URL.Query().Get("path") yields "" for a missing param too.
    let rel = params.get("path").map(String::as_str).unwrap_or("");
    if rel.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "path is required");
    }
    let Some(full) = confine_path(&cwd, rel) else {
        return json_error(StatusCode::FORBIDDEN, "path outside working directory");
    };

    // Stat before opening (Go: os.Stat err or IsDir → 404). Keeping the
    // metadata also supplies Content-Length for the streamed body, matching
    // Go's http.ServeFile.
    let meta = match tokio::fs::metadata(&full).await {
        Ok(m) if m.is_file() => m,
        _ => return json_error(StatusCode::NOT_FOUND, "file not found"),
    };
    // Stream the file instead of buffering it in RAM; an open failure after
    // the successful stat (e.g. the file vanished) is still a plain 404.
    let file = match tokio::fs::File::open(&full).await {
        Ok(f) => f,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "file not found"),
    };
    let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file));

    let basename = full
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mime = mime_guess::from_path(&full).first_or_octet_stream();
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_DISPOSITION,
                // Go: fmt.Sprintf("attachment; filename=%q", filepath.Base(full)).
                format!("attachment; filename={}", go_quote(&basename)),
            ),
            (header::CONTENT_TYPE, mime.essence_str().to_string()),
            (header::CONTENT_LENGTH, meta.len().to_string()),
        ],
        body,
    )
        .into_response()
}

// ---- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Cases mirror Go's filepath.Base(filepath.Clean("/" + name)) semantics.
    #[test]
    fn sanitize_filename_cases() {
        // Plain names pass through.
        assert_eq!(sanitize_filename("hello.txt"), Some("hello.txt".into()));
        // Traversal prefixes collapse to the base name.
        assert_eq!(sanitize_filename("../evil"), Some("evil".into()));
        assert_eq!(
            sanitize_filename("../../escape.txt"),
            Some("escape.txt".into())
        );
        // Absolute paths collapse to the base name.
        assert_eq!(sanitize_filename("/etc/passwd"), Some("passwd".into()));
        // Relative dir prefixes drop.
        assert_eq!(sanitize_filename("./x"), Some("x".into()));
        assert_eq!(sanitize_filename("a/b"), Some("b".into()));
        // Trailing ".." pops the last segment away entirely.
        assert_eq!(sanitize_filename("a/.."), None);
        // Empty / dot / slash / whitespace-only are rejected.
        assert_eq!(sanitize_filename(""), None);
        assert_eq!(sanitize_filename("."), None);
        assert_eq!(sanitize_filename(".."), None);
        assert_eq!(sanitize_filename("/"), None);
        assert_eq!(sanitize_filename("   "), None);
        assert_eq!(sanitize_filename("a/   "), None);
        // Backslash is an ordinary character on Linux (Go parity).
        assert_eq!(sanitize_filename("a\\b"), Some("a\\b".into()));
        // Whitespace-padded names are kept untrimmed (Go only checks TrimSpace).
        assert_eq!(sanitize_filename(" x "), Some(" x ".into()));
    }

    // Cases verified against Go: fmt.Sprintf("%q", name) (strconv.Quote).
    #[test]
    fn go_quote_cases() {
        assert_eq!(go_quote("hello.txt"), r#""hello.txt""#);
        assert_eq!(go_quote(r#"he"llo.txt"#), r#""he\"llo.txt""#);
        assert_eq!(go_quote(r"back\slash"), r#""back\\slash""#);
        assert_eq!(go_quote("tab\tname"), r#""tab\tname""#);
        assert_eq!(go_quote("nl\nname"), r#""nl\nname""#);
        assert_eq!(go_quote("bell\x07name"), r#""bell\aname""#);
        assert_eq!(go_quote("ctl\x01name"), r#""ctl\x01name""#);
        assert_eq!(go_quote("del\x7fname"), r#""del\x7fname""#);
        // Printable non-ASCII passes through literally (Go parity).
        assert_eq!(go_quote("żółć.txt"), "\"żółć.txt\"");
        assert_eq!(go_quote("emoji🎉.txt"), "\"emoji🎉.txt\"");
    }

    // Cases mirror Go's TestConfinedPath (api/filetransfer_test.go).
    #[test]
    fn confine_path_cases() {
        let base = FsPath::new("/srv/work");
        let ok = |rel: &str| confine_path(base, rel);
        assert_eq!(ok("file.txt"), Some(PathBuf::from("/srv/work/file.txt")));
        assert_eq!(
            ok("sub/dir/file.txt"),
            Some(PathBuf::from("/srv/work/sub/dir/file.txt"))
        );
        assert_eq!(ok("../escape"), None);
        assert_eq!(ok("../../etc/passwd"), None);
        // Absolute rel is joined under base, not an escape (Go filepath.Join).
        assert_eq!(
            ok("/etc/passwd"),
            Some(PathBuf::from("/srv/work/etc/passwd"))
        );
        assert_eq!(
            ok("sub/../file.txt"),
            Some(PathBuf::from("/srv/work/file.txt"))
        );
        assert_eq!(ok("sub/../../escape"), None);
        // "." resolves to base itself (allowed lexically; stat rejects dirs).
        assert_eq!(ok("."), Some(PathBuf::from("/srv/work")));
        // Popping past the filesystem root never panics and still confines.
        assert_eq!(ok("../../../../../../etc/passwd"), None);
    }
}
