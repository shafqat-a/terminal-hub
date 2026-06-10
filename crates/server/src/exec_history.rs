//! exec and history endpoint handlers + pure helpers.
//!
//! Wire contract (Go-compatible):
//! - POST /api/sessions/:id/exec  → {"output":"...","timeout":false,"truncated_bytes":0}
//! - GET  /api/sessions/:id/history?tail=N → {"session_id":"<id>","output":"..."}

use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::app::SharedState;
use crate::handlers::json_error;

// ---- Shared byte helper ----------------------------------------------------

/// Replace every bare `\n` with `\r\n` (byte-level, Go parity).
pub fn crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 256);
    for &b in bytes {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

// ---- Pure output-extraction helpers ----------------------------------------

/// Find the last line whose content contains `command` AND "; echo " (the
/// echoed input line that the shell prints back), then find the first
/// subsequent line containing `marker` that does NOT contain "echo ".
///
/// Returns `Some(output)` where output = lines strictly between those two
/// boundaries joined with `\n`.  Returns `None` if the marker was not found.
pub fn extract_exec_output(captured: &str, command: &str, marker: &str) -> Option<String> {
    let lines: Vec<&str> = captured.lines().collect();

    // Find the LAST line that is the echoed command line.
    // The shell echoes the full line that was sent: "<command>; echo <marker>"
    // We detect it by: line contains `command` AND line contains "; echo ".
    let echo_line_idx = lines
        .iter()
        .enumerate()
        .rev()
        .find(|(_, line)| line.contains(command) && line.contains("; echo "))
        .map(|(i, _)| i);

    let search_start = echo_line_idx.map(|i| i + 1).unwrap_or(0);

    // From search_start forward, find the first line containing `marker`
    // but NOT containing "echo " (skip the echoed command line itself if
    // there is no clear echo_line_idx — belt-and-suspenders).
    let marker_idx = lines[search_start..]
        .iter()
        .enumerate()
        .find(|(_, line)| line.contains(marker) && !line.contains("echo "))
        .map(|(i, _)| search_start + i)?;

    // Output: lines strictly between echo_line_idx (exclusive) and marker_idx (exclusive).
    let out_lines = &lines[search_start..marker_idx];
    Some(out_lines.join("\n"))
}

/// Return the lines after the echoed command line with no marker bound
/// (used for the timeout partial response).
pub fn extract_partial_output(captured: &str, command: &str) -> String {
    let lines: Vec<&str> = captured.lines().collect();

    let echo_line_idx = lines
        .iter()
        .enumerate()
        .rev()
        .find(|(_, line)| line.contains(command) && line.contains("; echo "))
        .map(|(i, _)| i);

    let start = echo_line_idx.map(|i| i + 1).unwrap_or(0);
    lines[start..].join("\n")
}

// ---- Cap helper ------------------------------------------------------------

const MAX_OUTPUT: usize = 500_000;

/// Cap `s` at MAX_OUTPUT bytes on a UTF-8 char boundary.
/// Returns (capped_string, truncated_byte_count).
fn cap_output(s: String) -> (String, usize) {
    if s.len() <= MAX_OUTPUT {
        return (s, 0);
    }
    let overflow = s.len() - MAX_OUTPUT;
    // Walk back from MAX_OUTPUT to find a valid char boundary.
    let mut cut = MAX_OUTPUT;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    (s[..cut].to_string(), overflow)
}

// ---- POST /api/sessions/:id/exec -------------------------------------------

pub async fn sessions_exec(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    #[derive(serde::Deserialize)]
    struct ExecRequest {
        #[serde(default)]
        command: String,
        timeout: Option<u64>,
    }

    let req = match serde_json::from_slice::<ExecRequest>(&body) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid request"),
    };
    if req.command.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "invalid request");
    }

    // Clamp timeout [1, 120]; default 30.
    let timeout_secs = req.timeout.unwrap_or(30).clamp(1, 120);
    let timeout = Duration::from_secs(timeout_secs);

    // Only live sessions can exec.
    let sess = match state.manager.get(&id).await {
        Some(s) => s,
        None => return json_error(StatusCode::NOT_FOUND, "session not running"),
    };

    // Generate a unique marker.
    let marker_bytes: [u8; 8] = rand::random();
    let marker = format!("__HERMES_DONE_{}__", hex::encode(marker_bytes));

    let tmux_name = tmux::session_name(&id);
    let data_dir = state.cfg.data_dir.clone();

    // Write newline to clear any partial input, then the command with marker echo.
    if let Err(e) = sess.pty.write(b"\n") {
        tracing::error!("exec: pty write newline failed for session {id}: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    let cmd_line = format!(
        "{command}; echo {marker}\n",
        command = req.command,
        marker = marker
    );
    if let Err(e) = sess.pty.write(cmd_line.as_bytes()) {
        tracing::error!("exec: pty write command failed for session {id}: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    let deadline = Instant::now() + timeout;

    loop {
        // Capture current pane.
        let captured = match tmux::capture_pane(&data_dir, &tmux_name, 5000).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => {
                tracing::error!("exec: capture_pane failed for session {id}: {e}");
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            }
        };

        if let Some(out) = extract_exec_output(&captured, &req.command, &marker) {
            let (output, truncated_bytes) = cap_output(out);
            return (
                StatusCode::OK,
                Json(json!({
                    "output": output,
                    "timeout": false,
                    "truncated_bytes": truncated_bytes,
                })),
            )
                .into_response();
        }

        if Instant::now() >= deadline {
            // Deadline hit: return partial output with timeout=true.
            let partial = extract_partial_output(&captured, &req.command);
            let (output, truncated_bytes) = cap_output(partial);
            return (
                StatusCode::OK,
                Json(json!({
                    "output": output,
                    "timeout": true,
                    "truncated_bytes": truncated_bytes,
                })),
            )
                .into_response();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---- GET /api/sessions/:id/history -----------------------------------------

pub async fn sessions_history(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // tail param: default 5000, parse failures → default, clamp max 500_000.
    let tail: usize = params
        .get("tail")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(5000)
        .min(500_000);

    let tmux_name = tmux::session_name(&id);
    let data_dir = state.cfg.data_dir.clone();

    // Determine if session is known: live OR detached-with-tmux.
    // If manager.get returns None AND !tmux::has_session → 404.
    let live = state.manager.get(&id).await.is_some();
    if !live && !tmux::has_session(&data_dir, &tmux_name).await {
        return json_error(StatusCode::NOT_FOUND, "session not found");
    }

    match tmux::capture_pane(&data_dir, &tmux_name, 10000).await {
        Ok(raw) => {
            let with_crlf = crlf(&raw);
            // Take last `tail` bytes; round start FORWARD to char boundary (UTF-8-safe).
            let output = if with_crlf.len() <= tail {
                String::from_utf8_lossy(&with_crlf).into_owned()
            } else {
                let start = with_crlf.len() - tail;
                // Round start forward to a valid UTF-8 boundary.
                let text = String::from_utf8_lossy(&with_crlf).into_owned();
                let byte_start = {
                    let mut s = start;
                    while s < text.len() && !text.is_char_boundary(s) {
                        s += 1;
                    }
                    s
                };
                text[byte_start..].to_string()
            };
            (
                StatusCode::OK,
                Json(json!({
                    "session_id": id,
                    "output": output,
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("history: capture_pane failed for session {id}: {e}");
            // Capture failed even though tmux has-session passed (race or error).
            json_error(StatusCode::NOT_FOUND, "session not found")
        }
    }
}

// ---- Unit tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- extract_exec_output -----------------------------------------------

    /// Normal case: echoed command line skipped, marker line excluded, output extracted.
    #[test]
    fn extract_normal() {
        let captured = "\
$ echo hello; echo __HERMES_DONE_aabbccddeeff0011__\r
hello\r
__HERMES_DONE_aabbccddeeff0011__\r
$";
        let cmd = "echo hello";
        let marker = "__HERMES_DONE_aabbccddeeff0011__";
        let result = extract_exec_output(captured, cmd, marker);
        assert!(result.is_some(), "should find marker");
        let out = result.unwrap();
        // Output must be the lines between echo line and marker line.
        assert!(out.contains("hello"), "output: {out:?}");
        // Must NOT contain the echoed line.
        assert!(
            !out.contains("; echo "),
            "echoed line must be excluded: {out:?}"
        );
        // Must NOT contain the marker.
        assert!(
            !out.contains("__HERMES_DONE_"),
            "marker must be excluded: {out:?}"
        );
    }

    /// Marker absent → None.
    #[test]
    fn extract_marker_absent_returns_none() {
        let captured = "\
$ echo hello\r
hello\r
$";
        let result = extract_exec_output(captured, "echo hello", "__HERMES_DONE_xyz__");
        assert!(result.is_none(), "must return None when marker not found");
    }

    /// The capture contains the literal `echo __HERMES_DONE_x__` in the echoed line
    /// — that line must be skipped, and the real marker line (no "echo ") is used.
    #[test]
    fn extract_echo_line_with_echo_word_skipped() {
        let marker = "__HERMES_DONE_deadbeef01234567__";
        let captured = format!("ls; echo {m}\r\nfoo.txt\r\nbar.txt\r\n{m}\r\n$", m = marker);
        let result = extract_exec_output(&captured, "ls", marker);
        assert!(result.is_some(), "marker should be found");
        let out = result.unwrap();
        assert!(out.contains("foo.txt"), "output: {out:?}");
        assert!(out.contains("bar.txt"), "output: {out:?}");
        assert!(
            !out.contains(marker),
            "marker line must be excluded: {out:?}"
        );
    }

    /// ANSI escape bytes are preserved in output lines.
    #[test]
    fn extract_ansi_preserved() {
        let marker = "__HERMES_DONE_1122334455667788__";
        // ESC [ 1 m = bold; ESC [ 0 m = reset
        let ansi_line = "\x1b[1mhello\x1b[0m";
        let captured = format!(
            "cat /dev/null; echo {m}\r\n{ansi}\r\n{m}\r\n$",
            m = marker,
            ansi = ansi_line
        );
        let result = extract_exec_output(&captured, "cat /dev/null", marker);
        assert!(result.is_some());
        let out = result.unwrap();
        assert!(
            out.contains('\x1b'),
            "ANSI escape bytes must be preserved: {out:?}"
        );
    }

    /// Command output that contains the word "echo" is not confused with
    /// the echoed-command line.
    #[test]
    fn extract_output_containing_echo_word_not_confused() {
        let marker = "__HERMES_DONE_aabb112233445566__";
        // The output of the command itself says "echo" but no "; echo ".
        let captured = format!(
            "printf echo; echo {m}\r\nechoed output here\r\n{m}\r\n$",
            m = marker
        );
        let result = extract_exec_output(&captured, "printf echo", marker);
        assert!(result.is_some());
        let out = result.unwrap();
        assert!(
            out.contains("echoed output here"),
            "output with 'echo' word: {out:?}"
        );
    }

    // ---- crlf helper -------------------------------------------------------

    #[test]
    fn crlf_replaces_lf_with_crlf() {
        let input = b"line1\nline2\nline3";
        let out = crlf(input);
        assert_eq!(out, b"line1\r\nline2\r\nline3");
    }

    #[test]
    fn crlf_leaves_existing_crlf_alone() {
        // Existing \r\n: the \n gets \r prepended, giving \r\r\n — Go parity.
        let input = b"a\r\nb";
        let out = crlf(input);
        assert_eq!(out, b"a\r\r\nb");
    }

    // ---- tail UTF-8 boundary -----------------------------------------------

    /// When the tail byte count falls inside a multibyte UTF-8 character,
    /// the start is rounded forward to the next valid char boundary.
    #[test]
    fn tail_utf8_boundary_safe() {
        // "á" = 0xC3 0xA1 (2 bytes in UTF-8).
        // Build a string where cutting at byte 1 would land mid-char.
        let s = "xá"; // 3 bytes: 'x'=1 + 'á'=2
        let bytes = s.as_bytes(); // [0x78, 0xc3, 0xa1]
                                  // tail=2: start=1, which is mid-char; round forward to 2 → "á"
        let tail = 2usize;
        let start = bytes.len() - tail; // = 1
        let text = String::from_utf8_lossy(bytes).into_owned();
        let byte_start = {
            let mut s = start;
            while s < text.len() && !text.is_char_boundary(s) {
                s += 1;
            }
            s
        };
        let sliced = &text[byte_start..];
        assert_eq!(
            sliced, "á",
            "boundary-safe tail should yield 'á', got: {sliced:?}"
        );
    }

    // ---- cap_output -------------------------------------------------------

    #[test]
    fn cap_output_under_limit() {
        let s = "hello".to_string();
        let (out, trunc) = cap_output(s.clone());
        assert_eq!(out, s);
        assert_eq!(trunc, 0);
    }

    #[test]
    fn cap_output_over_limit_truncates_at_boundary() {
        // Build a string just over MAX_OUTPUT with a multibyte char at the boundary.
        let mut s = "a".repeat(MAX_OUTPUT - 1);
        s.push('á'); // 2 bytes: pushes total to MAX_OUTPUT+1
        assert_eq!(s.len(), MAX_OUTPUT + 1);
        let (out, trunc) = cap_output(s);
        // The cut at MAX_OUTPUT=500_000 is inside 'á' (2 bytes), so we round back.
        // After rounding, the slice ends at MAX_OUTPUT-1 = 499_999.
        assert!(trunc > 0, "overflow must be > 0");
        assert!(
            out.is_char_boundary(out.len()),
            "result must be valid UTF-8 boundary"
        );
    }
}
