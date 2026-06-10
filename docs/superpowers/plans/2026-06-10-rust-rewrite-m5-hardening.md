# Rust Rewrite M5 — Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox steps.

**Goal:** Spec §4 edge-case contract (UTF-8 boundaries, mode replay, backpressure, resize storms, grapheme bombs, paste passthrough), image paste (conductor parity), graceful shutdown, CORS, and the M1–M4 review-deferred fixes. CI green, clippy clean, no wire-behavior regressions.

**Execution environment:** Same as M1–M4 (Annihilator, ~/git/terminal-hub, branch main, TDD, fmt+clippy --all-targets -D warnings clean per commit, no #[allow], no unsafe, Arc-clone into spawned tasks, real tmux, kill test servers by exact PID).

**Parallelism:** U1, U2, U3 are designed for concurrent worktree agents. File ownership: U1 owns `ws.rs` pump internals + `session/pty.rs` + new `session/modes.rs`; U2 owns new `session/paste.rs` + the `paste-image` match arm in ws.rs; U3 owns `files.rs`, `assets.rs`, `main.rs`, `auth/`, CORS in `app.rs`. Known overlap: ws.rs (U1 heavy / U2 one arm), `session/mod.rs` (U1+U2 one-line mod decls), app.rs tests (U1+U3) — controller resolves at merge.

---

### Normative behaviors

**UTF-8 boundary safety (spec §4.1):** The pump must never emit a WS text frame that splits a multibyte sequence. PTY broadcast chunks can split sequences arbitrarily; carry incomplete trailing bytes (1–3) to the next chunk per client. Truly invalid bytes (not a prefix of a valid sequence) are replaced U+FFFD as today. Snapshot (capture-pane) output is complete — no carry needed there.

**Backpressure (spec §4.5):** broadcast channel stays bounded (1024). On `RecvError::Lagged`, the client's view is corrupt — instead of silently continuing, re-sync: run capture-pane and send a fresh snapshot output frame (with mode re-assert per below), then resume streaming. Never unbounded buffering.

**Mode tracking & replay (spec §4.3):** Track DEC private modes from the PTY output stream, per session (not per client): bracketed paste (2004), SGR mouse (1006) + mouse tracking (1000/1002/1003/1005), app cursor (DECCKM, CSI ? 1), alt screen (47, 1047, 1049), focus reporting (1004), sync output (2026). Scanner = small state machine over output bytes handling CSI sequences split across read chunks; lives in the PTY read loop (session-level), state in `Mutex<ModeState>`. On attach AND on lag-resync, BEFORE the snapshot frame, send one output frame containing re-assert sequences (`CSI ? Pm h` for each active mode). (AMENDED post-review: originally specified after-snapshot, but tmux asserts ?1049h at attach so the re-assert would switch to a cleared alt buffer and wipe the snapshot — clear-then-paint is the correct order.) Golden unit tests for the scanner (set/reset/split-across-chunks/interleaved); integration test: enable bracketed paste + alt screen in the pane, reconnect, assert re-assert sequences arrive.

**Grapheme bombs (spec §4.6):** Apply UAX #15 stream-safe transform (unicode-normalization crate, `StreamSafe`) to decoded output text before framing — caps pathological combining-mark runs (inserts CGJ after 30). Test: output with 1000 combining marks on one base char arrives transformed (contains CGJ, browser-safe); normal text byte-identical.

**Bracketed paste + OSC 52 passthrough (spec §4.2, §4.7):** Already structurally guaranteed (input written verbatim; output never filtered beyond stream-safe). Pin with tests: input frame containing ESC[200~ multi-line + tabs + ANSI ESC bytes reaches the pty verbatim (capture via `tmux send-keys`-free echo harness or pipe-pane); output containing OSC 52 reaches the WS client intact.

**Resize storms (spec §4.4):** Resize calls serialized per session (no interleaved TIOCSWINSZ/`refresh-client -C`); rapid sequence of N resizes ends with tmux at the final size, no error. Test: 20 rapid resize frames, assert final `display-message '#{pane_width}x#{pane_height}'` matches last frame.

**Image paste (Go parity — internal/session/paste.go, ws/handler.go):** `paste-image` frame: base64-decode `data` (bad b64 → log + continue, never disconnect). `Session::paste_image(data, mime, store_dir)`: empty data → error; mime "" → image/png. Primary: copy to system clipboard via wl-copy (WAYLAND_DISPLAY + binary) or xclip (DISPLAY + binary), 5s timeout, stdout/stderr null (clipboard tools fork daemons that hold pipes), then write 0x16 (Ctrl-V) to pty. Fallback (no display/tool/failure): save to `<store_dir>/<session_id>/pastes/paste-<unix_nanos><ext>` (mime→ext map: png/jpeg→jpg/gif/webp/bmp, default .png), write absolute path + trailing space to pty. Read-only connections already drop the frame. Integration test (real tmux, env without DISPLAY vars → fallback): send paste-image frame, poll for file under pastes/, assert pane contains the typed path. Unit tests: ext map, empty-data error, bad-b64 continues.

**Graceful shutdown (spec §6):** SIGTERM/SIGINT → stop accepting, drain WS connections (close frames), flush/close DB, leave tmux sessions RUNNING, exit 0. axum `with_graceful_shutdown` + tokio signal. Sessions must NOT be killed and must re-adopt on restart (M3 machinery). Smoke-verified (binary-level): start, create session, SIGTERM, exit 0, tmux session alive, restart re-adopts.

**CORS (Go parity — main.go corsMiddleware, applied globally):** If Origin header present: `Access-Control-Allow-Origin: <origin>` (reflect), `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, X-Session-Token`, `Access-Control-Max-Age: 3600`. OPTIONS → 204 no body (even without Origin). Applies to every route incl. public + base-path-nested. Tests: preflight 204 + headers; GET with Origin gets reflected header; no Origin → no CORS headers.

**Deferred-list fixes:**
- Download: stream the file (tokio_util ReaderStream body) instead of `fs::read`; Content-Disposition filename escaped like Go `%q` (backslash-escape `"` and `\`, control chars → keep Go behavior: %q uses \xNN — replicate or reject; READ Go output for a quote-bearing name and match).
- assets static_file: reject any path containing `..` segment → 404 (embedded assets can't traverse, but debug builds may serve from filesystem).
- API keys: hash both sides (sha256) before ct_eq compare — kills the length oracle.
- `tower` → dev-dependencies; move `unix_now()` out of handlers.rs into a util module; TOCTOU comment in reap victim selection; sub-second idle_timeout guard (timeout < 1s and > 0 must still reap correctly or be clamped — read the reaper, decide, test).
- U4 test gaps: static asset under prefix (200) + root (404); GET /app/s/<token> + /ws/share under prefix; login page substitution under prefix; unauth API under prefix → 401 JSON; tighten root cookie assertion to exact `Path=/;`.

**Explicitly deferred to M6+/wontfix (documented decisions):** upload RAM spill-to-temp-file (wire-identical; revisit if real uploads grow), symlink canonicalize-then-confine in download (lexical = exact Go parity; changing it would diverge), Range/conditional-GET on download (Go ServeFile has it; our contract said bytes+disposition — note divergence in code comment).

---

## Execution units

### U1 — WS pump data-path hardening + §4 edge-case suite
Utf8 carry (helper with property-style unit tests: all split points of multi-byte corpus reassemble losslessly), stream-safe transform, lag→resync, mode tracker (`session/modes.rs`) + replay-on-attach/resync, resize serialization, passthrough pin tests (bracketed paste, OSC 52), §4 integration suite against real tmux (split UTF-8, alt-screen repaint, mode replay after reconnect, resize storm, combining-mark bomb, wide char/emoji at wrap).
Commit: `feat(ws): spec §4 pump hardening — utf8 boundaries, mode replay, backpressure resync`

### U2 — Image paste (conductor parity)
`session/paste.rs` ported from Go paste.go (clipboard primary, file fallback, ext map); ws.rs paste-image arm: b64 decode + paste_image call (log-and-continue on errors); integration + unit tests per contract above.
Commit: `feat(ws): image paste to clipboard with file-path fallback`

### U3 — HTTP/lifecycle hardening
Graceful shutdown; CORS layer (global, incl. nested); streaming download + Content-Disposition escaping; static_file `..` rejection; API-key double-hash compare; tower→dev-deps; unix_now relocation; TOCTOU comment; idle_timeout sub-second guard; U4 test-gap suite + cookie assertion tighten.
Commit: `feat(server): graceful shutdown, CORS, streaming download, auth/asset hardening`

### U4 — Gate + smoke + push (controller)
1. Merge U1→U2→U3, resolve overlaps, full gate (fmt/clippy/tests), paste summaries.
2. Parallel post-merge reviews (one per unit) — fix must-fix findings.
3. Content-verified smoke (fresh build, exact-PID kills): SIGTERM lifecycle (session survives + re-adopts); paste-image fallback file + typed path; CORS preflight 204; emoji/UTF-8 WS round-trip; large-file download round-trip sha256; share + base-path regression spot-checks (M4 smoke subset).
4. Tick checkboxes; update RESUME.md (M5 done, M6 next); commit `docs: M5 complete — checkboxes`; push; poll CI green.

## Exit criteria
~175+ tests green, clippy/fmt clean, CI green, smoke proves shutdown/re-adopt + paste fallback + CORS + UTF-8 integrity, all §4 items have at least one test, deferred-list items either fixed or documented as explicit decisions.
