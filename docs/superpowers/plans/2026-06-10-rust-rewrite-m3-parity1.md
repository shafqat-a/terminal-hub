# Rust Rewrite M3 — Parity 1 (API keys, exec, history, lifecycle, reaping, re-adoption) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox steps.

**Goal:** API-key auth, programmatic exec + history endpoints, session status lifecycle (running/detached/dead), restart re-adoption from tmux, idle reaping, max-session cap, and periodic activity persistence — wire-compatible with Go (main 912e980 for exec/history/API-key; feat/file-transfer for lifecycle).

**Adaptation note:** Go main's exec/history poll a raw-PTY history file. Our sessions are tmux-backed with no `.log` file; exec and history therefore source from `tmux capture-pane` instead. Wire shapes stay identical.

**Execution environment:** Same as M1/M2 (Annihilator, ~/git/terminal-hub, branch main, ssh -p 22, python3 heredocs, fmt+clippy -D warnings clean every commit, no #[allow], poison-recovery locks, real-tmux TDD).

---

### Wire contract (normative)

**API key:** env `AI_CONDUCTOR_API_KEY`; if unset → auto-generate 32 random bytes hex at startup and `tracing::info!("API key: {key}")`. Header `X-API-Key: <key>`, constant-time compare (`subtle` crate ConstantTimeEq). Middleware order: API key first; on mismatch fall through to session-token lookup. Valid API key grants access to ALL protected routes incl. /ws.

**POST /api/sessions/{id}/exec** body `{"command":"ls -la","timeout":30}`:
- command required non-empty else 400 `{"error":"invalid request"}`; timeout optional default 30 clamp [1,120] seconds.
- Behavior (tmux adaptation): marker = `__HERMES_DONE_<16 hex chars>__` (8 random bytes). Write `\n` to PTY, then `<command>; echo <marker>\n`. Poll `tmux capture-pane -e -p -S -5000` every 50ms until output contains the marker on a line NOT containing `echo ` (skip the echoed command line), or timeout. Extract output: lines after the echoed command line, up to (excluding) the marker line. Cap 500_000 bytes → set `truncated_bytes` to the overflow count.
- 200 `{"output":"...","timeout":false,"truncated_bytes":0}` (timeout=true if deadline hit; output = whatever was captured). 404 `{"error":"session not running"}` if session not live. 500 on tmux/PTY failure.

**GET /api/sessions/{id}/history?tail=N**: N bytes, default 5000, clamp max 500_000. Source: `capture-pane -e -p -S -10000`, LF→CRLF, take LAST N bytes (round the slice start forward to a UTF-8 char boundary). 200 `{"session_id":"<id>","output":"..."}`. 404 `{"error":"session not found"}` if unknown id (live OR detached-with-tmux counts as known; detached-without-tmux → capture fails → 404 same body).

**Status lifecycle:** store status ∈ running|detached|dead. Startup: `UPDATE sessions SET status='detached' WHERE status='running'` → re-adopt every tmux session named `aidc_*` (PtyHandle spawn `-A` attaches to existing; store row exists → status running + restore name/created_at; no row → upsert new with id from the name suffix). Store rows with no tmux session stay detached and appear in GET /api/sessions (merged list: live map sessions as running + store-only rows with persisted cols/rows/activity and stored status). PTY child exit while server runs → status dead, removed from live map (store row kept, marked dead), WS viewers closed. delete endpoint works on detached/dead rows too (kill tmux if present; remove row; 404 only if neither exists).

**Idle reaping:** env `AI_CONDUCTOR_IDLE_TIMEOUT` — 0/unset = disabled. Idle basis: only when viewers == 0; idle duration = now − (last_client_disconnect if > 0 else created_at) — so never-attached sessions become reapable after the timeout too. Reap loop interval = idle_timeout/2 clamped [1s, 60s]; victims → Manager::delete + `tracing::info!("session {id}: reaped (idle > {timeout:?})")`. Sessions with viewers attached are never reaped.

**Max sessions:** env `AI_CONDUCTOR_MAX_SESSIONS` — 0 = unlimited; checked in Manager::create against LIVE map size → create endpoint 429 `{"error":"session limit reached"}`.

**Flush loop:** every 15s persist `last_activity_at` (from pty.last_activity) and cols/rows for each live session. Interval injectable for tests.

**Store schema v2** (versioned migrations via `PRAGMA user_version`): sessions table gains `last_activity_at INTEGER NOT NULL DEFAULT 0`, `last_client_disconnect_at INTEGER NOT NULL DEFAULT 0`, `cols INTEGER NOT NULL DEFAULT 0`, `rows INTEGER NOT NULL DEFAULT 0`. Migration runner: v0→v1 = existing CREATE statements; v1→v2 = four ALTER TABLE ADD COLUMN. Fresh DBs run both. Store methods: `mark_all_detached()`, `set_status(id, status)`, `set_activity(id, unix)`, `set_size(id, cols, rows)`, `get_session(id) -> Option<SessionRow>`; `list_sessions` refactored to return `Vec<SessionRow>` (struct, not tuple — update existing callers/tests).

---

## Execution units (each: implement → spec review → quality review)

### - [x] U1 — Config + API-key auth
- Config: `api_key: Option<String>` (lookup AI_CONDUCTOR_API_KEY; from_lookup stays pure — generation happens in build_state: None → 32 rand bytes hex + `tracing::info!("API key: {key}")`). Add `idle_timeout: Duration` (AI_CONDUCTOR_IDLE_TIMEOUT, default 0 = disabled) and `max_sessions: u32` (AI_CONDUCTOR_MAX_SESSIONS, default 0) — these were NOT in the M1 config; add with tests (defaults + overrides).
- AppState gains resolved `api_key: String`. require_auth: if `X-API-Key` header present and non-empty → subtle ConstantTimeEq vs state.api_key → match = authorized; else fall through to existing token path. Dep: subtle = "2".
- Tests: valid key grants /api/sessions AND /terminal; wrong key + no token → 401 JSON on /api, 303 on /terminal; absent header + valid cookie still works; key comparison not length-leaky (just assert wrong-length key rejected).
- Commit: `feat(auth): X-API-Key authentication with constant-time comparison`

### - [x] U2 — Store v2 + status lifecycle + re-adoption
- Versioned migrations (user_version); v2 columns; `SessionRow` struct; new methods incl. mark_all_detached/set_status/set_activity/set_size/get_session; list_sessions → rows. TDD incl. v1→v2 upgrade test (create DB with v1 code path [simulate: execute v1 DDL manually + set user_version=1], reopen via Store::open, columns exist, data preserved).
- Manager re-adoption: build_state/Manager gains async `init()` (await in main + tests): mark_all_detached → tmux::list_sessions filter `aidc_` → for each: PtyHandle::spawn (-A attach) + store row lookup (restore name/created_at; missing → upsert) → live map + set_status running.
- Dead detection: PtyHandle gains `exited: tokio::sync::watch::Sender<bool>` signalled by the reader thread on EOF; Manager spawns per-session monitor: on exited → if still in map (not mid-delete) → set_status dead, remove from map, fire session.closed (WS viewers drop).
- delete works for live AND store-only rows (kill tmux if has_session; remove row; 404 only if neither).
- Manager::list merges live + store-only rows (stored status/cols/rows/activity).
- Tests (real tmux): re-adoption across manager instances on same data_dir (create via A; drop A without killing tmux; init B → listed running, name/created_at preserved, write works); store-only detached row listed with status detached; dead detection (external `tmux kill-session` → within ~3s status dead + WS closed — reuse delete_disconnects_viewer harness pattern); delete of detached row 200; delete of unknown 404.
- Commits: `feat(store): versioned migrations + session lifecycle columns` → `feat(session): status lifecycle, restart re-adoption, dead detection`

### - [x] U3 — Idle reaping + max sessions + flush loop
- Reap loop spawned in init when idle_timeout > 0 (interval = timeout/2 clamp [1s,60s]); victims per contract; loops stop when Manager dropped (abort JoinHandles in Drop).
- create: ErrSessionLimit when live count >= max_sessions (>0) → handler 429 `{"error":"session limit reached"}`.
- Flush loop every flush_interval (default 15s; injectable via #[cfg(test)] setter or ctor param) → set_activity + set_size.
- Tests: cap wire-exact 429; reap with idle_timeout=2s (never-attached session disappears ≤6s, tmux killed); attached session NOT reaped (viewer_attached held past timeout); flush with 200ms interval persists activity/size (assert store row updates).
- Commit: `feat(session): idle reaping, max-session cap, activity flush loop`

### - [x] U4 — exec + history endpoints
- `extract_exec_output(captured: &str, command: &str, marker: &str) -> (String, bool)` pure fn, unit-tested on fixtures: echoed-command line skipped, marker line excluded, ANSI preserved, marker absent → (tail, timed_out=true) semantics handled by caller.
- exec handler per contract (rand marker, `\n` then command+echo marker via pty.write, 50ms capture-pane poll loop, 500KB cap with truncated_bytes, default 30 clamp [1,120]); 404 "session not running" for non-live (incl. detached); 400 empty/missing command.
- history handler per contract (tail param, UTF-8-boundary-safe tail slice — unit test multibyte boundary; LF→CRLF same as WS snapshot).
- Routes in protected router. Integration tests (real tmux): exec echo round-trip with $((2+3)) arithmetic, exec timeout=1 on `sleep 5` → 200 timeout=true, unknown id 404 wire-exact, empty command 400, history contains prior echo, tail clamps, unknown id 404 "session not found".
- Commit: `feat(api): exec and history endpoints (tmux-sourced, Go wire shapes)`

### - [x] U5 — Milestone gate + smoke + push
1. Full gate (test/clippy/fmt) — paste summaries.
2. Real-binary smoke, CONTENT-verified (M2 lesson: assert bodies, and `cargo build` immediately before starting the server in the SAME ssh session): grep auto-generated API key from server log; exec via X-API-Key returns real command output; history returns bytes containing a known echo; MAX_SESSIONS=1 → second create 429 body-exact; RESTART smoke: create session → exec `echo RESTART_PROOF` → SIGINT server → restart same data_dir → GET /api/sessions shows session status running with original name → history contains RESTART_PROOF.
3. Tick M3 plan checkboxes; commit `docs: M3 checkboxes`; push; poll GitHub Actions API until the HEAD run concludes success.

## Exit criteria
Tests green (expect ~95+), clippy/fmt clean, CI green, restart smoke proves sessions + content survive a server restart, exec/history wire-exact via API key.
