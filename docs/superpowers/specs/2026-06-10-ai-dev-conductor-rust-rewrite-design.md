# AI Dev Conductor — Rust Rewrite Design

**Date:** 2026-06-10
**Status:** Approved
**Repo:** github.com/shafqat-a/terminal-hub (new `main`; previous Rust project archived on `legacy-terminal-hub`)
**Reference implementations:** ai-dev-conductor (Go, `main` @ 912e980 + `feat/file-transfer` @ 0970a69), warp-orion (Warp terminal fork, terminal edge-case reference), terminal-hub `legacy-terminal-hub` (reused `tmux-client` crate)

---

## 1. Context and Goal

ai-dev-conductor is a Go web-based terminal session manager (multi-session, WebSocket streaming, xterm.js UI). terminal-hub was a Rust attempt at the same space but has rendering bugs in its web console. This project recreates **the full ai-dev-conductor feature set in Rust** for reliability, on a clean orphan `main` branch in the terminal-hub repo.

The defining architectural fix: **tmux owns terminal state** ("tmux as the model"). On every viewer attach/reconnect the server repaints the exact current screen from tmux (`capture-pane -e` + cursor restore) instead of replaying raw byte history through xterm.js — eliminating the replay-rendering bug class. Live output streams as raw bytes to xterm.js, which handles emulation.

## 2. Scope

Feature parity with ai-dev-conductor `main` **plus** the `feat/file-transfer` branch. Sessions are tmux-backed (sessions survive server restarts).

### 2.1 HTTP/WS API surface (parity contract)

| Method | Route | Notes |
|---|---|---|
| GET | `/api/health` | health check |
| POST | `/api/login` | bcrypt password, session token (cookie + header), per-IP throttling → 429 + Retry-After |
| GET | `/terminal` | main UI (auth-gated) |
| GET | `/api/sessions` | list |
| POST | `/api/sessions` | create (tmux session) |
| PUT | `/api/sessions/{id}` | rename |
| DELETE | `/api/sessions/{id}` | delete (kill tmux session) |
| POST | `/api/sessions/{id}/exec` | programmatic command exec (API-key auth) |
| GET | `/api/sessions/{id}/history` | scrollback/history fetch (API-key auth) |
| POST | `/api/sessions/{id}/share` | mint read-only share link (TTL) |
| GET | `/api/sessions/{id}/shares` | list shares |
| DELETE | `/api/shares/{id}` | revoke share |
| GET | `/s/{token}` | public share viewer page |
| GET | `/ws/share/{token}` | read-only share WebSocket |
| POST | `/api/sessions/{id}/upload` | file upload into session cwd (max bytes cap) |
| GET | `/api/sessions/{id}/download` | file download from session cwd |
| GET | `/ws/{id}` | interactive session WebSocket |
| GET | `/static/*` | embedded assets |

Base-path mounting (`cfg.BasePath`) supported as in the file-transfer branch. WebSocket origin checking as in Go version.

### 2.2 Configuration (env vars — names unchanged)

`AI_CONDUCTOR_PASSWORD`, `AI_CONDUCTOR_ADDR`, `AI_CONDUCTOR_DATA_DIR`, `AI_CONDUCTOR_SHELL`, `AI_CONDUCTOR_PID_FILE`, `AI_CONDUCTOR_SESSION_TIMEOUT`, `AI_CONDUCTOR_LOGIN_MAX_ATTEMPTS`, `AI_CONDUCTOR_LOGIN_WINDOW`, `AI_CONDUCTOR_LOGIN_LOCKOUT`, `AI_CONDUCTOR_IDLE_TIMEOUT`, `AI_CONDUCTOR_MAX_SESSIONS`, plus file-transfer branch additions (`AI_CONDUCTOR_BASE_PATH`, `AI_CONDUCTOR_PUBLIC_URL`, `AI_CONDUCTOR_SHARE_TTL`, `AI_CONDUCTOR_MAX_UPLOAD_BYTES`). Defaults match the Go implementation.

### 2.3 Frontend

Port ai-dev-conductor's `web/` assets (xterm.js terminal, command palette, themes — Tokyo Night/Dracula/Solarized/Light, font size, activity dots, terminal-bell notifications, mobile on-screen keys, slide-in sidebar, image paste via Ctrl+V, auto-reconnect with exponential backoff, share viewer pages). Only the attach protocol changes: **one new server→client message type carrying the initial repaint frame** (capture-pane output + cursor position + active mode flags), after which raw bytes stream as today.

### 2.4 Non-goals

- WebAuthn/passkeys, multi-user ACLs, federation (terminal-hub features — out of scope).
- Server-side terminal emulation (`alacritty_terminal`) — rejected: tmux already is the model; stacking emulators increases bug surface.
- Replacing xterm.js with a custom renderer.

## 3. Architecture

Rust workspace; single deployable binary named `ai-dev-conductor` (drop-in for existing systemd unit / run.sh).

```
crates/
  tmux/    adapted from legacy terminal-hub tmux-client: control-mode
           connection (attach, send_command, %output event decoder) +
           capture-pane repaint + refresh-client resize
  core/    session manager: lifecycle, naming, idle reaping, max-session
           cap, exec, history, attach orchestration
  store/   rusqlite: session metadata, auth sessions, API keys, share
           tokens, upload limits
  server/  axum: REST + WebSocket handlers, auth middleware (password
           session tokens + API keys), login throttling, static assets
           embedded (rust-embed), base-path mounting
web/       ported conductor frontend (embedded at build)
```

- **Runtime:** tokio. **HTTP:** axum. **DB:** rusqlite (same single-file SQLite model as Go version).
- **tmux integration (Approach A — control mode):** one persistent control-mode connection to a dedicated tmux server socket; each conductor session = one tmux session. Live output = `%output` events demultiplexed to subscribed WebSockets. Input = `send-keys`/stdin write. Exec endpoint = `send-keys` + optional capture. History = tmux scrollback (`capture-pane -S`), not server memory.
- **Attach flow:** on WS connect → `capture-pane -e -q` (+ cursor pos via `display-message`, + mode flags) → send as repaint frame → subscribe to live `%output` stream. Reconnect is identical — always pixel-correct.
- **Resize policy:** latest-active-viewer wins, applied via `refresh-client -C WxH` (debounced client-side).
- **Restart survival:** tmux sessions live in the external tmux server; on conductor restart, sessions are re-adopted by listing tmux sessions and matching against store metadata.

## 4. Reliability requirements (warp-orion-derived edge-case contract)

From the study of warp-orion (`crates/warp_terminal`, `app/src/terminal/local_tty`). Each item below ships with a test.

**Relay layer must solve (tmux does not):**
1. **UTF-8 boundary safety** — never split a multibyte sequence across WebSocket text frames; buffer partial sequences across PTY/control-mode reads (Warp delegates to vte; our pump must carry remainder bytes). Binary frames for raw bytes are acceptable alternative.
2. **Bracketed paste passthrough** — client wraps paste in ESC[200~/201~ when mode active; server never strips/reorders control chars in paste payloads (incl. multi-line, tabs, ANSI bytes — conductor parity).
3. **Mode-flag tracking & replay** — track BRACKETED_PASTE, SGR_MOUSE (1006 + 1000/1002/1003/1005), APP_CURSOR, alt-screen (47/1049), focus reporting (1004), sync-output (2026); include active modes in the repaint frame so xterm.js state matches after reconnect.
4. **Resize storms** — debounce browser resize; serialize TIOCSWINSZ-equivalent (`refresh-client -C`) so tmux sees a consistent final size; no interleaving with output corruption.
5. **Backpressure** — bounded per-client output queue; slow WebSocket clients get coalesced/dropped-frame handling rather than unbounded memory growth (Warp: 256 KB read buffer, fair-yield loop).
6. **Grapheme/zero-width bombs** — cap pathological combining-char payloads relayed to the browser (Warp caps 256 bytes/cell per UAX #15 stream-safe format) to prevent xterm.js DOM explosion.
7. **Clipboard** — image paste delivered to server clipboard/file (conductor parity); OSC 52 passthrough.

**tmux already solves (verify, don't reimplement):** grid/scrollback state, wide-char cells, alt-screen buffer swap, soft-wrap tracking, scrollback limits (`history-limit`), clear-history semantics, mouse event forwarding.

## 5. Data model (rusqlite)

Tables mirroring the Go store: `sessions` (id, name, tmux_name, created_at, last_active), `auth_sessions` (token hash, expiry), `api_keys` (key hash, label, created_at), `shares` (id, session_id, token hash, expires_at, revoked). Migration on startup; single DB file under `AI_CONDUCTOR_DATA_DIR`.

## 6. Error handling

- All tmux command failures surface as typed errors (`thiserror`) → JSON error responses with appropriate HTTP status; never panic on tmux/IO errors.
- Control-mode connection supervisor: on tmux connection loss, exponential-backoff reconnect + session re-adoption; WS clients receive a status event.
- Graceful shutdown: drain WebSockets, leave tmux sessions running (that is the point), close DB.

## 7. Testing & CI

- **Unit tests** per crate (control-mode decoder golden tests, store, auth/throttling, UTF-8 pump property tests).
- **Edge-case suite** (Section 4): resize storms, split UTF-8 multibyte across reads, alt-screen enter/exit repaint, paste with control chars/multi-line, wide chars + emoji ZWJ at wrap point, mode replay after reconnect — run against a real tmux in CI.
- **E2E harness** in the spirit of conductor's `run-test.sh`: boot server, real WebSocket client, create/attach/exec/share/upload/download/kill.
- **CI:** GitHub Actions — fmt + clippy (deny warnings) + tests on Linux (primary target); release workflow + .deb packaging can be adapted from `legacy-terminal-hub` later.

## 8. Milestones

1. **M1 Skeleton:** workspace, config, axum server, health, login + throttling, static embed, ported login page.
2. **M2 tmux core:** tmux crate adaptation, session CRUD, interactive WS with repaint-on-attach, ported terminal UI.
3. **M3 Parity 1:** history, exec, API keys, idle reaping, max-session cap, restart re-adoption.
4. **M4 Parity 2:** shares (mint/list/revoke, viewer page, read-only WS), upload/download, base path.
5. **M5 Hardening:** full Section-4 edge-case suite, backpressure, image paste, CI green, clippy clean.
6. **M6 Deploy:** systemd unit, run.sh, deploy on Annihilator; optional .deb.

## 9. Deployment & development

Development happens on Annihilator (192.168.0.66, Linux, tmux present) in `~/git/terminal-hub`. Binary listens per `AI_CONDUCTOR_ADDR`; systemd service file equivalent to the Go one. orion's Go deployment stays untouched until the Rust version reaches M6.

## 10. Git surgery record (executed 2026-06-10)

- Old Rust terminal-hub `main` renamed → `legacy-terminal-hub`, pushed to origin.
- New orphan `main` created with no files; this spec is its first commit; force-pushed to origin (GitHub default branch remains `main`).
- Rollback: `git checkout legacy-terminal-hub` (full old tree, also on GitHub).
