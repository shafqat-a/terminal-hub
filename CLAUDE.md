# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

M3 (single-user auth + TLS) complete. Cargo workspace: `tmux-client`, `auth-core`,
`server`, `cli`. Self-signed TLS via `rcgen`. SQLite user store via `rusqlite`
(bundled). SSH-key challenge / WebAuthn passkey enrollment via the CLI. Cookie-gated
HTTP + WebSocket sessions. Exactly one primary user; multi-user permissions and
federation land in M4. See `docs/superpowers/specs/2026-05-21-terminal-hub-design.md`
for the full design and `docs/superpowers/plans/` for milestone plans.

Build: `cargo build --workspace`
Test: `cargo test --workspace` (tmux + ed25519 tests require `tmux` on PATH)
Run: see README "Dev setup" — needs bootstrap + tmux + env vars

## Product intent

A Rust-based web server that hosts multiple long-lived console (PTY) sessions and exposes them through a browser UI.

Hard requirements that constrain design choices:

1. **Multiple concurrent sessions.** The server owns N pseudo-terminal processes. Sessions outlive any single browser connection — a user can disconnect, refresh, or come back later and reattach to the same running shell with scrollback intact.
2. **Session sidebar.** The browser UI shows a left sidebar listing every running session; clicking one attaches the main pane to that session's I/O stream. Switching sessions must not kill or reset the underlying process.
3. **SSH-key bootstrap → passkey login.** First-time auth: user uploads an SSH public key (or proves possession of the private key) on the login screen, and the server registers a WebAuthn passkey bound to that identity. Subsequent logins use the passkey only; the SSH key is the enrollment factor, not the recurring credential.
4. **Clipboard must work.** Every input surface — the terminal pane especially — must accept native browser paste (Cmd/Ctrl+V, right-click paste, middle-click on Linux) without the terminal emulator swallowing or mangling the event. Multi-line paste, paste of tabs, and paste of ANSI/control bytes all need to survive intact. Treat this as a first-class acceptance criterion, not a polish item; xterm.js and similar libraries have known footguns here (bracketed paste, focus stealing, IME composition) that must be tested explicitly.

## Architecture sketch (not yet implemented)

The natural shape is three layers; the first implementer should confirm or revise before writing code.

- **PTY supervisor (Rust).** Owns a `HashMap<SessionId, PtySession>`. Each `PtySession` wraps a spawned process + its master PTY fd, plus a ring buffer of recent output for scrollback-on-reattach. Reads from the PTY fan out to any number of subscribed WebSocket clients; writes from any client are serialized into the PTY's stdin.
- **HTTP/WebSocket server (Rust).** Serves the static frontend, handles auth (SSH-key enrollment + WebAuthn assertion), and upgrades to WebSocket for the per-session I/O stream. Auth state lives in a server-side session cookie; the WebSocket handshake must reject unauthenticated upgrades.
- **Browser frontend.** Terminal emulator (almost certainly xterm.js) + a sidebar that lists sessions and a small control surface (new session, kill session, rename). Communicates with the server over one WebSocket per attached session, or one multiplexed WebSocket — decide based on how the sidebar's live status updates are delivered.

The "session survives disconnect" requirement is the load-bearing architectural constraint: the PTY must be owned by the supervisor, never by a WebSocket handler's task, or sessions will die when the browser closes.

## Open decisions (flag these to the user before picking)

- **Web framework:** `axum` (recommended default — tower ecosystem, first-class WebSocket, async-friendly) vs `actix-web` vs `warp`.
- **PTY crate:** `portable-pty` (cross-platform, used by wezterm) vs `nix`-direct `forkpty` (Unix-only, more control).
- **WebAuthn crate:** `webauthn-rs` is the obvious choice; confirm it supports the flow of "enroll passkey gated by SSH-key proof."
- **SSH-key proof-of-possession:** challenge/response signed with the private key vs. just trusting an uploaded public key on first contact (the latter is weaker and probably wrong). Decide before writing the login flow.
- **Frontend stack:** plain HTML + xterm.js + a small TS bundle is sufficient; avoid pulling in a SPA framework unless the sidebar grows real complexity.
- **Persistence:** does session metadata (names, ownership, last-seen) need to outlive a server restart? If yes, SQLite via `sqlx` or `rusqlite`. If no, in-memory only and document that restart wipes the session list.

## Working notes for future Claude

- When the user asks to "run it" or "see it work," there is nothing to run yet until the workspace is initialized. Don't pretend otherwise.
- Clipboard behavior cannot be verified by unit tests alone — it requires driving a real browser. Plan E2E coverage (Playwright or chrome-devtools MCP) for paste paths from day one, not as an afterthought.
- The SSH-key → passkey enrollment flow has real security implications; if asked to implement it, walk through the threat model with the user before writing code (what does "uploaded SSH key" prove? against what attacker?).
