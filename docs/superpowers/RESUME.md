# RESUME — terminal-hub Rust rewrite (handoff state)

**Saved:** 2026-06-10 ~13:30 +06 · **Branch:** main · **Last commit:** 0a32c6b · **CI:** green
**Read this first, then the M4 plan:** `docs/superpowers/plans/2026-06-10-rust-rewrite-m4-parity2.md`

## Where things stand

Milestones M1 (skeleton), M2 (tmux core + terminal UI), M3 (API keys/exec/history/lifecycle/reaping/re-adoption) are COMPLETE, reviewed, smoke-tested, CI-green. Plans for each live in `docs/superpowers/plans/` with all checkboxes ticked; the design spec (with the M2 PTY-attach amendment) is in `docs/superpowers/specs/`.

M4 (shares, file transfer, base path) is IN PROGRESS:
- **U1 DONE + reviewed** (commits 940bd40, 0a32c6b): share mint/list/revoke endpoints, store v3 share_links, Go-matched behaviors documented in crates/server/src/shares.rs.
- **U2 ~90% DONE BUT UNCOMMITTED AND UNREVIEWED** — the working tree is intentionally dirty with it:
  - untracked: `web/templates/share.html`, `web/templates/share_invalid.html`, `web/static/js/share.js` (ported from Go with `__BASE_PATH__` placeholders)
  - modified: `assets.rs` (serve_substituted), `ws.rs` (pump gained `read_only: bool` + share WS handler + ~5 new tests), `shares.rs` (+27 lines), `app.rs` (routes), `Cargo.toml`/`Cargo.lock`
  - `cargo test --workspace` passes WITH this WIP: 138 (105 server + 26 store + 7 tmux); fmt/clippy state unverified
- **U3 (upload/download), U4 (base path), U5 (smoke+push): NOT STARTED** — full specs in the M4 plan.

## Next concrete step

1. Review the dirty-tree U2 work against the M4 plan's U2 section (esp.: read-only enforcement drops input/resize/paste/binary; share viewers fire viewer_attached/detached; 404 text bodies match Go's http.Error text/plain; `__BASE_PATH__` placeholders intact, zero `{{`). Run fmt + clippy --all-targets -D warnings.
2. If sound: commit as `feat(shares): public share viewer page and read-only share WebSocket`, then proceed U3 → U4 → U5 per the plan.

## Project conventions (established M1–M4, enforced by review)

TDD per unit; `cargo fmt --all` + `cargo clippy --workspace --all-targets -- -D warnings` clean at every commit; NO `#[allow]`; NO `unsafe` (one was removed for unsoundness — see 3f6068a); mutex poison recovery via `unwrap_or_else(|e| e.into_inner())`; Arc-clone fields into spawned tasks (never `&self`); real-tmux tests on tempdir-isolated sockets, sessions killed in-test; smoke tests must assert response BODIES and build the binary in the same shell session before starting it; kill test servers by exact PID (`pkill -f` matches your own ssh/bash command string and kills your shell).

## Deferred to M5 (hardening) — collected from reviews

SIGTERM graceful-shutdown handler (systemd needs it; required before M6 deploy); reject `..` segments in assets static_file (debug builds serve from filesystem); move `tower` to dev-dependencies; relocate `unix_now()` out of handlers.rs; UTF-8 boundary buffering in the WS byte pump (lossy = Go parity, spec §4.1); API-key compare length-oracle note (subtle ct_eq short-circuit — hash both sides if it matters); TOCTOU comment in reap victim selection; sub-second idle_timeout guard; warp-derived edge-case test suite (spec §4); plus the M5 plan itself (not yet written — derive from spec §4 + this list).

## M6 (deploy) reminders

systemd unit + run.sh + deploy on Annihilator; orion's Go production instance stays untouched until then. Go reference: ~/git/ai-dev-conductor (branch feat/file-transfer; main 912e980 had exec/history/API-key — both already mined; wire contracts are embedded in the M2–M4 plan files).
