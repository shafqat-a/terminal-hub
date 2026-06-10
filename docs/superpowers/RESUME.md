# RESUME — terminal-hub Rust rewrite (handoff state)

**Saved:** 2026-06-10 ~16:30 +06 · **Branch:** main · **M4 COMPLETE**
**Plans:** `docs/superpowers/plans/` (M1–M4 all ticked) · **Spec:** `docs/superpowers/specs/`

## Where things stand

Milestones M1 (skeleton), M2 (tmux core + terminal UI), M3 (API keys/exec/history/lifecycle/reaping/re-adoption), and M4 (shares, file transfer, base path) are COMPLETE, reviewed, smoke-tested. 156 tests (122 server + 26 store + 8 tmux), fmt/clippy clean.

M4 was finished with parallel worktree agents (U3 + U4 simultaneously), each independently reviewed post-merge — both SOUND. One plan error was found and fixed during integration: the M4 plan over-specified share mint `path` as base_path-prefixed; Go (api/shares.go:85) returns it UN-prefixed and app.js prepends window.BASE_PATH — fixed in c41dfac, documented in code comments.

## Next: M5 (hardening) — plan not yet written

Derive the M5 plan from spec §4 plus this deferred list (collected from M1–M4 reviews):

- SIGTERM graceful-shutdown handler (systemd needs it; required before M6 deploy)
- Reject `..` segments in assets static_file (debug builds serve from filesystem)
- Move `tower` to dev-dependencies; relocate `unix_now()` out of handlers.rs
- UTF-8 boundary buffering in the WS byte pump (lossy = Go parity, spec §4.1)
- API-key compare length-oracle note (subtle ct_eq short-circuit — hash both sides if it matters)
- TOCTOU comment in reap victim selection; sub-second idle_timeout guard
- warp-derived edge-case test suite (spec §4)
- **From M4 U3 review:** download streams whole file into memory (use streaming body; Go ServeFile streams + Range); Content-Disposition not %q-escaped (quote/control chars in filename → malformed header/500); upload buffers whole part in RAM (Go spills >32MiB to temp files); symlink-following inside cwd is lexical-confinement-only (matches Go, but canonicalize-then-confine is the hardening move)
- **From M4 U4 review:** test gaps — static assets under prefix, share viewer page + /ws/share under prefix, login-page substitution under prefix, unauth-API-401 under prefix (all manually verified OK); tighten root cookie test to `Path=/;`; NO CORS layer anywhere (Go applies corsMiddleware globally — pre-existing gap, decide in M5)

## M6 (deploy) reminders

systemd unit + run.sh + deploy on Annihilator; orion's Go production instance stays untouched until then. Go reference: ~/git/ai-dev-conductor (branch feat/file-transfer; main 912e980 had exec/history/API-key — both already mined; wire contracts are embedded in the M2–M4 plan files).

## Project conventions (established M1–M4, enforced by review)

TDD per unit; `cargo fmt --all` + `cargo clippy --workspace --all-targets -- -D warnings` clean at every commit; NO `#[allow]`; NO `unsafe` (one was removed for unsoundness — see 3f6068a); mutex poison recovery via `unwrap_or_else(|e| e.into_inner())`; Arc-clone fields into spawned tasks (never `&self`); real-tmux tests on tempdir-isolated sockets, sessions killed in-test; smoke tests must assert response BODIES and build the binary in the same shell session before starting it; kill test servers by exact PID (`pkill -f` matches your own ssh/bash command string and kills your shell).
