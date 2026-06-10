# RESUME — terminal-hub Rust rewrite (handoff state)

**Saved:** 2026-06-10 ~19:00 +06 · **Branch:** main · **M5 COMPLETE**
**Plans:** `docs/superpowers/plans/` (M1–M5 all ticked) · **Spec:** `docs/superpowers/specs/`

## Where things stand

M1 (skeleton), M2 (tmux core + terminal UI), M3 (API keys/exec/history/lifecycle/reaping/re-adoption), M4 (shares, file transfer, base path), M5 (hardening: spec §4 pump suite, image paste, graceful shutdown, CORS, deferred fixes) are COMPLETE, reviewed, smoke-tested. 209 tests (175 server + 26 store + 8 tmux), fmt/clippy clean.

M5 was three parallel worktree agents (U1 pump / U2 paste / U3 HTTP-lifecycle) merged by the controller. Post-merge review found two must-fix bugs in U1, both fixed in 1cefad7: (1) mode re-assert must precede the snapshot (tmux always asserts ?1049h, so after-snapshot re-assert wiped the screen on reconnect — plan text amended); (2) lag-resync must `resubscribe()` the broadcast receiver or it replays the stale buffer over the fresh snapshot.

Smoke-verified: SIGTERM exit 0 + tmux survives + restart re-adopts; paste-image fallback (file bytes + typed path in pane, via raw-WS client); CORS preflight 204 with exact Go headers; UTF-8 emoji/CJK/ZWJ exec round-trip clean; 10 MB streamed download with Content-Length and matching sha256; share page + base-path instance regressions green.

## Next: M6 (deploy)

systemd unit + run.sh + deploy on Annihilator; optional .deb (adapt from legacy-terminal-hub). orion's Go production instance stays untouched until cutover. Pre-deploy notes:
- Graceful shutdown is in (required for systemd); 15s drain bound, exit 0 on both paths.
- **tmux server needs the xterm `Ms` terminal-override for OSC 52 clipboard forwarding** (U1 finding — without it tmux won't forward OSC 52 to clients; the test sets it explicitly).
- Go reference: ~/git/ai-dev-conductor (feat/file-transfer), wire contracts embedded in M2–M5 plan files.

## Backlog (deferred from M5 reviews — none blocking)

- Final activity flush on shutdown (Go CloseAll→flush parity; today up to one flush-interval of last_activity is lost on SIGTERM).
- Shutdown holds up to 15s with open WS connections (Go exits immediately; no active close frames sent) — document or actively close.
- Cross-chunk StreamSafe state (per-client persistent counter; current per-chunk reset is evadable across paced chunks — tmux's per-cell cap mitigates).
- Mode scanner edges: C0 controls inside CSI treated as malformed; DCS/OSC payloads scanned as Ground (only matters if tmux allow-passthrough is enabled); 8-bit C1 CSI unrecognized.
- pty.write is a blocking write under mutex on the async runtime (pre-existing M2); paste_image awaits inside the pump select loop (output pauses ≤5s worst case; lag-resync absorbs).
- /app/ws/share-under-prefix test; upload RAM spill-to-temp; symlink canonicalize (wontfix: lexical = Go parity); Range/conditional-GET (documented divergence in files.rs).

## Project conventions (established M1–M5, enforced by review)

TDD per unit; `cargo fmt --all` + `cargo clippy --workspace --all-targets -- -D warnings` clean at every commit; NO `#[allow]`; NO `unsafe`; mutex poison recovery via `unwrap_or_else(|e| e.into_inner())`; Arc-clone fields into spawned tasks (never `&self`); real-tmux tests on tempdir-isolated sockets, sessions killed in-test; smoke tests must assert response BODIES and build the binary in the same shell session before starting it; kill test servers by exact PID (`pkill -f` matches your own ssh/bash command string and kills your shell). Parallel worktree agents per unit with explicit file ownership; controller merges + post-merge parallel reviews; plan errors found by review get the plan text amended in the same commit as the fix.
