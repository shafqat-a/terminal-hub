# terminal-hub

A Rust web server that hosts long-lived terminal sessions backed by tmux and exposes them through a browser.

## Status

M2 (multi-session local) — sidebar with create/kill/switch, multi-tab mirroring, scrollback replay. No auth yet. See `docs/superpowers/plans/` for milestones.

## Dev setup

Requires Rust ≥ 1.79, tmux ≥ 3.0.

    tmux -L terminal-hub new-session -d -s _boot
    cargo run -p terminal-hub-server
    open http://127.0.0.1:5999/

Stop the tmux server: `tmux -L terminal-hub kill-server`.

## Tests

    cargo test --workspace

Integration tests start and stop their own ephemeral tmux servers; they require `tmux` on `PATH`.
