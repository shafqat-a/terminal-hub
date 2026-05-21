# terminal-hub

A Rust web server that hosts long-lived terminal sessions backed by tmux and exposes them through a browser.

## Status

M3 (single-user auth + TLS) complete. Self-signed TLS on first boot, SQLite
user store, CLI-driven SSH-key → passkey enrollment, cookie-gated sessions.
See `docs/superpowers/plans/` for milestones.

## Dev setup

Requires Rust ≥ 1.79, tmux ≥ 3.0, Node ≥ 20 (for e2e), an SSH ed25519 keypair.

One-time bootstrap of the primary user:

    TERMINAL_HUB_CONFIG_DIR=/tmp/th-dev cargo run -p terminal-hub-cli -- \
        bootstrap --email you@example.com --pubkey ~/.ssh/id_ed25519.pub

Start tmux + server:

    tmux -L terminal-hub new-session -d -s _boot
    TERMINAL_HUB_CONFIG_DIR=/tmp/th-dev \
    TERMINAL_HUB_PUBLIC_URL=https://localhost:5999/ \
    cargo run -p terminal-hub-server

Enroll a passkey from your laptop (writes a one-time URL to stdout):

    cargo run -p terminal-hub-cli -- enroll \
        --server https://localhost:5999 --email you@example.com --insecure

Open the printed URL, create the passkey, then sign in at <https://localhost:5999/login.html>.

Stop the tmux server: `tmux -L terminal-hub kill-server`.

## Tests

    cargo test --workspace

Integration tests start and stop their own ephemeral tmux servers; they require `tmux` on `PATH`.
