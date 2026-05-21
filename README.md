# terminal-hub

A Rust web server that hosts long-lived terminal sessions backed by tmux and exposes them through a browser.

## Status

M4 (multi-user + per-session ACLs) complete. Multi-user instance with a
primary user and any number of secondaries; per-session capabilities
(`attach` / `write` / `manage`); CLI and admin panel for user management;
sidebar share modal for granting per-session access; best-effort audit log
covering login, attach, create, kill, rename, grant, revoke, add-user,
remove-user, and peer-create-toggle. Federation (cross-peer sessions)
remains M5. See `docs/superpowers/plans/` for milestones.

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

## Multi-user (M4)

Add a secondary user from the server host:

    cargo run -p terminal-hub-cli -- add-user \
        --email alice@example.com --pubkey ~alice/.ssh/id_ed25519.pub

Then have alice enroll a passkey from her laptop using the M3 flow:

    cargo run -p terminal-hub-cli -- enroll \
        --server https://your-host:5999 --email alice@example.com

The primary user grants per-session access via the `↪` button on each
session in the sidebar (opens a modal with attach/write/manage checkboxes
per user) or via `POST /api/permissions/session/:session_id`. Capabilities
are a bitmask: `1 = attach` (read-only), `2 = write`, `4 = manage` (rename
+ kill). Saving an all-unchecked row revokes the grant.

By default secondaries cannot create sessions. Toggle this per user with
the peer-create allowlist (also exposed at the API level):

    curl -X POST -H "Content-Type: application/json" --cookie 'th_session=...' \
        -d '{"user_email":"alice@example.com","peer_id":"local","allow":true}' \
        https://your-host:5999/api/permissions/peer-create

The primary's admin panel for adding and removing users lives at
`/admin/users.html`.

## Tests

    cargo test --workspace

Integration tests start and stop their own ephemeral tmux servers; they require `tmux` on `PATH`.
