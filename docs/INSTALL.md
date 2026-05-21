# Installing terminal-hub

## Prerequisites

- **tmux ≥ 3.0** on PATH. terminal-hub spawns and attaches via tmux's control-mode protocol; without it the server refuses to start.
- **An ed25519 SSH keypair** on every machine you intend to log in from (passkey enrollment is gated by SSH-key proof-of-possession).
- For native builds from source: **Rust ≥ 1.86** (toolchain pinned in `rust-toolchain.toml`).

## Linux / macOS (native install)

1. Download the latest release tarball matching your OS/arch from GitHub Releases (`terminal-hub-<version>-<target>.tar.gz`).
2. Unpack and run the installer:
   ```sh
   tar xzf terminal-hub-*.tar.gz
   cd terminal-hub-*
   sh dist/install.sh
   ```
3. Bootstrap your primary user (only once):
   ```sh
   terminal-hub-cli bootstrap --email you@example.com --pubkey ~/.ssh/id_ed25519.pub
   ```
4. Enable the service:
   - **Linux:** `systemctl --user enable --now tmux-server.service terminal-hub.service`
   - **macOS:** `launchctl load ~/Library/LaunchAgents/dev.terminal-hub.tmux.plist ~/Library/LaunchAgents/dev.terminal-hub.plist`
5. Browse to https://localhost:5999/login.html. (One-time self-signed cert warning — click through.)
6. From your laptop, enroll a passkey:
   ```sh
   terminal-hub-cli enroll --server https://localhost:5999 --email you@example.com --insecure
   ```
   Open the printed bootstrap URL in your browser. Click "Create passkey."
7. Sign in at https://localhost:5999/login.html with your new passkey.

## Windows (via WSL2)

Native Windows is not supported — terminal-hub depends on tmux which has no maintained native Windows port. Run inside WSL2:

1. Install WSL2 + Ubuntu (`wsl --install`).
2. Inside WSL2, follow the Linux install steps above.
3. Browse to the URL from Windows host or another machine; the server binds inside WSL.

## Federation (multi-instance)

Once two instances are installed and each has its own primary user:

1. On instance A, get its peer info:
   ```sh
   terminal-hub-cli peer-info --friendly-name a-box --url https://a.local:5999/
   ```
   This prints A's pubkey, peer fingerprint, TLS cert fingerprint, and a ready-to-paste `[[peer]]` block.
2. On instance B's `authorized_peers` file (in B's config dir), add a line:
   ```
   <A_PUBKEY_B64> a-box <A_TLS_CERT_FP>
   ```
3. Add the `[[peer]]` block A printed into B's `peers.toml`.
4. Repeat 1–3 in the other direction (so both A and B trust each other).
5. Sign in to either instance; the sidebar will show local sessions plus the other instance's sessions, grouped by `friendly_name`.

**MVP security caveats:**

- TLS cert pinning is not enforced yet (the client accepts any self-signed cert). Peer identity is still cryptographically established via the ed25519 handshake, so an attacker cannot impersonate a peer — but a network MitM can observe / modify the bytes.
- Attaching to a remote peer's session via the web UI is read-only in MVP (sidebar shows them but the WS proxy is a documented follow-up). Use `ssh peer && terminal-hub-cli ...` for active control until that ships.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Server fails to start: "tmux server socket missing" | Run `tmux -L terminal-hub new-session -d -s _boot` first, or enable the bundled `tmux-server.service` unit. |
| Browser shows "untrusted cert" | Self-signed cert in MVP. Click through, or trust `~/.config/terminal-hub/tls.crt` in the OS trust store. |
| `enroll` says "ssh-agent has no identities" | Run `ssh-add ~/.ssh/id_ed25519` first. |
| `enroll` returns 401 every key | The email is not enrolled on the server; run `terminal-hub-cli bootstrap` (primary) or `add-user` (secondary). |
| Sidebar peer group says "unreachable" | Network failure, wrong URL, wrong peer pubkey, OR A's pubkey isn't in B's `authorized_peers`. Check B's logs. |

## Building from source

```sh
git clone <repo>
cd terminal-hub
cargo build --workspace --release
# Binaries at target/release/terminal-hub and target/release/terminal-hub-cli
```
