# terminal-hub

A Rust web server that hosts long-lived terminal sessions backed by tmux and exposes them through a browser. Multi-user, ACL-gated, passkey-protected, and federation-ready — every instance can aggregate sessions from configured peers in one sidebar.

[![Build status](https://github.com/shafqat-a/terminal-hub/actions/workflows/ci.yml/badge.svg)](https://github.com/shafqat-a/terminal-hub/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

---

## What you get

- **Browser terminals that survive disconnects.** PTYs live in tmux, not in the web server — refresh the page, close the laptop, come back tomorrow; your shell is still where you left it.
- **WebAuthn passkey login** bootstrapped by SSH key. The private key never enters the browser; a CLI signs the server's challenge from ssh-agent.
- **Multi-user with per-session ACLs.** Primary user manages everything; secondary users see only sessions explicitly granted to them, with `attach` / `write` / `manage` capabilities.
- **Federation.** Configure peers in `peers.toml`; the sidebar shows local sessions + each peer's sessions, grouped, with live status dots.
- **Audit log** of every meaningful action (login, attach, create, kill, rename, grant, revoke, peer-add, …).
- **xterm.js frontend** with proper clipboard / paste (bracketed paste mode, multi-line, tab paste, ANSI bytes all preserved).

## Status

M5 (federation) substantially complete; M6 (packaging) shipped. **50 commits, 86 tests passing, clippy clean.**

**Documented MVP follow-ups (deferred):**

- TLS cert pinning (peer-key handshake already provides cryptographic identity; transport currently uses `accept_invalid_certs` against self-signed peer certs).
- Federated `/ws/attach` proxy (peer sessions visible in the sidebar but read-only; attaching uses `ssh` for now).

## Install (Debian / Ubuntu)

```sh
sudo dpkg -i terminal-hub_<version>_amd64.deb
sudo apt-get install -f                              # pulls in tmux
terminal-hub-cli bootstrap --email you@example.com --pubkey ~/.ssh/id_ed25519.pub
systemctl --user enable --now tmux-server.service terminal-hub.service
sudo loginctl enable-linger $(whoami)                # keep running after logout
```

Open <https://localhost:5999/login.html>. From your laptop:

```sh
terminal-hub-cli enroll --server https://your-host:5999 --email you@example.com --insecure
```

Open the printed URL, create a passkey, sign in.

See [`docs/INSTALL.md`](docs/INSTALL.md) for full instructions, federation setup, and troubleshooting.

## Build from source

```sh
git clone https://github.com/shafqat-a/terminal-hub
cd terminal-hub
cargo build --workspace --release
# Or build a .deb:
cargo install cargo-deb && sh dist/build-deb.sh
```

Requires Rust 1.86+ and tmux 3.0+.

## Workspace layout

```
crates/
├── tmux-client/   # control-mode (`tmux -CC` / `-C`) protocol decoder + driver
├── auth-core/     # SSH-key challenge/sign/verify primitives (shared by server + CLI)
├── server/        # axum HTTP + WS, SQLite, WebAuthn, tmux client, federation
└── cli/           # terminal-hub-cli: bootstrap, enroll, add-user, peer-info, …
crates/server/static/    # vanilla HTML + xterm.js frontend (no SPA framework)
docs/
├── INSTALL.md     # operator install + federation setup
└── superpowers/
    ├── specs/     # design spec (2026-05-21-terminal-hub-design.md)
    └── plans/     # M1–M6 implementation plans
dist/
├── install.sh     # POSIX installer for tarball distribution
├── build-deb.sh   # helper to build a .deb locally
├── systemd/       # placeholder unit templates (tarball install)
├── deb/           # systemd units + maintainer scripts for the .deb
└── launchd/       # macOS LaunchAgents
.github/workflows/
├── ci.yml         # fmt + clippy + test on Ubuntu + macOS
└── release.yml    # tag-triggered .tar.gz + .deb release artifacts
```

## Architecture (one-paragraph)

Three layers. The **browser** runs xterm.js and talks to the server over an authenticated WebSocket. The **server** (Rust + axum) owns auth, ACL enforcement, federation proxying, and a tmux control-mode client; it never owns PTY file descriptors directly. The **tmux server** owns every PTY; if terminal-hub crashes and restarts, it reattaches via `tmux list-sessions` and resumes serving — sessions survive. Federation reuses the same HTTP+WS API: A acts as an authenticated client of B using an ed25519 peer-key handshake.

Full design: [`docs/superpowers/specs/2026-05-21-terminal-hub-design.md`](docs/superpowers/specs/2026-05-21-terminal-hub-design.md)

## Testing

```sh
cargo test --workspace        # 86 tests; requires tmux on PATH
cargo clippy --workspace --all-targets -- -D warnings
```

End-to-end clipboard / paste tests under `e2e/` (Playwright; install with `npm i && npx playwright install chromium`).

## Security model — short version

- **Three trust layers** with independent credentials: user↔instance (SSH-key + passkey), instance↔instance (ed25519 peer-key + TLS fingerprint pinning planned), browser↔instance (signed session cookie).
- **Primary user is effectively root** on the instance and on every peered instance. Spec §13 walks through the threat model and the explicitly-accepted "effective transitive trust" risk for small homelab fleets.
- The browser never sees a private SSH key — the CLI helper signs challenges via ssh-agent.
- Cert pinning + federated WS proxy are tracked as security follow-ups before any non-personal deployment.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
