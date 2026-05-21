# terminal-hub — design spec

**Date:** 2026-05-21
**Status:** approved (brainstorming complete); pending implementation plan
**Supersedes:** the "Open decisions" section of `CLAUDE.md`

## 1. Summary

A Rust web server that hosts multiple long-lived terminal sessions backed by tmux and exposes them through a browser UI. A primary user (you) administers each instance; secondary users have per-session permissions granted by the primary. Multiple instances can be peered so the sidebar of any one instance shows the sessions running on all the others, with that instance acting as a proxy. Sessions survive browser disconnects, terminal-hub crashes, and tmux restarts (so long as the tmux server itself stays alive).

## 2. Goals

1. Browser-accessible terminal sessions that persist across disconnects.
2. Per-session ACLs for non-admin users.
3. Federation: one instance can aggregate and proxy sessions from other peered instances.
4. SSH-key bootstrap + WebAuthn passkey for authentication; no passwords.
5. Native Linux and macOS support; Windows via WSL2.
6. Clipboard paste that works correctly in the terminal pane.

## 3. Non-goals (explicit)

- Transitive federation. A only sees peers in A's own `authorized_peers`.
- Per-user identity flowing across instances. Federation auth is instance-level.
- Native Windows. Use WSL2.
- Mobile app or native desktop client. Browser only.
- Session recording/replay beyond tmux scrollback.
- Role hierarchy beyond `primary` / `secondary`.
- Audit log review UI in MVP (log is written, viewer comes later).
- Mitigation of "effective transitive trust" (see §13).

## 4. Platform targets

| Platform | Build | Notes |
|---|---|---|
| Linux x86_64 / aarch64 | static musl binary | primary target; tmux from distro |
| macOS arm64 / x86_64 | signed `.pkg` (eventually) | tmux from Homebrew |
| Windows | none — use WSL2 Linux build | documented in install guide |

Service install per platform:
- Linux: systemd user unit (`~/.config/systemd/user/terminal-hub.service`)
- macOS: launchd plist (`~/Library/LaunchAgents/dev.terminal-hub.plist`)
- Both must also keep the tmux server alive (separate unit / plist).

## 5. Architecture overview

Three processes per instance:

```
┌──────────────────────────────────────────────────────────┐
│  browser                                                 │
└────────────┬─────────────────────────────────────────────┘
             │  HTTPS / WSS  (passkey-authenticated cookie)
┌────────────▼─────────────────────────────────────────────┐
│  terminal-hub (axum web server)                          │
│   - auth (WebAuthn)                                      │
│   - permission enforcement                               │
│   - federation proxy                                     │
│   - tmux control-mode client (one per attached session)  │
└────┬────────────────────────────────┬────────────────────┘
     │ unix socket (tmux -CC)         │ HTTPS / WSS to peers
     │                                │ (peer-key authenticated)
┌────▼─────────────┐         ┌────────▼─────────────────────┐
│  tmux server     │         │  other terminal-hub instances│
│  (holds PTYs)    │         │  (B, C, ...)                 │
└──────────────────┘         └──────────────────────────────┘
```

- **terminal-hub** is the only thing the browser touches. It owns auth, permissions, the federation client, and the tmux client.
- **tmux server** owns the PTY master fds. If terminal-hub crashes, the PTYs stay alive; on restart, terminal-hub reconnects via `tmux list-sessions`.
- **Peer instances** are just other terminal-hub processes on other machines, talking the same HTTP+WSS protocol terminal-hub already speaks for browsers, but with peer-key auth instead of a passkey-derived cookie.

## 6. User & authentication model

### 6.1 Roles

- **Primary user** — exactly one per instance. Full access to every session reachable from this instance (local + federated). Can enroll secondaries, grant/revoke permissions, add/remove peers.
- **Secondary user** — zero default access. Sees only sessions the primary has explicitly granted; can spawn new sessions only on instances the primary has flagged with `peer_create_allowed`.

### 6.2 Enrollment flow (admin side)

Primary drops `{email, ssh_pubkey}` into the instance's user store (CLI or primary's web UI). No self-signup.

### 6.3 First-login flow (CLI helper, **not** in-browser)

We do **not** ask the user to upload an SSH private key into the browser. Instead:

1. Primary's bootstrap: `terminal-hub bootstrap --email you@example.com --pubkey ~/.ssh/id_ed25519.pub` (run on the server itself, sets up the primary's pubkey).
2. From the user's laptop: `terminal-hub enroll --server https://A.local:5999 --email alice@example.com`
   - The CLI talks to the local ssh-agent (fallback: prompts for key file path + passphrase).
   - Server returns a random challenge.
   - The CLI signs the challenge using the SSH key.
   - Server verifies signature against the stored pubkey and returns a single-use bootstrap token (short TTL, ~5 min).
   - CLI prints the token: `Open https://A.local:5999/enroll?t=<token> in your browser.`
3. User opens that URL in the browser. Server validates the token and runs the standard WebAuthn passkey registration ceremony. The passkey is bound to `alice@example.com`.
4. Future logins: passkey only.

Properties:
- Private key never enters a browser, never touches JavaScript memory.
- ssh-agent integration covers the common case (no passphrase prompts).
- SSH pubkey is **retained** as a recovery factor — re-running `terminal-hub enroll` issues a fresh bootstrap token so the user can register a new passkey if their device is lost.

### 6.4 Browser session

After passkey assertion, server issues an HTTP-only, Secure, SameSite=Lax cookie containing a signed session token. WebSocket upgrades reject unauthenticated requests. One cookie covers local and federated sessions; the browser never sees peer credentials.

## 7. Permission model

All permissions live on the primary's instance only. Secondaries have no concept of federated identity — to peer B, A is a single trusted client.

### 7.1 Schema (SQLite)

```sql
users(
  email TEXT PRIMARY KEY,
  pubkey BLOB NOT NULL,                    -- SSH pubkey, recovery factor
  passkey_creds BLOB,                      -- serialized webauthn credentials
  role TEXT CHECK(role IN ('primary','secondary')) NOT NULL,
  enrolled_at INTEGER NOT NULL
);

permissions(
  user_email TEXT NOT NULL REFERENCES users(email),
  peer_id TEXT NOT NULL,                   -- 'local' for this instance
  session_id TEXT NOT NULL,                -- terminal-hub UUIDv7
  capabilities INTEGER NOT NULL,           -- bitmask: 1=attach, 2=write, 4=manage
  granted_by TEXT NOT NULL REFERENCES users(email),
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (user_email, peer_id, session_id)
);

peer_create_allowed(
  user_email TEXT NOT NULL REFERENCES users(email),
  peer_id TEXT NOT NULL,
  granted_by TEXT NOT NULL REFERENCES users(email),
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (user_email, peer_id)
);

audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  user_email TEXT NOT NULL,
  action TEXT NOT NULL,                    -- 'login', 'attach', 'create', 'kill', 'grant', 'revoke', 'peer-add', ...
  peer_id TEXT,
  session_id TEXT,
  details TEXT                             -- JSON blob with action-specific context
);
```

### 7.2 Enforcement

Every API handler resolves the cookie → `user_email`. Then:

- If `users.role = 'primary'` → skip permission check. Primary sees and does everything.
- If `users.role = 'secondary'` → every list/attach/write/kill/rename request is filtered through `permissions`. Capabilities checked at the operation level.
- Sessions a secondary creates herself get an auto-inserted row with `capabilities = attach|write|manage` for that secondary plus a row for the primary.

### 7.3 Grant UI

Primary's sidebar shows a "Share" affordance on each session → modal with email checkboxes and capability toggles. Revoke is a checkbox flip. Grants for federated sessions are stored as `(user, peer_id, session_id, caps)` rows; enforcement still happens at A's proxy layer.

## 8. Session model

### 8.1 Backing store: tmux

Each terminal-hub session maps 1:1 to a tmux session.

- **Session ID** = UUIDv7 generated by terminal-hub at create time.
- **tmux session name** = `th-<uuid>` (the `th-` prefix lets us filter out non-terminal-hub tmux sessions if the user shares the tmux server).
- **Display name, owner, created_at** = stored in tmux user-options (`@display-name`, `@owner-email`, `@created-at`) via `tmux set-option`. These survive terminal-hub restarts because tmux persists them.

### 8.2 Lifecycle operations

| Operation | Implementation |
|---|---|
| Create | `tmux new-session -d -s th-<uuid> -F …`; set `@display-name`, `@owner-email`, `@created-at`; insert auto-grant rows |
| List | `tmux list-sessions -F '#{session_name}|#{@display-name}|#{@owner-email}|#{@created-at}'`, filter to `th-` prefix |
| Attach | open `tmux -CC attach-session -t th-<uuid>`; one control-mode pipe per attached terminal-hub session; fan output to WebSockets, serialize input |
| Rename (display) | `tmux set-option -t th-<uuid> @display-name "..."` (the underlying tmux session name stays `th-<uuid>` forever) |
| Kill | `tmux kill-session -t th-<uuid>`; cascade-delete permission rows |

### 8.3 Crash recovery

On boot, terminal-hub:
1. Connects to the configured tmux server socket (default: `/tmp/tmux-<uid>/terminal-hub`).
2. If the socket is absent, terminal-hub refuses to start and prints instructions for launching the tmux server under systemd-user / launchd. We intentionally do not have terminal-hub spawn tmux itself, because then the tmux server would inherit terminal-hub's lifecycle and the crash-recovery property is lost.
3. Lists sessions via `tmux -L terminal-hub list-sessions -F …`, rebuilds in-memory map from session names + user-options.
4. Resumes serving. Attached browsers reconnect via WebSocket; they replay scrollback from tmux's buffer (`capture-pane`).

If the tmux server itself dies, sessions are lost. The install guide tells the user to run tmux under systemd-user / launchd so the server respawns. Improving on this is out-of-scope for MVP.

### 8.4 Scrollback on reattach

On browser attach, terminal-hub asks tmux for the last N lines (`capture-pane -p -S -<N>`) and replays them over the WebSocket before live streaming begins. Default N = 5000 lines.

### 8.5 Clipboard / paste

xterm.js with **bracketed paste mode** explicitly enabled, plus the `customKeyEventHandler` hook so Cmd/Ctrl-V triggers `term.paste(text)` rather than going to the key handler. Right-click paste uses the browser's clipboard API (`navigator.clipboard.readText()`). Test plan: Playwright (or chrome-devtools MCP) end-to-end tests for multi-line paste, tab paste, ANSI-byte paste, and IME composition. Clipboard is a first-class acceptance criterion, not a polish item.

## 9. Federation

### 9.1 Trust model

Each instance has its own ed25519 peer keypair (`peer_id` / `peer_id.pub`) generated on first boot. Adding peer B to instance A:

1. On B (CLI or admin UI): `terminal-hub peer-info` prints B's pubkey + 12-char SHA-256 fingerprint, e.g. `peer-id: a3f9:c12e:7b04`. Also prints B's TLS cert fingerprint.
2. On A's "Add server" UI: enter `(url, friendly_name, expected peer fingerprint, expected TLS cert fingerprint)`.
3. A opens TLS to B. Both fingerprints must match what was entered; otherwise abort with a clear error.
4. A sends `POST /peer/auth { pubkey, signed_challenge }`. B verifies the pubkey is in `authorized_peers` and the signature is valid; returns a short-lived peer session token.
5. A persists B's pubkey + TLS cert fingerprint to `peers.toml`. A's pubkey must already be in B's `authorized_peers` (admin step done out-of-band on B).

Out-of-band fingerprint verification is mandatory — no TOFU.

### 9.2 Connection topology

- **Lazy on-demand.** A connects to peer B only when (a) the user clicks into B's group in the sidebar, or (b) the user attaches to a session on B.
- **Idle timeout.** Connection closes after 60s of no activity.
- **Status cache.** Last successful fetch's session list cached in memory with `last_fetched` timestamp; sidebar shows cached state when peer is unreachable, dimmed, with the timestamp.

### 9.3 Protocol

No new protocol. A is a client of B using the same HTTP+WSS API a browser uses, with peer-key auth instead of passkey. This means:

- Every operation a browser can perform, A can perform on the user's behalf.
- B does not know which secondary user on A is driving the request; B sees only "instance A, authenticated."
- Permission enforcement for secondaries happens at A's proxy layer (A filters B's responses, blocks operations the secondary lacks).

### 9.4 What A trusts B with

Full read/write/admin on B's sessions. If A is compromised, attacker has full control of every peered instance reachable from A. Documented as accepted risk (§13).

## 10. TLS

- Each instance generates a self-signed certificate on first boot (ed25519 or RSA-2048; `tls.crt` + `tls.key` in the config dir).
- Browser users hit a one-time cert-trust prompt; we ship a `terminal-hub install-cert` CLI helper that imports it into the OS trust store (per-platform).
- Peer-to-peer TLS uses **certificate fingerprint pinning** stored alongside the peer pubkey. A connects to B → checks the served cert's SHA-256 against the stored fingerprint → aborts on mismatch. No public CA needed; works on private networks without DNS.
- Cert rotation: re-run `terminal-hub peer-info` on B, paste the new fingerprint into A. Documented procedure, no automation in MVP.

## 11. Persistence layout

Resolved by `directories-next` per platform:

| Platform | Config dir |
|---|---|
| Linux | `$XDG_CONFIG_HOME/terminal-hub/` or `~/.config/terminal-hub/` |
| macOS | `~/Library/Application Support/terminal-hub/` |

Contents:

```
config.toml          # bind addr/port, primary email, tmux socket path
state.db             # SQLite: users, permissions, peer_create_allowed, audit_log
peer_id              # ed25519 private key, mode 0600
peer_id.pub          # ed25519 public key
tls.key              # mode 0600
tls.crt
authorized_peers     # peers we accept connections FROM
                     # format (one per line): <pubkey-b64> <friendly_name> <tls_cert_fp>
peers.toml           # peers we connect TO (url, friendly_name, peer_pubkey, tls_cert_fp)
```

User pubkeys (for recovery + initial enrollment) live in `state.db` `users.pubkey`, not on disk. Enrollment via the CLI (`terminal-hub bootstrap` / primary's "Add user" UI) writes directly to the DB.

Permissions and dir creation are enforced at startup; the server refuses to start with overly-permissive modes on `peer_id` or `tls.key`.

## 12. Sidebar UX

```
┌─ Sessions ─────────────────────┐
│ ▼ Local (3)                ●   │
│    ◦ build-shell               │
│    ◦ tail-logs                 │
│    ◦ scratch                   │
│ ▼ prod-box (2)             ●   │   ● = reachable
│    ◦ deploy                    │
│    ◦ db-console                │
│ ▶ homelab (4)              ○   │   ○ = unreachable, cached
│ + Add server                   │
└────────────────────────────────┘
```

- Collapsible group per peer.
- Status dot reflects last connection attempt.
- Expanding an offline peer triggers a reconnect; failure → toast `homelab unreachable — last seen 14:02`.
- For secondaries, the list shows only sessions the primary has granted.

## 13. Threat model summary

| Threat | Mitigation | Residual |
|---|---|---|
| Passive network eavesdropping | TLS everywhere | none in-scope |
| MitM on initial peer add | Out-of-band fingerprint verification for both peer pubkey and TLS cert | user must actually verify |
| Stolen passkey | Bound to a single browser/device; recovery via SSH-key re-enrollment | one device's worth of access |
| Stolen SSH private key | Attacker can re-enroll a passkey; primary can rotate the pubkey via CLI | requires reaching the server's enrollment endpoint |
| Compromised secondary's credentials | Limited to sessions explicitly granted to that secondary | scope of their grants |
| Compromised primary's credentials | Full instance control + full control of every peered instance reachable | accepted; "primary is root" |
| Compromised peer instance | Full access to local instance (because A trusts B as much as B trusts A) | accepted; small fleet, all trusted |
| XSS in web UI | CSP headers, no `innerHTML` from server data, escape in templates | reduce-not-eliminate |
| Web UI compromise → SSH key exfil | **Impossible** — SSH key never enters the browser | none |

### Documented but un-mitigated risks

- **Effective transitive trust.** A trusts B; Bob is admin on A; therefore Bob effectively controls B. If C is also peered with A, Bob effectively controls C. No mitigation in MVP — small-fleet homelab assumption.
- **tmux server compromise** — the tmux server is in the user's own UID; an attacker with that UID already owns the data. Not a separate threat.

## 14. Stack picks (closes CLAUDE.md "Open decisions")

| Concern | Pick | Why |
|---|---|---|
| Web framework | **axum** | First-class async, WebSocket support, tower ecosystem, the boring right choice |
| TLS | **rustls** | Pure Rust, no OpenSSL dep, axum integrates cleanly |
| PTY abstraction | **none needed for terminal-hub itself** | tmux owns PTYs; we just speak the control protocol over a Unix socket |
| tmux control-mode client | **handwritten** | The control-mode protocol is small; existing crates target the CLI surface, not `-CC` |
| WebAuthn | **webauthn-rs** | The canonical Rust crate; supports the registration ceremony we need |
| SSH key crypto | **ssh-key** (Rust crate) for parsing, **ed25519-dalek** for signing | Pure Rust |
| SSH-agent client | **ssh-agent-client-rs** or roll our own (small protocol) | TBD in implementation plan |
| Persistence | **rusqlite (bundled mode)** | Single file, no external service, ships in the binary |
| Config files | **toml + serde** | Hand-editable, gitops-friendly |
| Path resolution | **directories-next** | Cross-platform config dir resolution |
| Async runtime | **tokio** | axum requires it |
| Logging | **tracing + tracing-subscriber** | Standard |
| Frontend | **vanilla HTML + xterm.js + small TypeScript bundle** (esbuild) | No SPA framework; sidebar doesn't need one |
| E2E tests | **Playwright** (or chrome-devtools MCP) | For clipboard / paste verification |

## 15. Open questions for the implementation plan

1. **ssh-agent on macOS** uses a non-standard socket path resolution; verify `ssh-agent-client-rs` handles it or write a small shim.
2. **tmux version floor** — `-CC` control mode is stable since tmux 1.8 but some flags differ; pin a minimum (probably ≥ 3.0) and check at startup.
3. **WebAuthn relying-party ID** for federated instances — each instance is its own RP (different hostname); no shared identity. Document this.
4. **systemd / launchd unit templates** ship in `dist/`; not part of the binary.
5. **First-boot UX** — server starts with no users; primary bootstrap is a CLI command. The HTTP layer should refuse to serve until at least one primary exists.
6. **Migration from a future schema change** — `rusqlite` migrations via plain SQL files; pick a convention (e.g. `migrations/0001_initial.sql`).

## 16. References

- Project intent and constraints: `CLAUDE.md`
- This spec: `docs/superpowers/specs/2026-05-21-terminal-hub-design.md`
- Next step: implementation plan, to be written via the `superpowers:writing-plans` skill.
