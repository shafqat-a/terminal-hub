# M3 — Auth & Single-User Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Important:** Refresh this plan after M2 ships. Concrete struct field names, route shapes, and the `AppState` layout may need to adjust to what M2 ended up with. In particular: M2 introduces `AppState`, the `Hub`, and the `/api/sessions` routes — every route added in M3 attaches to that same state, and every existing route except `/healthz` should gain the auth middleware in Task 7.

**Goal:** Make terminal-hub safe to expose on the network. By the end of M3 the server boots over self-signed TLS, has a SQLite-backed user store, and accepts only authenticated browser sessions whose passkeys were registered through a CLI-driven SSH-key challenge flow. No multi-user / permission work — there is exactly one primary user, and unauthenticated requests to any protected route return 401 or redirect to `/login.html`.

**Architecture:** Add a `db` module to the server crate that owns the rusqlite connection pool and runs migrations on startup. Add an `auth` module split into three submodules: `challenge` (in-memory 5-min TTL store for SSH challenges), `bootstrap` (argon2-hashed one-time tokens in SQLite), and `passkey` (webauthn-rs ceremonies). Add a `tls` module that generates a self-signed cert via `rcgen` on first boot and serves with `axum-server` + `rustls`. The CLI crate grows two real subcommands (`bootstrap`, `enroll`) plus a small `ssh-agent` client wrapper. Frontend gains two new static pages — `login.html` and `enroll.html` — each backed by a vanilla JS module that drives `navigator.credentials.create`/`.get`.

**Tech Stack:** M2 stack + `rusqlite` 0.31 (bundled), `rcgen` 0.13, `axum-server` 0.6 (rustls), `rustls` 0.23, `webauthn-rs` 0.5, `ssh-key` 0.6, `ed25519-dalek` 2, `ssh-agent-client-rs` 0.9, `clap` 4 (derive), `argon2` 0.5, `base64` 0.22 (URL-safe-no-pad), `sha2` 0.10, `directories-next` 2, `url` 2, `tempfile` 3 (dev), `cookie` 0.18, `tower-cookies` 0.10.

**Spec reference:** `docs/superpowers/specs/2026-05-21-terminal-hub-design.md` §6 (user & auth model), §10 (TLS), §11 (persistence layout), §14 (stack picks).

---

## Task 1: Config dir + persistence scaffolding (directories-next)

**Files:**
- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/paths.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Add deps**

Add to `crates/server/Cargo.toml` `[dependencies]`:

```toml
directories-next = "2"
```

Add to `[dev-dependencies]`:

```toml
tempfile = "3"
```

- [ ] **Step 2: Implement path resolver**

Create `crates/server/src/paths.rs`:

```rust
//! Resolves the per-platform config directory and the files inside it.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    /// Use `TERMINAL_HUB_CONFIG_DIR` if set (tests, dev). Otherwise resolve via
    /// `directories-next` to the platform's config dir.
    pub fn resolve() -> anyhow::Result<Self> {
        if let Ok(p) = std::env::var("TERMINAL_HUB_CONFIG_DIR") {
            return Ok(Self::at(PathBuf::from(p)));
        }
        let pd = directories_next::ProjectDirs::from("dev", "terminal-hub", "terminal-hub")
            .ok_or_else(|| anyhow::anyhow!("no platform config dir available"))?;
        Ok(Self::at(pd.config_dir().to_path_buf()))
    }

    pub fn at(root: PathBuf) -> Self { Self { root } }

    pub fn ensure(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        Ok(())
    }

    pub fn db(&self) -> PathBuf { self.root.join("state.db") }
    pub fn tls_crt(&self) -> PathBuf { self.root.join("tls.crt") }
    pub fn tls_key(&self) -> PathBuf { self.root.join("tls.key") }
    pub fn config_toml(&self) -> PathBuf { self.root.join("config.toml") }

    pub fn root(&self) -> &Path { &self.root }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_overrides_platform_default() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("TERMINAL_HUB_CONFIG_DIR", tmp.path());
        let p = Paths::resolve().unwrap();
        assert_eq!(p.root(), tmp.path());
        assert_eq!(p.db().file_name().unwrap(), "state.db");
        std::env::remove_var("TERMINAL_HUB_CONFIG_DIR");
    }

    #[test]
    fn ensure_creates_missing_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b/c");
        let p = Paths::at(nested.clone());
        p.ensure().unwrap();
        assert!(nested.exists());
    }
}
```

Add `pub mod paths;` to `crates/server/src/lib.rs`.

- [ ] **Step 3: Run + commit**

Run: `cargo test -p terminal-hub-server paths`
Expected: 2 pass.

```bash
git add crates/server/Cargo.toml crates/server/src/paths.rs crates/server/src/lib.rs
git commit -m "feat(server): cross-platform Paths resolver with TERMINAL_HUB_CONFIG_DIR override"
```

---

## Task 2: SQLite store + initial migration

**Files:**
- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/db/mod.rs`
- Create: `crates/server/src/db/migrations/0001_initial.sql`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Add rusqlite + serde_json + chrono shim**

Add to `crates/server/Cargo.toml` `[dependencies]`:

```toml
rusqlite = { version = "0.31", features = ["bundled"] }
```

- [ ] **Step 2: Write migration SQL**

Create `crates/server/src/db/migrations/0001_initial.sql`:

```sql
-- Single-user M3 schema. Multi-user permissions/peers come in M4.

CREATE TABLE IF NOT EXISTS users (
  email          TEXT PRIMARY KEY,
  pubkey_openssh TEXT NOT NULL,                            -- raw ssh-ed25519 / ssh-rsa pubkey line
  passkey_creds  BLOB,                                     -- JSON-serialized Vec<Passkey>, null until first passkey registered
  role           TEXT NOT NULL CHECK(role IN ('primary','secondary')),
  enrolled_at    INTEGER NOT NULL                          -- unix seconds
);

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
  token_hash   BLOB PRIMARY KEY,                           -- argon2 hash of the raw token (string)
  user_email   TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  issued_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  consumed_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_user ON bootstrap_tokens(user_email);
CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_exp  ON bootstrap_tokens(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  cookie_hash  BLOB PRIMARY KEY,                           -- sha-256 of the cookie value
  user_email   TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  issued_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_email);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  user_email  TEXT,
  action      TEXT NOT NULL,
  details     TEXT                                         -- JSON blob
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
```

- [ ] **Step 3: Implement the Store**

Create `crates/server/src/db/mod.rs`:

```rust
//! SQLite-backed persistence. Single connection guarded by a Mutex — M3 traffic
//! is small enough that a pool isn't worth the dependency.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_initial", include_str!("migrations/0001_initial.sql")),
];

#[derive(Debug, Clone)]
pub struct UserRow {
    pub email: String,
    pub pubkey_openssh: String,
    pub passkey_creds: Option<Vec<u8>>,
    pub role: String,
    pub enrolled_at: i64,
}

#[derive(Debug, Clone)]
pub struct BootstrapTokenRow {
    pub token_hash: Vec<u8>,
    pub user_email: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub cookie_hash: Vec<u8>,
    pub user_email: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Connection>>,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let store = Self { inner: Arc::new(Mutex::new(conn)) };
        store.run_migrations_blocking()?;
        Ok(store)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { inner: Arc::new(Mutex::new(conn)) };
        store.run_migrations_blocking()?;
        Ok(store)
    }

    fn run_migrations_blocking(&self) -> anyhow::Result<()> {
        let g = self.inner.try_lock().expect("fresh store, no contention");
        g.execute(
            "CREATE TABLE IF NOT EXISTS _migrations (
                 name TEXT PRIMARY KEY,
                 applied_at INTEGER NOT NULL
             )",
            [],
        )?;
        for (name, sql) in MIGRATIONS {
            let applied: Option<i64> = g.query_row(
                "SELECT applied_at FROM _migrations WHERE name = ?1",
                params![name],
                |r| r.get(0),
            ).optional()?;
            if applied.is_none() {
                g.execute_batch(sql)?;
                g.execute(
                    "INSERT INTO _migrations(name, applied_at) VALUES (?1, ?2)",
                    params![name, now_secs()],
                )?;
            }
        }
        Ok(())
    }

    // ---------- users ----------

    pub async fn upsert_user(&self, email: &str, pubkey_openssh: &str, role: &str) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "INSERT INTO users(email, pubkey_openssh, role, enrolled_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(email) DO UPDATE SET pubkey_openssh = excluded.pubkey_openssh",
            params![email, pubkey_openssh, role, now_secs()],
        )?;
        Ok(())
    }

    pub async fn get_user(&self, email: &str) -> anyhow::Result<Option<UserRow>> {
        let g = self.inner.lock().await;
        let row = g.query_row(
            "SELECT email, pubkey_openssh, passkey_creds, role, enrolled_at
             FROM users WHERE email = ?1",
            params![email],
            |r| Ok(UserRow {
                email: r.get(0)?,
                pubkey_openssh: r.get(1)?,
                passkey_creds: r.get(2)?,
                role: r.get(3)?,
                enrolled_at: r.get(4)?,
            }),
        ).optional()?;
        Ok(row)
    }

    pub async fn set_passkey_creds(&self, email: &str, blob: &[u8]) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        let n = g.execute(
            "UPDATE users SET passkey_creds = ?1 WHERE email = ?2",
            params![blob, email],
        )?;
        anyhow::ensure!(n == 1, "no user {email}");
        Ok(())
    }

    // ---------- bootstrap tokens ----------

    pub async fn insert_bootstrap_token(&self, hash: &[u8], email: &str, ttl_secs: i64) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        let now = now_secs();
        g.execute(
            "INSERT INTO bootstrap_tokens(token_hash, user_email, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![hash, email, now, now + ttl_secs],
        )?;
        Ok(())
    }

    pub async fn list_bootstrap_tokens_for(&self, email: &str) -> anyhow::Result<Vec<BootstrapTokenRow>> {
        let g = self.inner.lock().await;
        let mut stmt = g.prepare(
            "SELECT token_hash, user_email, issued_at, expires_at, consumed_at
             FROM bootstrap_tokens WHERE user_email = ?1 AND consumed_at IS NULL
             AND expires_at > ?2",
        )?;
        let rows = stmt.query_map(params![email, now_secs()], |r| Ok(BootstrapTokenRow {
            token_hash: r.get(0)?,
            user_email: r.get(1)?,
            issued_at: r.get(2)?,
            expires_at: r.get(3)?,
            consumed_at: r.get(4)?,
        }))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn consume_bootstrap_token(&self, hash: &[u8]) -> anyhow::Result<bool> {
        let g = self.inner.lock().await;
        let n = g.execute(
            "UPDATE bootstrap_tokens SET consumed_at = ?1
             WHERE token_hash = ?2 AND consumed_at IS NULL AND expires_at > ?1",
            params![now_secs(), hash],
        )?;
        Ok(n == 1)
    }

    // ---------- cookie sessions ----------

    pub async fn insert_session(&self, hash: &[u8], email: &str, ttl_secs: i64) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        let now = now_secs();
        g.execute(
            "INSERT INTO sessions(cookie_hash, user_email, issued_at, expires_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?3)",
            params![hash, email, now, now + ttl_secs],
        )?;
        Ok(())
    }

    pub async fn lookup_session(&self, hash: &[u8]) -> anyhow::Result<Option<SessionRow>> {
        let g = self.inner.lock().await;
        let row = g.query_row(
            "SELECT cookie_hash, user_email, issued_at, expires_at FROM sessions
             WHERE cookie_hash = ?1 AND expires_at > ?2",
            params![hash, now_secs()],
            |r| Ok(SessionRow {
                cookie_hash: r.get(0)?,
                user_email: r.get(1)?,
                issued_at: r.get(2)?,
                expires_at: r.get(3)?,
            }),
        ).optional()?;
        if row.is_some() {
            let _ = g.execute(
                "UPDATE sessions SET last_seen_at = ?1 WHERE cookie_hash = ?2",
                params![now_secs(), hash],
            );
        }
        Ok(row)
    }

    pub async fn delete_session(&self, hash: &[u8]) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute("DELETE FROM sessions WHERE cookie_hash = ?1", params![hash])?;
        Ok(())
    }

    // ---------- audit ----------

    pub async fn audit(&self, user_email: Option<&str>, action: &str, details_json: Option<&str>) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "INSERT INTO audit_log(ts, user_email, action, details) VALUES (?1, ?2, ?3, ?4)",
            params![now_secs(), user_email, action, details_json],
        )?;
        Ok(())
    }
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrations_apply_idempotently() {
        let s = Store::in_memory().unwrap();
        // Second open on the same file would re-run; in-memory we just confirm a re-run is fine.
        s.run_migrations_blocking().unwrap();
        assert!(s.get_user("nobody@example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn user_round_trip() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("you@example.com", "ssh-ed25519 AAAA…", "primary").await.unwrap();
        let u = s.get_user("you@example.com").await.unwrap().unwrap();
        assert_eq!(u.role, "primary");
        assert!(u.passkey_creds.is_none());
        s.set_passkey_creds("you@example.com", b"{}").await.unwrap();
        assert_eq!(s.get_user("you@example.com").await.unwrap().unwrap().passkey_creds.unwrap(), b"{}");
    }

    #[tokio::test]
    async fn bootstrap_token_consume_once() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary").await.unwrap();
        s.insert_bootstrap_token(b"hash1", "a@b", 300).await.unwrap();
        assert!(s.consume_bootstrap_token(b"hash1").await.unwrap());
        assert!(!s.consume_bootstrap_token(b"hash1").await.unwrap(), "second consume must fail");
    }

    #[tokio::test]
    async fn expired_session_not_found() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary").await.unwrap();
        s.insert_session(b"cookieX", "a@b", -1).await.unwrap();
        assert!(s.lookup_session(b"cookieX").await.unwrap().is_none());
    }
}
```

Add `pub mod db;` to `crates/server/src/lib.rs`.

- [ ] **Step 4: Run + commit**

Run: `cargo test -p terminal-hub-server db`
Expected: 4 pass.

```bash
git add crates/server/Cargo.toml crates/server/src/db/ crates/server/src/lib.rs
git commit -m "feat(server): SQLite store with initial migration for users/tokens/sessions/audit"
```

---

## Task 3: Self-signed TLS cert generation (rcgen)

**Files:**
- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/tls.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Add deps**

Add to `crates/server/Cargo.toml` `[dependencies]`:

```toml
rcgen = "0.13"
rustls = { version = "0.23", default-features = false, features = ["ring"] }
axum-server = { version = "0.6", features = ["tls-rustls"] }
```

- [ ] **Step 2: Implement cert ensure-on-boot**

Create `crates/server/src/tls.rs`:

```rust
//! Generates a self-signed TLS cert on first boot and writes it to the config dir.
//!
//! On macOS / Linux, the key file is chmod 0600 so the server refuses to start
//! later if the user has loosened it.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::path::Path;

pub struct CertFiles {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn ensure(cert_path: &Path, key_path: &Path, hostnames: &[String]) -> anyhow::Result<CertFiles> {
    if cert_path.exists() && key_path.exists() {
        check_key_perms(key_path)?;
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        return Ok(CertFiles { cert_pem, key_pem });
    }

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(hostnames.to_vec())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "terminal-hub");
    dn.push(DnType::OrganizationName, "terminal-hub");
    params.distinguished_name = dn;
    for h in hostnames {
        if h.parse::<std::net::IpAddr>().is_ok() {
            params.subject_alt_names.push(SanType::IpAddress(h.parse()?));
        } else {
            params.subject_alt_names.push(SanType::DnsName(h.parse()?));
        }
    }
    // ten years; rotation procedure documented in §10 of the spec.
    params.not_after = rcgen::date_time_ymd(2036, 1, 1);

    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    if let Some(parent) = cert_path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(cert_path, &cert_pem)?;
    std::fs::write(key_path, &key_pem)?;
    set_key_perms(key_path)?;

    Ok(CertFiles { cert_pem, key_pem })
}

#[cfg(unix)]
fn set_key_perms(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(p)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(p, perms)
}

#[cfg(not(unix))]
fn set_key_perms(_p: &Path) -> std::io::Result<()> { Ok(()) }

#[cfg(unix)]
fn check_key_perms(p: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(p)?.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode & 0o077 == 0,
        "TLS key {} is world/group readable (mode {:o}); chmod 600",
        p.display(), mode
    );
    Ok(())
}

#[cfg(not(unix))]
fn check_key_perms(_p: &Path) -> anyhow::Result<()> { Ok(()) }

/// SHA-256 fingerprint of the DER-encoded cert, formatted as colon-hex.
pub fn fingerprint(cert_pem: &str) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let pem = pem::parse(cert_pem.as_bytes())?;
    let mut h = Sha256::new();
    h.update(pem.contents());
    let bytes = h.finalize();
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reuses() {
        let tmp = tempfile::tempdir().unwrap();
        let c = tmp.path().join("tls.crt");
        let k = tmp.path().join("tls.key");
        let a = ensure(&c, &k, &["localhost".into(), "127.0.0.1".into()]).unwrap();
        let b = ensure(&c, &k, &["localhost".into(), "127.0.0.1".into()]).unwrap();
        assert_eq!(a.cert_pem, b.cert_pem);
        assert!(a.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn rejects_loose_perms() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let c = tmp.path().join("tls.crt");
            let k = tmp.path().join("tls.key");
            ensure(&c, &k, &["localhost".into()]).unwrap();
            let mut perms = std::fs::metadata(&k).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&k, perms).unwrap();
            assert!(ensure(&c, &k, &["localhost".into()]).is_err());
        }
    }
}
```

Add `pub mod tls;` to `crates/server/src/lib.rs`.

Add `pem = "3"` and `sha2 = "0.10"` to `[dependencies]` to support `fingerprint`.

- [ ] **Step 3: Run + commit**

Run: `cargo test -p terminal-hub-server tls`
Expected: 2 pass.

```bash
git add crates/server/Cargo.toml crates/server/src/tls.rs crates/server/src/lib.rs
git commit -m "feat(server): rcgen-based self-signed TLS with 0600-key enforcement"
```

---

## Task 4: SSH-pubkey parsing + challenge signing (shared crate)

The challenge/verify path is used by both the server (verify) and the CLI (sign). Put it in a small shared crate so we don't duplicate.

**Files:**
- Create: `crates/auth-core/Cargo.toml`
- Create: `crates/auth-core/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Add the workspace member**

Update `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/tmux-client", "crates/server", "crates/cli", "crates/auth-core"]
```

- [ ] **Step 2: Create the crate**

Create `crates/auth-core/Cargo.toml`:

```toml
[package]
name = "auth-core"
version = "0.1.0"
edition.workspace = true

[dependencies]
ssh-key = { version = "0.6", features = ["ed25519", "rsa"] }
ed25519-dalek = "2"
sha2 = "0.10"
base64 = "0.22"
thiserror = { workspace = true }

[dev-dependencies]
rand = "0.8"
```

Create `crates/auth-core/src/lib.rs`:

```rust
//! Verifies SSH-key signatures over an opaque challenge bytestring.
//!
//! Used by:
//!   - server: parses stored OpenSSH pubkey, verifies signature on POST /auth/enroll/initiate
//!   - CLI:    parses local OpenSSH privkey or asks ssh-agent to sign
//!
//! The "challenge" is 32 random bytes. The signed payload is `b"terminal-hub-enroll\0" || challenge`
//! to prevent the signature from being usable as proof-of-possession for a different protocol.

use base64::Engine;
use sha2::{Digest, Sha256};
use ssh_key::PublicKey;

pub const SIG_DOMAIN: &[u8] = b"terminal-hub-enroll\0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh-key parse: {0}")] Parse(#[from] ssh_key::Error),
    #[error("unsupported key algorithm: {0}")] UnsupportedAlgo(String),
    #[error("signature verification failed")] BadSig,
    #[error("base64: {0}")] B64(#[from] base64::DecodeError),
    #[error("ed25519: {0}")] Ed(#[from] ed25519_dalek::SignatureError),
}

/// `payload(challenge)` is what gets signed. Exposed so the CLI signs the same bytes.
pub fn payload(challenge: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_DOMAIN.len() + challenge.len());
    v.extend_from_slice(SIG_DOMAIN);
    v.extend_from_slice(challenge);
    v
}

/// SHA-256 fingerprint of the OpenSSH pubkey wire encoding, b64-no-pad. Audit/debug only.
pub fn pubkey_fingerprint(openssh: &str) -> Result<String, Error> {
    let pk = PublicKey::from_openssh(openssh)?;
    let mut h = Sha256::new();
    h.update(pk.key_data().to_bytes()?);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize()))
}

/// Verify a raw signature blob (algorithm-specific encoding) against `payload(challenge)`.
///
/// We only support ssh-ed25519 in M3. RSA support is a fast follow.
pub fn verify(openssh_pubkey: &str, challenge: &[u8], signature: &[u8]) -> Result<(), Error> {
    let pk = PublicKey::from_openssh(openssh_pubkey)?;
    match pk.key_data() {
        ssh_key::public::KeyData::Ed25519(ed) => {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(ed.0.as_ref().try_into().map_err(|_| Error::BadSig)?)?;
            let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::BadSig)?;
            vk.verify_strict(&payload(challenge), &sig).map_err(|_| Error::BadSig)?;
            Ok(())
        }
        other => Err(Error::UnsupportedAlgo(format!("{:?}", other.algorithm()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    fn make_ed25519_keypair() -> (ed25519_dalek::SigningKey, String) {
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let vk_bytes = sk.verifying_key().to_bytes();
        let ssh_pub = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(vk_bytes));
        let openssh = ssh_pub.to_openssh().unwrap();
        (sk, openssh)
    }

    #[test]
    fn roundtrip_ed25519() {
        let (sk, openssh) = make_ed25519_keypair();
        let challenge = [7u8; 32];
        let sig = sk.sign(&payload(&challenge));
        verify(&openssh, &challenge, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn rejects_wrong_challenge() {
        let (sk, openssh) = make_ed25519_keypair();
        let sig = sk.sign(&payload(&[1u8; 32]));
        assert!(verify(&openssh, &[2u8; 32], &sig.to_bytes()).is_err());
    }

    #[test]
    fn fingerprint_is_stable() {
        let (_sk, openssh) = make_ed25519_keypair();
        assert_eq!(pubkey_fingerprint(&openssh).unwrap(), pubkey_fingerprint(&openssh).unwrap());
    }
}
```

- [ ] **Step 3: Run + commit**

Run: `cargo test -p auth-core`
Expected: 3 pass.

```bash
git add Cargo.toml crates/auth-core/
git commit -m "feat(auth-core): shared SSH-key challenge/verify primitive (ed25519)"
```

---

## Task 5: Challenge store + bootstrap-token machinery (server-side)

**Files:**
- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/auth/mod.rs`
- Create: `crates/server/src/auth/challenge.rs`
- Create: `crates/server/src/auth/bootstrap.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Add deps**

Add to `crates/server/Cargo.toml` `[dependencies]`:

```toml
auth-core = { path = "../auth-core" }
argon2 = "0.5"
base64 = "0.22"
sha2 = "0.10"
rand = "0.8"
```

- [ ] **Step 2: Auth module root**

Create `crates/server/src/auth/mod.rs`:

```rust
pub mod bootstrap;
pub mod challenge;

/// Hash a cookie value (or any opaque secret) with SHA-256 for storage in the DB.
/// We don't need argon2 here because the secret is full-entropy (32 random bytes b64-encoded);
/// salting buys nothing.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}
```

- [ ] **Step 3: Challenge store**

Create `crates/server/src/auth/challenge.rs`:

```rust
//! In-memory store of "we issued challenge X for email Y at time Z".
//! 5-min TTL. Single-process; if we ever shard the server, move to SQLite.

use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub struct ChallengeStore {
    inner: Arc<Mutex<HashMap<String, Entry>>>, // key = b64(challenge); value = (email, issued)
}

struct Entry {
    email: String,
    issued: Instant,
}

impl Default for ChallengeStore {
    fn default() -> Self { Self { inner: Default::default() } }
}

impl ChallengeStore {
    pub fn new() -> Self { Self::default() }

    pub async fn issue(&self, email: &str) -> (Vec<u8>, String) {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let mut g = self.inner.lock().await;
        self.gc_locked(&mut g);
        g.insert(b64.clone(), Entry { email: email.to_string(), issued: Instant::now() });
        (bytes.to_vec(), b64)
    }

    /// Returns the email the challenge was issued for, if valid and unconsumed.
    pub async fn consume(&self, challenge_b64: &str) -> Option<String> {
        let mut g = self.inner.lock().await;
        self.gc_locked(&mut g);
        let entry = g.remove(challenge_b64)?;
        if entry.issued.elapsed() > TTL { return None; }
        Some(entry.email)
    }

    fn gc_locked(&self, g: &mut HashMap<String, Entry>) {
        g.retain(|_, e| e.issued.elapsed() <= TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issue_and_consume_once() {
        let s = ChallengeStore::new();
        let (_raw, b64) = s.issue("a@b").await;
        assert_eq!(s.consume(&b64).await.as_deref(), Some("a@b"));
        assert_eq!(s.consume(&b64).await, None, "single-use only");
    }

    #[tokio::test]
    async fn unknown_returns_none() {
        let s = ChallengeStore::new();
        assert_eq!(s.consume("never-issued").await, None);
    }
}
```

- [ ] **Step 4: Bootstrap-token helpers**

Create `crates/server/src/auth/bootstrap.rs`:

```rust
//! Bootstrap tokens are the one-time secret that lets the user open the enrollment
//! URL in the browser after the CLI has proved possession of the SSH key.
//!
//! The raw token (b64) is shown to the user once. Only its argon2 hash lives in the DB.

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use base64::Engine;
use rand::RngCore;

use crate::db::Store;

pub const TTL_SECS: i64 = 5 * 60;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("argon2: {0}")] Argon(String),
    #[error("db: {0}")] Db(#[from] anyhow::Error),
    #[error("expired or unknown token")] Invalid,
}

/// Generate a new token, store its argon2 hash in `bootstrap_tokens`, return the raw value
/// (encoded as URL-safe b64 — what we hand to the user via the CLI).
pub async fn mint(store: &Store, email: &str) -> Result<String, Error> {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let raw_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);

    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon = Argon2::default();
    let hash = argon
        .hash_password(raw_b64.as_bytes(), &salt)
        .map_err(|e| Error::Argon(e.to_string()))?
        .to_string();

    store.insert_bootstrap_token(hash.as_bytes(), email, TTL_SECS).await?;
    Ok(raw_b64)
}

/// Look up an unconsumed, unexpired token whose hash verifies against `raw_b64`.
/// On success, marks it consumed and returns the email.
pub async fn redeem(store: &Store, raw_b64: &str) -> Result<String, Error> {
    // We can't index by raw token (we don't store it). Scan unexpired rows
    // and argon2-verify each. The set is tiny (one user, 5-min TTL, max a few
    // outstanding tokens), so the O(n) cost is irrelevant.
    let rows = store.list_bootstrap_tokens_for_all_users().await?;
    for row in rows {
        let stored = std::str::from_utf8(&row.token_hash).map_err(|_| Error::Invalid)?;
        let parsed = argon2::PasswordHash::new(stored).map_err(|e| Error::Argon(e.to_string()))?;
        if Argon2::default().verify_password(raw_b64.as_bytes(), &parsed).is_ok() {
            if store.consume_bootstrap_token(&row.token_hash).await? {
                return Ok(row.user_email);
            }
        }
    }
    Err(Error::Invalid)
}
```

We added a method call we don't have yet (`list_bootstrap_tokens_for_all_users`). Add it to `crates/server/src/db/mod.rs` under the `// ---------- bootstrap tokens ----------` block:

```rust
pub async fn list_bootstrap_tokens_for_all_users(&self) -> anyhow::Result<Vec<BootstrapTokenRow>> {
    let g = self.inner.lock().await;
    let mut stmt = g.prepare(
        "SELECT token_hash, user_email, issued_at, expires_at, consumed_at
         FROM bootstrap_tokens WHERE consumed_at IS NULL AND expires_at > ?1",
    )?;
    let rows = stmt.query_map(params![now_secs()], |r| Ok(BootstrapTokenRow {
        token_hash: r.get(0)?,
        user_email: r.get(1)?,
        issued_at: r.get(2)?,
        expires_at: r.get(3)?,
        consumed_at: r.get(4)?,
    }))?
    .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}
```

Add `pub mod auth;` to `crates/server/src/lib.rs`.

- [ ] **Step 5: Inline tests for bootstrap**

Append to `crates/server/src/auth/bootstrap.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mint_redeem_consume_once() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary").await.unwrap();
        let raw = mint(&s, "a@b").await.unwrap();
        assert_eq!(redeem(&s, &raw).await.unwrap(), "a@b");
        assert!(matches!(redeem(&s, &raw).await, Err(Error::Invalid)));
    }

    #[tokio::test]
    async fn redeem_with_garbage_fails() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary").await.unwrap();
        let _raw = mint(&s, "a@b").await.unwrap();
        assert!(matches!(redeem(&s, "not-a-real-token").await, Err(Error::Invalid)));
    }
}
```

- [ ] **Step 6: Run + commit**

Run: `cargo test -p terminal-hub-server auth`
Expected: 4 pass (2 challenge, 2 bootstrap).

```bash
git add crates/server/Cargo.toml crates/server/src/auth/ crates/server/src/db/mod.rs crates/server/src/lib.rs
git commit -m "feat(server): challenge store + argon2-hashed bootstrap tokens"
```

---

## Task 6: WebAuthn passkey ceremonies

webauthn-rs 0.5 keeps per-user state as a serializable `Passkey` (registration) / list-of-`Passkey` (auth). We store the JSON-serialized list in `users.passkey_creds` and keep the in-flight `PasskeyRegistration` / `PasskeyAuthentication` state in memory keyed by a short-lived ID.

**Files:**
- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/auth/passkey.rs`
- Modify: `crates/server/src/auth/mod.rs`

- [ ] **Step 1: Add deps**

Add to `crates/server/Cargo.toml` `[dependencies]`:

```toml
webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
url = "2"
uuid = { version = "1", features = ["v4", "serde"] }
```

(`uuid` may already be present from M2 with `v7,serde` — merge feature flags.)

- [ ] **Step 2: Implement the passkey module**

Create `crates/server/src/auth/passkey.rs`:

```rust
//! webauthn-rs wrapper. One Webauthn instance per server boot, keyed off
//! TERMINAL_HUB_PUBLIC_URL. The RP-ID is derived from that URL's host.

use crate::db::Store;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

const STATE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("webauthn: {0}")] Webauthn(#[from] WebauthnError),
    #[error("db: {0}")] Db(#[from] anyhow::Error),
    #[error("no such user")] NoUser,
    #[error("registration state expired or unknown")] BadState,
    #[error("user has no passkey enrolled")] NoCreds,
    #[error("json: {0}")] Json(#[from] serde_json::Error),
    #[error("config: {0}")] Config(String),
}

#[derive(Clone)]
pub struct PasskeySvc {
    wan: Arc<Webauthn>,
    reg_state: Arc<Mutex<HashMap<Uuid, (String, PasskeyRegistration, Instant)>>>,
    auth_state: Arc<Mutex<HashMap<Uuid, (String, PasskeyAuthentication, Instant)>>>,
}

impl PasskeySvc {
    /// Builds the Webauthn instance from `TERMINAL_HUB_PUBLIC_URL` (e.g. `https://hub.local:5999/`).
    /// Fails loudly if unset — RP-ID is mandatory.
    pub fn from_env() -> Result<Self, Error> {
        let raw = std::env::var("TERMINAL_HUB_PUBLIC_URL")
            .map_err(|_| Error::Config("TERMINAL_HUB_PUBLIC_URL must be set".into()))?;
        let url = Url::parse(&raw).map_err(|e| Error::Config(format!("bad public url: {e}")))?;
        let rp_id = url.host_str().ok_or_else(|| Error::Config("public url has no host".into()))?;
        let origin = Url::parse(&format!("{}://{}{}",
                                         url.scheme(),
                                         url.host_str().unwrap(),
                                         url.port().map(|p| format!(":{p}")).unwrap_or_default()))
            .map_err(|e| Error::Config(e.to_string()))?;
        let wan = WebauthnBuilder::new(rp_id, &origin)
            .map_err(Error::Webauthn)?
            .rp_name("terminal-hub")
            .build()
            .map_err(Error::Webauthn)?;
        Ok(Self {
            wan: Arc::new(wan),
            reg_state: Default::default(),
            auth_state: Default::default(),
        })
    }

    pub fn rp_id(&self) -> &str { self.wan.get_allowed_origins()[0].host_str().unwrap_or("") }

    // ---------- registration ----------

    pub async fn start_registration(
        &self, store: &Store, email: &str,
    ) -> Result<(Uuid, CreationChallengeResponse), Error> {
        let user = store.get_user(email).await?.ok_or(Error::NoUser)?;
        let existing: Vec<Passkey> = match &user.passkey_creds {
            Some(b) => serde_json::from_slice(b).unwrap_or_default(),
            None => Vec::new(),
        };
        let exclude: Vec<CredentialID> = existing.iter().map(|p| p.cred_id().clone()).collect();
        let user_id = stable_user_uuid(email);
        let (ccr, reg) = self.wan.start_passkey_registration(
            user_id,
            email,
            email,
            if exclude.is_empty() { None } else { Some(exclude) },
        )?;
        let token = Uuid::new_v4();
        let mut g = self.reg_state.lock().await;
        gc(&mut g);
        g.insert(token, (email.to_string(), reg, Instant::now()));
        Ok((token, ccr))
    }

    pub async fn finish_registration(
        &self, store: &Store, token: Uuid, rpkc: &RegisterPublicKeyCredential,
    ) -> Result<(), Error> {
        let (email, reg) = {
            let mut g = self.reg_state.lock().await;
            let (email, reg, t) = g.remove(&token).ok_or(Error::BadState)?;
            if t.elapsed() > STATE_TTL { return Err(Error::BadState); }
            (email, reg)
        };
        let pk = self.wan.finish_passkey_registration(rpkc, &reg)?;
        let user = store.get_user(&email).await?.ok_or(Error::NoUser)?;
        let mut existing: Vec<Passkey> = match user.passkey_creds {
            Some(b) => serde_json::from_slice(&b).unwrap_or_default(),
            None => Vec::new(),
        };
        existing.push(pk);
        let blob = serde_json::to_vec(&existing)?;
        store.set_passkey_creds(&email, &blob).await?;
        let _ = store.audit(Some(&email), "passkey-register", None).await;
        Ok(())
    }

    // ---------- authentication ----------

    pub async fn start_authentication(
        &self, store: &Store, email: &str,
    ) -> Result<(Uuid, RequestChallengeResponse), Error> {
        let user = store.get_user(email).await?.ok_or(Error::NoUser)?;
        let creds: Vec<Passkey> = serde_json::from_slice(
            user.passkey_creds.as_deref().ok_or(Error::NoCreds)?,
        ).map_err(Error::Json)?;
        if creds.is_empty() { return Err(Error::NoCreds); }
        let (rcr, st) = self.wan.start_passkey_authentication(&creds)?;
        let token = Uuid::new_v4();
        let mut g = self.auth_state.lock().await;
        gc(&mut g);
        g.insert(token, (email.to_string(), st, Instant::now()));
        Ok((token, rcr))
    }

    pub async fn finish_authentication(
        &self, store: &Store, token: Uuid, pkc: &PublicKeyCredential,
    ) -> Result<String, Error> {
        let (email, st) = {
            let mut g = self.auth_state.lock().await;
            let (email, st, t) = g.remove(&token).ok_or(Error::BadState)?;
            if t.elapsed() > STATE_TTL { return Err(Error::BadState); }
            (email, st)
        };
        let result = self.wan.finish_passkey_authentication(pkc, &st)?;
        // Update counters in stored creds.
        let user = store.get_user(&email).await?.ok_or(Error::NoUser)?;
        let mut creds: Vec<Passkey> = serde_json::from_slice(
            user.passkey_creds.as_deref().ok_or(Error::NoCreds)?,
        )?;
        for c in creds.iter_mut() {
            c.update_credential(&result);
        }
        let blob = serde_json::to_vec(&creds)?;
        store.set_passkey_creds(&email, &blob).await?;
        let _ = store.audit(Some(&email), "passkey-login", None).await;
        Ok(email)
    }
}

/// Deterministic user-handle UUID, derived from the email.
fn stable_user_uuid(email: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, email.as_bytes())
}

fn gc<V>(map: &mut HashMap<Uuid, (String, V, Instant)>) {
    map.retain(|_, (_, _, t)| t.elapsed() <= STATE_TTL);
}
```

Export it from `crates/server/src/auth/mod.rs`:

```rust
pub mod bootstrap;
pub mod challenge;
pub mod passkey;
```

(plus the existing `pub fn sha256`).

- [ ] **Step 3: Smoke build**

WebAuthn flows are hard to unit-test without a virtual authenticator; we exercise them through the HTTP integration tests in Task 8. Just confirm it compiles.

Run: `cargo build -p terminal-hub-server`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add crates/server/Cargo.toml crates/server/src/auth/
git commit -m "feat(server): webauthn-rs passkey registration + authentication services"
```

---

## Task 7: Auth HTTP routes + cookie middleware + AppState wiring

This task is dense: it adds the routes, the cookie middleware that gates everything else, and revises `lib.rs` to thread `Store` + `ChallengeStore` + `PasskeySvc` through `AppState`.

**Files:**
- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/auth/routes.rs`
- Create: `crates/server/src/auth/middleware.rs`
- Modify: `crates/server/src/auth/mod.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Add deps**

Add to `crates/server/Cargo.toml` `[dependencies]`:

```toml
cookie = "0.18"
tower-cookies = "0.10"
```

- [ ] **Step 2: Routes**

Create `crates/server/src/auth/routes.rs`:

```rust
use crate::auth::{bootstrap, challenge::ChallengeStore, passkey::PasskeySvc, sha256};
use crate::db::Store;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

const COOKIE_NAME: &str = "th_session";
const COOKIE_TTL_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Clone)]
pub struct AuthState {
    pub store: Store,
    pub challenge: ChallengeStore,
    pub passkey: Arc<PasskeySvc>,
    pub public_url: String,
}

// ---------- /auth/challenge ----------

#[derive(Deserialize)]
pub struct ChallengeReq { pub email: String }

#[derive(Serialize)]
pub struct ChallengeResp { pub challenge: String }

pub async fn post_challenge(
    State(s): State<AuthState>,
    Json(b): Json<ChallengeReq>,
) -> Result<Json<ChallengeResp>, (StatusCode, String)> {
    if s.store.get_user(&b.email).await.map_err(e500)?.is_none() {
        // Deliberate: don't leak whether the user exists. Still issue a challenge,
        // it just won't verify later.
    }
    let (_raw, b64) = s.challenge.issue(&b.email).await;
    Ok(Json(ChallengeResp { challenge: b64 }))
}

// ---------- /auth/enroll/initiate ----------

#[derive(Deserialize)]
pub struct InitiateReq {
    pub email: String,
    pub challenge: String,   // b64-URL-no-pad of the 32-byte challenge
    pub signature: String,   // b64-URL-no-pad of the raw ed25519 signature bytes
}

#[derive(Serialize)]
pub struct InitiateResp {
    pub bootstrap_url: String,
    pub token: String,
}

pub async fn post_enroll_initiate(
    State(s): State<AuthState>,
    Json(b): Json<InitiateReq>,
) -> Result<Json<InitiateResp>, (StatusCode, String)> {
    let claimed_email = s.challenge.consume(&b.challenge).await
        .ok_or((StatusCode::UNAUTHORIZED, "unknown or expired challenge".into()))?;
    if claimed_email != b.email {
        return Err((StatusCode::UNAUTHORIZED, "email mismatch".into()));
    }
    let user = s.store.get_user(&b.email).await.map_err(e500)?
        .ok_or((StatusCode::UNAUTHORIZED, "no such user".into()))?;
    let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b.challenge.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b.signature.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    auth_core::verify(&user.pubkey_openssh, &challenge_bytes, &sig)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "signature verification failed".into()))?;

    let token = bootstrap::mint(&s.store, &b.email).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = s.store.audit(Some(&b.email), "enroll-initiate", None).await;
    let mut url = s.public_url.trim_end_matches('/').to_string();
    url.push_str("/enroll.html?t=");
    url.push_str(&token);
    Ok(Json(InitiateResp { bootstrap_url: url, token }))
}

// ---------- /auth/passkey/register/start ----------

#[derive(Deserialize)]
pub struct StartRegQuery { pub t: String }

#[derive(Serialize)]
pub struct StartRegResp {
    pub registration_id: Uuid,
    pub ccr: serde_json::Value,
}

pub async fn get_passkey_register_start(
    State(s): State<AuthState>,
    Query(q): Query<StartRegQuery>,
) -> Result<Json<StartRegResp>, (StatusCode, String)> {
    let email = bootstrap::redeem(&s.store, &q.t).await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid bootstrap token".into()))?;
    let (id, ccr) = s.passkey.start_registration(&s.store, &email).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(StartRegResp { registration_id: id, ccr: serde_json::to_value(ccr).unwrap() }))
}

// ---------- /auth/passkey/register/finish ----------

#[derive(Deserialize)]
pub struct FinishRegReq {
    pub registration_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

pub async fn post_passkey_register_finish(
    State(s): State<AuthState>,
    Json(b): Json<FinishRegReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    s.passkey.finish_registration(&s.store, b.registration_id, &b.credential).await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- /auth/passkey/login/start ----------

#[derive(Deserialize)]
pub struct StartLoginReq { pub email: String }

#[derive(Serialize)]
pub struct StartLoginResp {
    pub auth_id: Uuid,
    pub rcr: serde_json::Value,
}

pub async fn post_passkey_login_start(
    State(s): State<AuthState>,
    Json(b): Json<StartLoginReq>,
) -> Result<Json<StartLoginResp>, (StatusCode, String)> {
    let (id, rcr) = s.passkey.start_authentication(&s.store, &b.email).await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok(Json(StartLoginResp { auth_id: id, rcr: serde_json::to_value(rcr).unwrap() }))
}

// ---------- /auth/passkey/login/finish ----------

#[derive(Deserialize)]
pub struct FinishLoginReq {
    pub auth_id: Uuid,
    pub credential: PublicKeyCredential,
}

pub async fn post_passkey_login_finish(
    State(s): State<AuthState>,
    cookies: Cookies,
    Json(b): Json<FinishLoginReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let email = s.passkey.finish_authentication(&s.store, b.auth_id, &b.credential).await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let cookie_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    s.store.insert_session(&sha256(cookie_value.as_bytes()), &email, COOKIE_TTL_SECS).await
        .map_err(e500)?;
    let mut c = Cookie::new(COOKIE_NAME, cookie_value);
    c.set_http_only(true);
    c.set_secure(true);
    c.set_same_site(cookie::SameSite::Lax);
    c.set_path("/");
    c.set_max_age(cookie::time::Duration::seconds(COOKIE_TTL_SECS));
    cookies.add(c);
    Ok(StatusCode::NO_CONTENT)
}

// ---------- /auth/logout ----------

pub async fn post_logout(
    State(s): State<AuthState>,
    cookies: Cookies,
) -> Result<StatusCode, (StatusCode, String)> {
    if let Some(c) = cookies.get(COOKIE_NAME) {
        let _ = s.store.delete_session(&sha256(c.value().as_bytes())).await;
        let mut clear = Cookie::new(COOKIE_NAME, "");
        clear.set_path("/");
        clear.set_max_age(cookie::time::Duration::seconds(0));
        cookies.add(clear);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn e500<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub const COOKIE_NAME_PUB: &str = COOKIE_NAME;
```

- [ ] **Step 3: Middleware**

Create `crates/server/src/auth/middleware.rs`:

```rust
//! Cookie middleware. Public routes (login.html, enroll.html, /healthz, anything
//! under /auth/) are exempt; everything else returns 401 if there's no valid cookie.

use crate::auth::{routes::COOKIE_NAME_PUB, sha256};
use crate::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use tower_cookies::Cookies;

pub async fn require_session(
    State(state): State<AppState>,
    cookies: Cookies,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if is_public(path) {
        return next.run(req).await;
    }
    let Some(cookie) = cookies.get(COOKIE_NAME_PUB) else {
        return unauth(path);
    };
    let hash = sha256(cookie.value().as_bytes());
    match state.auth.store.lookup_session(&hash).await {
        Ok(Some(_)) => next.run(req).await,
        _ => unauth(path),
    }
}

fn is_public(path: &str) -> bool {
    path == "/healthz"
        || path == "/login.html"
        || path == "/enroll.html"
        || path == "/app.css"
        || path == "/login.js"
        || path == "/enroll.js"
        || path.starts_with("/auth/")
}

fn unauth(path: &str) -> Response {
    // For HTML page requests, redirect to login. For API / WS, return 401.
    if path.starts_with("/api/") || path.starts_with("/ws/") {
        (StatusCode::UNAUTHORIZED, "auth required").into_response()
    } else {
        Redirect::to("/login.html").into_response()
    }
}
```

- [ ] **Step 4: Wire it all into lib.rs**

Replace `crates/server/src/lib.rs`:

```rust
use axum::routing::{any, get, post};
use axum::Router;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

pub mod api;
pub mod attach;
pub mod auth;
pub mod db;
pub mod hub;
pub mod paths;
pub mod session_id;
pub mod sessions;
pub mod tls;

pub struct Config {
    pub tmux_socket: String,
    pub tmux_session: String,
    pub bind: String,
    pub public_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tmux_socket: std::env::var("TERMINAL_HUB_TMUX_SOCKET").unwrap_or_else(|_| "terminal-hub".into()),
            tmux_session: std::env::var("TERMINAL_HUB_TMUX_SESSION").unwrap_or_else(|_| "_boot".into()),
            bind: std::env::var("TERMINAL_HUB_BIND").unwrap_or_else(|_| "127.0.0.1:5999".into()),
            public_url: std::env::var("TERMINAL_HUB_PUBLIC_URL").unwrap_or_else(|_| "https://localhost:5999/".into()),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub mgr: Arc<sessions::Manager>,
    pub cfg: Arc<Config>,
    pub hub: hub::Hub,
    pub auth: auth::routes::AuthState,
}

pub async fn router_with(cfg: Config, store: db::Store) -> anyhow::Result<Router> {
    std::env::set_var("TERMINAL_HUB_PUBLIC_URL", &cfg.public_url);
    let mgr = Arc::new(sessions::Manager::connect(&cfg.tmux_socket, &cfg.tmux_session).await?);
    let hub = hub::Hub::new(cfg.tmux_socket.clone());
    let passkey = Arc::new(auth::passkey::PasskeySvc::from_env()?);
    let auth_state = auth::routes::AuthState {
        store: store.clone(),
        challenge: auth::challenge::ChallengeStore::new(),
        passkey,
        public_url: cfg.public_url.clone(),
    };
    let state = AppState { mgr, cfg: Arc::new(cfg), hub, auth: auth_state };

    let auth_routes = Router::new()
        .route("/auth/challenge", post(auth::routes::post_challenge))
        .route("/auth/enroll/initiate", post(auth::routes::post_enroll_initiate))
        .route("/auth/passkey/register/start", get(auth::routes::get_passkey_register_start))
        .route("/auth/passkey/register/finish", post(auth::routes::post_passkey_register_finish))
        .route("/auth/passkey/login/start", post(auth::routes::post_passkey_login_start))
        .route("/auth/passkey/login/finish", post(auth::routes::post_passkey_login_finish))
        .route("/auth/logout", post(auth::routes::post_logout));

    Ok(Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/sessions", get(api::list).post(api::create))
        .route("/api/sessions/:id", axum::routing::patch(api::rename).delete(api::kill))
        .route("/ws/attach/:id", any(attach::ws_attach))
        .merge(auth_routes)
        .fallback_service(ServeDir::new(static_dir()))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::middleware::require_session,
        ))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")); p.push("static"); p
}
```

Replace `crates/server/src/main.rs`:

```rust
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use terminal_hub_server::{db, paths, tls, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::default();
    let paths = paths::Paths::resolve()?;
    paths.ensure()?;

    let store = db::Store::open(&paths.db())?;

    let host = url::Url::parse(&cfg.public_url)?
        .host_str().unwrap_or("localhost").to_string();
    let tls_files = tls::ensure(&paths.tls_crt(), &paths.tls_key(), &[host.clone(), "127.0.0.1".into()])?;

    let app = terminal_hub_server::router_with(cfg.clone(), store).await?;

    let tls_conf = RustlsConfig::from_pem(
        tls_files.cert_pem.into_bytes(),
        tls_files.key_pem.into_bytes(),
    ).await?;

    let addr: SocketAddr = cfg.bind.parse()?;
    tracing::info!(%addr, public_url=%cfg.public_url, "terminal-hub listening (TLS)");
    axum_server::bind_rustls(addr, tls_conf)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
```

Note: `Config` now derives nothing but is cloned in `main`. Make it derive `Clone`:

```rust
#[derive(Clone)]
pub struct Config { /* … */ }
```

Update `auth/mod.rs` to add the new submodules:

```rust
pub mod bootstrap;
pub mod challenge;
pub mod middleware;
pub mod passkey;
pub mod routes;

pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}
```

- [ ] **Step 5: Build**

Run: `cargo build -p terminal-hub-server`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/server/Cargo.toml crates/server/src/
git commit -m "feat(server): auth HTTP routes, cookie middleware, TLS startup wiring"
```

---

## Task 8: HTTP integration test for the SSH-key → bootstrap-token flow

We can't drive WebAuthn from `reqwest` (it needs a real authenticator), but we can fully exercise `/auth/challenge` → `/auth/enroll/initiate` → token redemption end-to-end with the auth-core signer.

**Files:**
- Create: `crates/server/tests/auth.rs`

- [ ] **Step 1: Add dev deps**

Add to `crates/server/Cargo.toml` `[dev-dependencies]`:

```toml
ed25519-dalek = "2"
rand = "0.8"
ssh-key = { version = "0.6", features = ["ed25519"] }
```

- [ ] **Step 2: Test**

Create `crates/server/tests/auth.rs`:

```rust
use base64::Engine;
use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::process::Command;
use terminal_hub_server::{db::Store, Config};
use tokio::net::TcpListener;

const SOCKET: &str = "terminal-hub-test-m3-auth";
const BOOT: &str = "_boot";

fn ensure() { let _ = Command::new("tmux").args(["-L", SOCKET, "new-session", "-d", "-s", BOOT]).status(); }
fn kill() { let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status(); }

fn make_user() -> (ed25519_dalek::SigningKey, String) {
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pk = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(sk.verifying_key().to_bytes()));
    (sk, pk.to_openssh().unwrap())
}

async fn spawn(store: Store) -> SocketAddr {
    std::env::set_var("TERMINAL_HUB_PUBLIC_URL", "https://localhost:65535/");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cfg = Config {
        tmux_socket: SOCKET.into(),
        tmux_session: BOOT.into(),
        bind: addr.to_string(),
        public_url: format!("http://{}/", addr),
    };
    let app = terminal_hub_server::router_with(cfg, store).await.unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_initiate_redeem_full_flow() {
    ensure();
    let store = Store::in_memory().unwrap();
    let (sk, pubkey_openssh) = make_user();
    store.upsert_user("alice@example.com", &pubkey_openssh, "primary").await.unwrap();
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::builder().cookie_store(true).build().unwrap();

    // 1) Ask for a challenge.
    let ch: serde_json::Value = c.post(format!("http://{addr}/auth/challenge"))
        .json(&serde_json::json!({ "email": "alice@example.com" }))
        .send().await.unwrap().json().await.unwrap();
    let challenge_b64 = ch["challenge"].as_str().unwrap();
    let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(challenge_b64).unwrap();

    // 2) Sign and POST /auth/enroll/initiate.
    let sig = sk.sign(&auth_core::payload(&challenge_bytes));
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let init: serde_json::Value = c.post(format!("http://{addr}/auth/enroll/initiate"))
        .json(&serde_json::json!({
            "email": "alice@example.com",
            "challenge": challenge_b64,
            "signature": sig_b64,
        }))
        .send().await.unwrap().json().await.unwrap();
    let token = init["token"].as_str().unwrap().to_string();
    assert!(init["bootstrap_url"].as_str().unwrap().contains("/enroll.html?t="));

    // 3) Redeem the token via the passkey register-start endpoint.
    //    Real WebAuthn flow needs a browser; here we only assert that the token
    //    is accepted (HTTP 200) on first use and rejected (4xx) on second.
    let r1 = c.get(format!("http://{addr}/auth/passkey/register/start?t={token}")).send().await.unwrap();
    assert_eq!(r1.status(), 200, "first redemption should succeed");
    let r2 = c.get(format!("http://{addr}/auth/passkey/register/start?t={token}")).send().await.unwrap();
    assert!(r2.status().is_client_error(), "second redemption must fail");
    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_signature_is_rejected() {
    ensure();
    let store = Store::in_memory().unwrap();
    let (_sk, pubkey_openssh) = make_user();
    store.upsert_user("eve@example.com", &pubkey_openssh, "primary").await.unwrap();
    let addr = spawn(store).await;
    let c = reqwest::Client::new();
    let ch: serde_json::Value = c.post(format!("http://{addr}/auth/challenge"))
        .json(&serde_json::json!({ "email": "eve@example.com" }))
        .send().await.unwrap().json().await.unwrap();
    let fake = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
    let resp = c.post(format!("http://{addr}/auth/enroll/initiate"))
        .json(&serde_json::json!({
            "email": "eve@example.com",
            "challenge": ch["challenge"],
            "signature": fake,
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), 401);
    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_route_requires_cookie() {
    ensure();
    let store = Store::in_memory().unwrap();
    let addr = spawn(store).await;
    let c = reqwest::Client::new();
    let r = c.get(format!("http://{addr}/api/sessions")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c.get(format!("http://{addr}/healthz")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    kill();
}
```

- [ ] **Step 3: Run + commit**

Run: `cargo test -p terminal-hub-server --test auth -- --nocapture`
Expected: 3 pass.

```bash
git add crates/server/Cargo.toml crates/server/tests/auth.rs
git commit -m "test(server): end-to-end SSH-challenge → bootstrap-token + 401 gating"
```

---

## Task 9: CLI — `bootstrap` and `enroll` subcommands

**Files:**
- Modify: `crates/cli/Cargo.toml`
- Create: `crates/cli/src/main.rs` (replace placeholder)
- Create: `crates/cli/src/agent.rs`

- [ ] **Step 1: Deps**

Replace `crates/cli/Cargo.toml`:

```toml
[package]
name = "terminal-hub-cli"
version = "0.1.0"
edition.workspace = true

[[bin]]
name = "terminal-hub-cli"
path = "src/main.rs"

[dependencies]
anyhow = { workspace = true }
auth-core = { path = "../auth-core" }
clap = { version = "4", features = ["derive"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
ssh-key = { version = "0.6", features = ["ed25519"] }
ssh-agent-client-rs = "0.9"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { workspace = true }
base64 = "0.22"
rusqlite = { version = "0.31", features = ["bundled"] }
directories-next = "2"
url = "2"
```

The CLI shares the SQLite store code with the server via direct rusqlite use for the `bootstrap` subcommand (which writes the primary user row offline; the server reads it on next boot).

- [ ] **Step 2: ssh-agent wrapper**

Create `crates/cli/src/agent.rs`:

```rust
//! Tiny wrapper over `ssh-agent-client-rs`. Connects via $SSH_AUTH_SOCK,
//! lists identities, asks the agent to sign `payload` with the public key
//! whose openssh wire form matches `wanted_openssh`.
//!
//! Fallback (reading a private key file) is documented as "later enhancement"
//! per the M3 plan; we hard-fail with a clear message if the agent has no
//! matching key.

use anyhow::{anyhow, bail, Context, Result};
use ssh_agent_client_rs::Client;
use std::path::PathBuf;

pub fn sign_with_agent(wanted_openssh: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let sock = std::env::var("SSH_AUTH_SOCK")
        .map_err(|_| anyhow!("SSH_AUTH_SOCK is not set; start ssh-agent or `ssh-add` your key"))?;
    let mut client = Client::connect(PathBuf::from(sock).as_path())
        .context("connecting to ssh-agent")?;
    let want = ssh_key::PublicKey::from_openssh(wanted_openssh)
        .context("parsing target pubkey")?;
    let identities = client.list_identities().context("ssh-agent list identities")?;
    let matched = identities
        .into_iter()
        .find(|id| id.key_data() == want.key_data())
        .ok_or_else(|| anyhow!(
            "ssh-agent has no key matching the pubkey on file. \
             Try `ssh-add ~/.ssh/id_ed25519` and re-run."
        ))?;
    let sig = client.sign(&matched, payload).context("ssh-agent sign")?;
    // ssh-agent returns an `ssh-sig` wire-format blob; for ed25519 the inner
    // signature is 64 bytes after a small framed header. ssh-agent-client-rs
    // exposes it as `Signature` — we serialize then strip the framing.
    Ok(extract_ed25519_raw(&sig)?)
}

/// SSH wire-format signatures wrap the raw bytes:
///   string "ssh-ed25519"
///   string <64 raw bytes>
/// Strip down to the 64 raw bytes.
fn extract_ed25519_raw(framed: &ssh_key::Signature) -> Result<Vec<u8>> {
    let algo = framed.algorithm();
    if algo != ssh_key::Algorithm::Ed25519 {
        bail!("unsupported signature algorithm: {algo:?}");
    }
    let bytes = framed.as_bytes();
    if bytes.len() != 64 {
        bail!("expected 64-byte ed25519 signature, got {}", bytes.len());
    }
    Ok(bytes.to_vec())
}
```

- [ ] **Step 3: Main**

Replace `crates/cli/src/main.rs`:

```rust
mod agent;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "terminal-hub-cli", version, about = "terminal-hub admin CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the primary user in the on-disk SQLite DB. Run on the server host.
    Bootstrap {
        #[arg(long)] email: String,
        #[arg(long, value_name = "PATH")] pubkey: PathBuf,
        #[arg(long, env = "TERMINAL_HUB_CONFIG_DIR")] config_dir: Option<PathBuf>,
    },
    /// Sign the server's challenge from this laptop. Prints a bootstrap URL.
    Enroll {
        #[arg(long)] server: String,
        #[arg(long)] email: String,
        /// Skip TLS verification (use for self-signed certs on a trusted network).
        #[arg(long, default_value_t = false)] insecure: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Bootstrap { email, pubkey, config_dir } => run_bootstrap(email, pubkey, config_dir),
        Cmd::Enroll { server, email, insecure } => run_enroll(server, email, insecure).await,
    }
}

fn run_bootstrap(email: String, pubkey_path: PathBuf, config_dir: Option<PathBuf>) -> Result<()> {
    let pubkey = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("reading {}", pubkey_path.display()))?;
    let pubkey = pubkey.trim().to_string();
    ssh_key::PublicKey::from_openssh(&pubkey)
        .with_context(|| "pubkey file is not in valid OpenSSH format")?;

    let dir = resolve_config_dir(config_dir)?;
    std::fs::create_dir_all(&dir)?;
    let db_path = dir.join("state.db");
    let conn = Connection::open(&db_path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(include_str!("../../server/src/db/migrations/0001_initial.sql"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    conn.execute(
        "INSERT INTO users(email, pubkey_openssh, role, enrolled_at)
         VALUES (?1, ?2, 'primary', ?3)
         ON CONFLICT(email) DO UPDATE SET pubkey_openssh = excluded.pubkey_openssh",
        params![email, pubkey, now],
    )?;
    println!("OK: primary user {email} written to {}", db_path.display());
    Ok(())
}

fn resolve_config_dir(override_: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_ { return Ok(p); }
    let pd = directories_next::ProjectDirs::from("dev", "terminal-hub", "terminal-hub")
        .ok_or_else(|| anyhow!("no platform config dir available"))?;
    Ok(pd.config_dir().to_path_buf())
}

#[derive(Deserialize)]
struct ChallengeResp { challenge: String }
#[derive(Deserialize)]
struct InitiateResp { bootstrap_url: String, token: String }

async fn run_enroll(server: String, email: String, insecure: bool) -> Result<()> {
    let base = url::Url::parse(&server).context("--server is not a valid URL")?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()?;

    // 1. Ask the server which pubkey it has on file for us. We don't have an
    //    endpoint that returns it directly (would be an info leak); the user
    //    instead must have their pubkey loaded in ssh-agent. The server uses
    //    whatever it stored at bootstrap time. We sign the challenge with every
    //    identity the agent offers and let the server verify against its stored
    //    key — first match wins.
    let chal_resp: ChallengeResp = client.post(base.join("/auth/challenge")?)
        .json(&serde_json::json!({ "email": &email }))
        .send().await?.error_for_status()?.json().await?;
    let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&chal_resp.challenge)?;
    let payload = auth_core::payload(&challenge_bytes);

    // Iterate through identities in the agent until one verifies on the server.
    let sock = std::env::var("SSH_AUTH_SOCK")
        .map_err(|_| anyhow!("SSH_AUTH_SOCK not set; run `ssh-add` first"))?;
    let mut agent = ssh_agent_client_rs::Client::connect(std::path::Path::new(&sock))
        .context("connect to ssh-agent")?;
    let identities = agent.list_identities().context("list-identities")?;
    if identities.is_empty() {
        bail!("ssh-agent has no identities loaded. Run `ssh-add ~/.ssh/id_ed25519`.");
    }

    for id in identities {
        let Ok(sig) = agent.sign(&id, &payload) else { continue };
        if sig.algorithm() != ssh_key::Algorithm::Ed25519 { continue; }
        if sig.as_bytes().len() != 64 { continue; }
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_bytes());
        let resp = client.post(base.join("/auth/enroll/initiate")?)
            .json(&serde_json::json!({
                "email": &email,
                "challenge": &chal_resp.challenge,
                "signature": sig_b64,
            }))
            .send().await?;
        if resp.status().is_success() {
            let body: InitiateResp = resp.json().await?;
            println!("\nEnrollment URL (open in your browser within 5 minutes):");
            println!("    {}\n", body.bootstrap_url);
            println!("(token: {})", body.token);
            return Ok(());
        }
        // 401 just means this identity isn't the one on file — try the next.
    }
    bail!("none of the keys in your ssh-agent match the pubkey on the server for {email}");
}
```

- [ ] **Step 4: Build + commit**

Run: `cargo build -p terminal-hub-cli`
Expected: clean.

Manual smoke (requires server running):

```bash
TERMINAL_HUB_CONFIG_DIR=/tmp/th-dev cargo run -p terminal-hub-cli -- \
    bootstrap --email you@example.com --pubkey ~/.ssh/id_ed25519.pub
```

Expected: `OK: primary user … written to /tmp/th-dev/state.db`.

```bash
git add crates/cli/
git commit -m "feat(cli): bootstrap (writes primary user) and enroll (ssh-agent challenge) subcommands"
```

---

## Task 10: Frontend — login.html + enroll.html with WebAuthn JS

**Files:**
- Create: `crates/server/static/login.html`
- Create: `crates/server/static/login.js`
- Create: `crates/server/static/enroll.html`
- Create: `crates/server/static/enroll.js`
- Create: `crates/server/static/auth.css`

- [ ] **Step 1: Shared CSS**

Create `crates/server/static/auth.css`:

```css
html, body { margin: 0; height: 100%; background: #111; color: #ddd;
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif; }
body.auth { display: grid; place-items: center; }
.card { background: #181818; border: 1px solid #2a2a2a; border-radius: 8px;
  padding: 32px; width: 360px; }
.card h1 { font-size: 16px; text-transform: uppercase; letter-spacing: 0.08em;
  margin: 0 0 24px 0; color: #aaa; }
.card label { display: block; font-size: 12px; color: #888; margin: 12px 0 4px; }
.card input { width: 100%; padding: 8px; background: #111; color: #ddd;
  border: 1px solid #333; border-radius: 4px; box-sizing: border-box; }
.card button { width: 100%; padding: 10px; margin-top: 20px; background: #2a2a2a;
  color: #ddd; border: 0; border-radius: 4px; cursor: pointer; font-size: 14px; }
.card button:hover { background: #353535; }
.card button:disabled { opacity: 0.5; cursor: not-allowed; }
.card .err { color: #f55; font-size: 12px; margin-top: 12px; min-height: 1.4em; }
.card .ok  { color: #5f5; font-size: 12px; margin-top: 12px; min-height: 1.4em; }
```

- [ ] **Step 2: Login page**

Create `crates/server/static/login.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>terminal-hub — sign in</title>
    <link rel="stylesheet" href="/auth.css">
  </head>
  <body class="auth">
    <form class="card" id="login-form">
      <h1>Sign in</h1>
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="username" required>
      <button id="submit" type="submit">Sign in with passkey</button>
      <div id="msg" class="err"></div>
    </form>
    <script src="/login.js" type="module"></script>
  </body>
</html>
```

Create `crates/server/static/login.js`:

```js
// Base64URL helpers — WebAuthn passes raw bytes as base64url-without-padding.
const b64u = {
  decode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  },
  encode(buf) {
    const s = btoa(String.fromCharCode(...new Uint8Array(buf)));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

// webauthn-rs serializes ArrayBuffers as base64url strings inside JSON.
// We need to walk known keys and convert them to actual ArrayBuffers before
// handing the structure to navigator.credentials.get().
function prepRequest(rcr) {
  const o = rcr.publicKey;
  o.challenge = b64u.decode(o.challenge);
  if (o.allowCredentials) {
    o.allowCredentials = o.allowCredentials.map(c => ({ ...c, id: b64u.decode(c.id) }));
  }
  return o;
}

function serializeAssertion(cred) {
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64u.encode(cred.response.clientDataJSON),
      authenticatorData: b64u.encode(cred.response.authenticatorData),
      signature: b64u.encode(cred.response.signature),
      userHandle: cred.response.userHandle ? b64u.encode(cred.response.userHandle) : null,
    },
    extensions: cred.getClientExtensionResults(),
  };
}

const form = document.getElementById("login-form");
const msg = document.getElementById("msg");

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  msg.textContent = "";
  const email = document.getElementById("email").value.trim();
  try {
    const startRes = await fetch("/auth/passkey/login/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (!startRes.ok) throw new Error(await startRes.text());
    const { auth_id, rcr } = await startRes.json();

    const assertion = await navigator.credentials.get({ publicKey: prepRequest(rcr) });
    if (!assertion) throw new Error("no credential returned");

    const finishRes = await fetch("/auth/passkey/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auth_id, credential: serializeAssertion(assertion) }),
    });
    if (!finishRes.ok) throw new Error(await finishRes.text());
    location.href = "/";
  } catch (e) {
    msg.textContent = e.message || String(e);
  }
});
```

- [ ] **Step 3: Enroll page**

Create `crates/server/static/enroll.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>terminal-hub — register passkey</title>
    <link rel="stylesheet" href="/auth.css">
  </head>
  <body class="auth">
    <div class="card">
      <h1>Register passkey</h1>
      <p style="font-size: 13px; color: #888; margin: 0 0 16px;">
        We'll create a passkey bound to this device. You'll use it for future logins.
      </p>
      <button id="register" type="button">Create passkey</button>
      <div id="msg" class="err"></div>
    </div>
    <script src="/enroll.js" type="module"></script>
  </body>
</html>
```

Create `crates/server/static/enroll.js`:

```js
const b64u = {
  decode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  },
  encode(buf) {
    const s = btoa(String.fromCharCode(...new Uint8Array(buf)));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

function prepCreate(ccr) {
  const o = ccr.publicKey;
  o.challenge = b64u.decode(o.challenge);
  o.user.id = b64u.decode(o.user.id);
  if (o.excludeCredentials) {
    o.excludeCredentials = o.excludeCredentials.map(c => ({ ...c, id: b64u.decode(c.id) }));
  }
  return o;
}

function serializeAttestation(cred) {
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64u.encode(cred.response.clientDataJSON),
      attestationObject: b64u.encode(cred.response.attestationObject),
    },
    extensions: cred.getClientExtensionResults(),
  };
}

const params = new URLSearchParams(location.search);
const token = params.get("t");
const msg = document.getElementById("msg");
const btn = document.getElementById("register");

if (!token) {
  msg.textContent = "Missing bootstrap token. Run `terminal-hub-cli enroll` again.";
  btn.disabled = true;
}

btn.addEventListener("click", async () => {
  msg.textContent = "";
  btn.disabled = true;
  try {
    const startRes = await fetch(`/auth/passkey/register/start?t=${encodeURIComponent(token)}`);
    if (!startRes.ok) throw new Error(await startRes.text());
    const { registration_id, ccr } = await startRes.json();

    const cred = await navigator.credentials.create({ publicKey: prepCreate(ccr) });
    if (!cred) throw new Error("user cancelled");

    const finishRes = await fetch("/auth/passkey/register/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ registration_id, credential: serializeAttestation(cred) }),
    });
    if (!finishRes.ok) throw new Error(await finishRes.text());
    msg.className = "ok";
    msg.textContent = "Passkey registered. Redirecting to sign-in…";
    setTimeout(() => { location.href = "/login.html"; }, 1500);
  } catch (e) {
    btn.disabled = false;
    msg.className = "err";
    msg.textContent = e.message || String(e);
  }
});
```

- [ ] **Step 4: Manual smoke**

Boot the server with TLS + a primary user:

```bash
# one-time
TERMINAL_HUB_CONFIG_DIR=/tmp/th-dev cargo run -p terminal-hub-cli -- \
    bootstrap --email you@example.com --pubkey ~/.ssh/id_ed25519.pub
tmux -L terminal-hub new-session -d -s _boot

# server
TERMINAL_HUB_CONFIG_DIR=/tmp/th-dev \
TERMINAL_HUB_PUBLIC_URL=https://localhost:5999/ \
TERMINAL_HUB_BIND=127.0.0.1:5999 \
cargo run -p terminal-hub-server

# laptop (separate shell)
cargo run -p terminal-hub-cli -- enroll \
    --server https://localhost:5999 --email you@example.com --insecure
```

Open the printed URL in a Chromium-based browser (accept the self-signed cert), click "Create passkey", confirm with Touch ID / platform authenticator, then sign in.

- [ ] **Step 5: Commit**

```bash
git add crates/server/static/auth.css crates/server/static/login.html \
        crates/server/static/login.js crates/server/static/enroll.html \
        crates/server/static/enroll.js
git commit -m "feat(frontend): login.html + enroll.html driving WebAuthn ceremonies"
```

---

## Task 11: Optional — Playwright e2e for clipboard / multi-line paste

Per spec §8.5, clipboard correctness is a first-class acceptance criterion. We add a single Playwright test that exercises multi-line paste into the terminal pane. Skip this task only if Playwright is unavailable in CI; mark it MANDATORY for shipping.

**Files:**
- Create: `e2e/package.json`
- Create: `e2e/playwright.config.ts`
- Create: `e2e/tests/clipboard.spec.ts`
- Create: `e2e/README.md`
- Modify: `.gitignore`

- [ ] **Step 1: Init Playwright project**

Create `e2e/package.json`:

```json
{
  "name": "terminal-hub-e2e",
  "private": true,
  "scripts": {
    "test": "playwright test"
  },
  "devDependencies": {
    "@playwright/test": "^1.45.0"
  }
}
```

Create `e2e/playwright.config.ts`:

```ts
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: {
    baseURL: process.env.TH_BASE_URL ?? "https://localhost:5999",
    ignoreHTTPSErrors: true,
    permissions: ["clipboard-read", "clipboard-write"],
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
  ],
});
```

- [ ] **Step 2: The test**

Create `e2e/tests/clipboard.spec.ts`:

```ts
import { test, expect } from "@playwright/test";

// Assumes:
//   - server is running with a primary user already signed in (cookie injected, or
//     pre-recorded `storageState` from a prior login). The fixture loader is out
//     of scope for M3; this test documents the contract.
//   - there is at least one tmux session attached at /

test.describe("clipboard paste", () => {
  test("multi-line paste arrives intact", async ({ page, context }) => {
    const payload = "line one\nline two\nline three\n";
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/");
    await page.locator(".xterm-helper-textarea").click();
    await page.evaluate(async (text) => { await navigator.clipboard.writeText(text); }, payload);
    await page.keyboard.press("Meta+V");
    // xterm.js renders into rows; check that each line shows up.
    await expect(page.locator(".xterm-rows")).toContainText("line one");
    await expect(page.locator(".xterm-rows")).toContainText("line two");
    await expect(page.locator(".xterm-rows")).toContainText("line three");
  });

  test("tab character survives paste", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/");
    await page.locator(".xterm-helper-textarea").click();
    await page.evaluate(async () => { await navigator.clipboard.writeText("col1\tcol2"); });
    await page.keyboard.press("Meta+V");
    await expect(page.locator(".xterm-rows")).toContainText("col1");
    await expect(page.locator(".xterm-rows")).toContainText("col2");
  });
});
```

Create `e2e/README.md`:

```markdown
# terminal-hub e2e

Playwright tests for clipboard / paste behavior (spec §8.5).

## Setup

    cd e2e
    npm install
    npx playwright install chromium

## Run

    TH_BASE_URL=https://localhost:5999 npm test

The current tests assume the server is running and a primary user is already
signed in (cookie present). Auth fixture wiring is a fast follow.
```

Append to `.gitignore`:

```
/e2e/node_modules/
/e2e/test-results/
/e2e/playwright-report/
```

- [ ] **Step 3: Run + commit**

Run: `cd e2e && npm install && npx playwright install chromium && npm test`
Expected: 2 tests pass (assuming server is running with auth fixture).

```bash
git add e2e/ .gitignore
git commit -m "test(e2e): Playwright clipboard / multi-line paste regression coverage"
```

---

## Task 12: README + CLAUDE.md update for M3

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: README**

Replace the "Status" and "Dev setup" sections of `README.md`:

```markdown
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
```

- [ ] **Step 2: CLAUDE.md**

Replace the `## Repository status` block with:

```markdown
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
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: README and CLAUDE.md status for M3 completion"
```

---

## Done criteria for M3

- All M1 + M2 tests still pass.
- `cargo test --workspace` is green with `tmux` installed.
- `cargo clippy --workspace -- -D warnings` clean.
- Manual flow: `terminal-hub-cli bootstrap` → start server → `terminal-hub-cli enroll`
  → open printed URL → register passkey → sign in → attach to a session.
- Re-running `enroll` produces a fresh bootstrap URL (recovery path).
- Hitting any protected route without a cookie returns 401 (API/WS) or
  redirects to `/login.html` (HTML).
- `tls.key` permissions are 0600 on disk; the server refuses to start if they're loosened.
- `TERMINAL_HUB_PUBLIC_URL` unset → server fails fast with a clear error.
- Playwright clipboard tests (Task 11) pass against a running server with a
  signed-in session.

**Next milestone:** M4 — multi-user permissions (secondaries, per-session ACLs, audit-log viewer). See `docs/superpowers/plans/2026-05-21-m4-multi-user-permissions.md`.
