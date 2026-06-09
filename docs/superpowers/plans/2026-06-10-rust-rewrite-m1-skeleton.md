# Rust Rewrite M1 — Skeleton (workspace, config, server, auth, login page) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Rust workspace and a running `ai-dev-conductor` server with health check, bcrypt login + per-IP throttling, session-token auth middleware, embedded static assets, and the ported login page — wire-compatible with the Go implementation.

**Architecture:** Cargo workspace with `crates/server` (axum HTTP, auth, handlers) and `crates/store` (rusqlite persistence). Auth/session wire behavior copies the Go conductor exactly (same cookie name, JSON shapes, status codes, log lines). Spec: `docs/superpowers/specs/2026-06-10-ai-dev-conductor-rust-rewrite-design.md`.

**Tech Stack:** Rust stable, tokio, axum 0.7, tower, rusqlite (bundled), bcrypt, sha2, rand, hex, humantime, rust-embed, mime_guess, serde/serde_json, tracing, thiserror.

**Execution environment:** ALL commands run on Annihilator inside `~/git/terminal-hub` (branch `main`). Either work in an interactive SSH shell (`ssh -p 22 shafqat@192.168.0.66`) or prefix each command with `ssh -p 22 shafqat@192.168.0.66 'cd ~/git/terminal-hub && <command>'`. The Go reference checkout is `~/git/ai-dev-conductor` on the same machine (branch `feat/file-transfer`). Rust toolchain: if `cargo` is missing, install via `curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y` and `source ~/.cargo/env`.

---

### Wire-compatibility contract (extracted from Go source — normative for every task)

- `GET /api/health` → `200` `{"status":"ok"}`
- `POST /api/login` body `{"password":"..."}`:
  - throttled → `429`, header `Retry-After: <int secs+1>`, body `{"error":"too many attempts, try again later"}`, log `auth: login throttled, ip=<ip> retry_after=<n>s`
  - malformed JSON → `400` `{"error":"invalid request"}`
  - wrong password → `401` `{"error":"invalid password"}`, log `auth: failed login attempt, ip=<ip>`
  - success → `200` `{"success":true,"token":"<64 hex chars>"}` + `Set-Cookie: ai_conductor_session=<token>; Path=/; HttpOnly; SameSite=Strict; Max-Age=<session_timeout_secs>`
- Auth token lookup order: `X-Session-Token` header → `?token=` query param → `ai_conductor_session` cookie.
- Unauthenticated: paths starting `/api` or `/ws` → `401` `{"error":"unauthorized"}`; otherwise `302` redirect to `/`.
- Client IP: first comma-separated element of `X-Forwarded-For` if present, else peer address host.
- Rate limiter: `max_attempts` failures within `window` → lockout `base * 2^offence` capped at `16 * base`; success resets all state; `max_attempts = 0` disables.
- Token: 32 random bytes, lowercase hex (64 chars). Tokens stored server-side as SHA-256 hex digests.

---

## Task 1: Workspace scaffolding

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `crates/server/Cargo.toml`, `crates/server/src/main.rs`

- [ ] **Step 1: Create workspace files**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/server", "crates/store"]

[workspace.package]
edition = "2021"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[profile.release]
lto = "thin"
codegen-units = 1
strip = "debuginfo"
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

`.gitignore`:
```
/target
*.log
*.pid
/data/
```

`crates/server/Cargo.toml`:
```toml
[package]
name = "ai-dev-conductor"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
```

`crates/server/src/main.rs`:
```rust
fn main() {
    println!("ai-dev-conductor");
}
```

- [ ] **Step 2: Create the store crate stub**

`crates/store/Cargo.toml`:
```toml
[package]
name = "store"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
thiserror = { workspace = true }
```

`crates/store/src/lib.rs`:
```rust
// rusqlite-backed persistence. Populated in Task 3.
```

- [ ] **Step 3: Verify it builds**

Run: `cargo check --workspace`
Expected: `Finished` with no errors.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "chore: cargo workspace skeleton (server + store crates)"
```

---

## Task 2: Configuration from environment

**Files:**
- Create: `crates/server/src/config.rs`
- Modify: `crates/server/src/main.rs`, `crates/server/Cargo.toml`

- [ ] **Step 1: Add dependencies**

In `crates/server/Cargo.toml` `[dependencies]` add:
```toml
humantime = "2"
thiserror = { workspace = true }
```

- [ ] **Step 2: Write failing tests**

Create `crates/server/src/config.rs` containing only the tests module for now:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn empty_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn defaults_match_go_implementation() {
        let cfg = Config::from_lookup(empty_env).unwrap();
        assert_eq!(cfg.password, "admin");
        assert_eq!(cfg.addr, "0.0.0.0:8080");
        assert_eq!(cfg.data_dir, std::path::PathBuf::from("./data/sessions"));
        assert_eq!(cfg.session_timeout, std::time::Duration::from_secs(24 * 3600));
        assert_eq!(cfg.login_max_attempts, 5);
        assert_eq!(cfg.login_window, std::time::Duration::from_secs(60));
        assert_eq!(cfg.login_lockout, std::time::Duration::from_secs(60));
        assert_eq!(cfg.pid_file, None);
    }

    #[test]
    fn env_overrides_are_parsed() {
        let lookup = |key: &str| -> Option<String> {
            match key {
                "AI_CONDUCTOR_PASSWORD" => Some("s3cret".into()),
                "AI_CONDUCTOR_ADDR" => Some("127.0.0.1:5050".into()),
                "AI_CONDUCTOR_SESSION_TIMEOUT" => Some("2h".into()),
                "AI_CONDUCTOR_LOGIN_MAX_ATTEMPTS" => Some("0".into()),
                "AI_CONDUCTOR_PID_FILE" => Some("/tmp/c.pid".into()),
                _ => None,
            }
        };
        let cfg = Config::from_lookup(lookup).unwrap();
        assert_eq!(cfg.password, "s3cret");
        assert_eq!(cfg.addr, "127.0.0.1:5050");
        assert_eq!(cfg.session_timeout, std::time::Duration::from_secs(7200));
        assert_eq!(cfg.login_max_attempts, 0);
        assert_eq!(cfg.pid_file, Some(std::path::PathBuf::from("/tmp/c.pid")));
    }

    #[test]
    fn invalid_duration_is_an_error() {
        let lookup = |key: &str| -> Option<String> {
            (key == "AI_CONDUCTOR_SESSION_TIMEOUT").then(|| "notaduration".to_string())
        };
        assert!(Config::from_lookup(lookup).is_err());
    }
}
```

Add `mod config;` to `crates/server/src/main.rs`:
```rust
mod config;

fn main() {
    println!("ai-dev-conductor");
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p ai-dev-conductor config`
Expected: COMPILE ERROR (`Config` not defined).

- [ ] **Step 4: Implement Config**

Prepend to `crates/server/src/config.rs` (above the tests module):
```rust
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub password: String,
    pub addr: String,
    pub data_dir: PathBuf,
    pub pid_file: Option<PathBuf>,
    pub session_timeout: Duration,
    pub login_max_attempts: u32,
    pub login_window: Duration,
    pub login_lockout: Duration,
}

#[derive(Debug, thiserror::Error)]
#[error("config: invalid value for {key}: {message}")]
pub struct ConfigError {
    pub key: &'static str,
    pub message: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Lookup-injected constructor so tests never touch process env.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        fn duration(
            lookup: &impl Fn(&str) -> Option<String>,
            key: &'static str,
            default: Duration,
        ) -> Result<Duration, ConfigError> {
            match lookup(key) {
                None => Ok(default),
                Some(raw) => humantime::parse_duration(&raw).map_err(|e| ConfigError {
                    key,
                    message: e.to_string(),
                }),
            }
        }

        let login_max_attempts = match lookup("AI_CONDUCTOR_LOGIN_MAX_ATTEMPTS") {
            None => 5,
            Some(raw) => raw.parse().map_err(|_| ConfigError {
                key: "AI_CONDUCTOR_LOGIN_MAX_ATTEMPTS",
                message: format!("not a number: {raw}"),
            })?,
        };

        Ok(Config {
            password: lookup("AI_CONDUCTOR_PASSWORD").unwrap_or_else(|| "admin".into()),
            addr: lookup("AI_CONDUCTOR_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into()),
            data_dir: lookup("AI_CONDUCTOR_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("./data/sessions")),
            pid_file: lookup("AI_CONDUCTOR_PID_FILE").map(PathBuf::from),
            session_timeout: duration(
                &lookup,
                "AI_CONDUCTOR_SESSION_TIMEOUT",
                Duration::from_secs(24 * 3600),
            )?,
            login_max_attempts,
            login_window: duration(&lookup, "AI_CONDUCTOR_LOGIN_WINDOW", Duration::from_secs(60))?,
            login_lockout: duration(&lookup, "AI_CONDUCTOR_LOGIN_LOCKOUT", Duration::from_secs(60))?,
        })
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p ai-dev-conductor config`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(config): env-based configuration with Go-compatible defaults"
```

---

## Task 3: Store crate — auth session persistence

**Files:**
- Modify: `crates/store/Cargo.toml`, `crates/store/src/lib.rs`

- [ ] **Step 1: Add dependencies**

`crates/store/Cargo.toml` `[dependencies]` becomes:
```toml
thiserror = { workspace = true }
rusqlite = { version = "0.31", features = ["bundled"] }
sha2 = "0.10"
hex = "0.4"
```
Add:
```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Write failing tests**

Append to `crates/store/src/lib.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("conductor.db")).unwrap();
        (store, dir)
    }

    #[test]
    fn valid_token_within_expiry_validates() {
        let (store, _d) = open_temp();
        store.add_auth_session("tok-abc", 1000).unwrap();
        assert!(store.validate_auth_session("tok-abc", 999).unwrap());
    }

    #[test]
    fn expired_token_is_rejected_and_purged() {
        let (store, _d) = open_temp();
        store.add_auth_session("tok-abc", 1000).unwrap();
        assert!(!store.validate_auth_session("tok-abc", 1000).unwrap());
        // second call still false (row purged, not resurrected)
        assert!(!store.validate_auth_session("tok-abc", 0).unwrap());
    }

    #[test]
    fn unknown_token_is_rejected() {
        let (store, _d) = open_temp();
        assert!(!store.validate_auth_session("never-issued", 0).unwrap());
    }

    #[test]
    fn raw_token_is_not_stored_in_db() {
        let (store, _d) = open_temp();
        store.add_auth_session("tok-secret", 1000).unwrap();
        let conn = store.conn.lock().unwrap();
        let token: String = conn
            .query_row("SELECT token_hash FROM auth_sessions LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_ne!(token, "tok-secret");
        assert_eq!(token.len(), 64); // sha256 hex
    }

    #[test]
    fn open_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/conductor.db");
        assert!(Store::open(&nested).is_ok());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p store`
Expected: COMPILE ERROR (`Store` not defined).

- [ ] **Step 4: Implement Store**

Replace the top of `crates/store/src/lib.rs` (above the tests module) with:
```rust
//! rusqlite-backed persistence for ai-dev-conductor.
//! M1: auth sessions only. Later milestones add sessions, api_keys, shares.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Store {
    pub(crate) conn: Mutex<Connection>,
}

const MIGRATIONS: &str = "
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
";

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(MIGRATIONS)?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    pub fn add_auth_session(&self, token: &str, expires_at: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO auth_sessions (token_hash, expires_at) VALUES (?1, ?2)",
            params![hash_token(token), expires_at],
        )?;
        Ok(())
    }

    /// Returns true when the token exists and has not expired (`now` is unix
    /// seconds). Expired rows are deleted opportunistically.
    pub fn validate_auth_session(&self, token: &str, now: i64) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM auth_sessions WHERE expires_at <= ?1", params![now])?;
        let mut stmt =
            conn.prepare("SELECT 1 FROM auth_sessions WHERE token_hash = ?1 AND expires_at > ?2")?;
        Ok(stmt.exists(params![hash_token(token), now])?)
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p store`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(store): rusqlite store with hashed auth session persistence"
```

---

## Task 4: Auth core — password hashing and token generation

**Files:**
- Create: `crates/server/src/auth/mod.rs`, `crates/server/src/auth/ratelimit.rs` (empty until Task 5)
- Modify: `crates/server/src/main.rs`, `crates/server/Cargo.toml`

- [ ] **Step 1: Add dependencies**

`crates/server/Cargo.toml` `[dependencies]` add:
```toml
bcrypt = "0.15"
rand = "0.8"
hex = "0.4"
```

- [ ] **Step 2: Write tests and implementation**

Create `crates/server/src/auth/mod.rs`:
```rust
pub mod ratelimit;

use bcrypt::{hash, verify, DEFAULT_COST};
use rand::RngCore;

pub const COOKIE_NAME: &str = "ai_conductor_session";

/// Bcrypt-hashes the configured password once at startup; verification
/// thereafter (Go parity: bcrypt password hashing).
pub struct AuthService {
    password_hash: String,
}

impl AuthService {
    pub fn new(password: &str) -> Self {
        AuthService {
            password_hash: hash(password, DEFAULT_COST).expect("bcrypt hash cannot fail"),
        }
    }

    pub fn verify_password(&self, candidate: &str) -> bool {
        verify(candidate, &self.password_hash).unwrap_or(false)
    }
}

/// 32 random bytes, lowercase hex — identical to Go GenerateSessionToken.
pub fn generate_session_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_password_verifies() {
        let svc = AuthService::new("hunter2");
        assert!(svc.verify_password("hunter2"));
    }

    #[test]
    fn wrong_password_fails() {
        let svc = AuthService::new("hunter2");
        assert!(!svc.verify_password("hunter3"));
        assert!(!svc.verify_password(""));
    }

    #[test]
    fn tokens_are_64_hex_chars_and_unique() {
        let a = generate_session_token();
        let b = generate_session_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
```

Create the empty placeholder so the module compiles:
```bash
touch crates/server/src/auth/ratelimit.rs
```

Update `crates/server/src/main.rs`:
```rust
mod auth;
mod config;

fn main() {
    println!("ai-dev-conductor");
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p ai-dev-conductor auth`
Expected: 3 passed (bcrypt tests take a few seconds).

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat(auth): bcrypt password service + hex session token generation"
```

---

## Task 5: Per-IP login rate limiter

**Files:**
- Modify: `crates/server/src/auth/ratelimit.rs`

- [ ] **Step 1: Write failing tests**

`crates/server/src/auth/ratelimit.rs` — add the tests module first:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const WINDOW: Duration = Duration::from_secs(60);
    const BASE: Duration = Duration::from_secs(60);

    fn limiter() -> RateLimiter {
        RateLimiter::new(3, WINDOW, BASE)
    }

    #[test]
    fn allowed_until_max_attempts_reached() {
        let rl = limiter();
        let t0 = Instant::now();
        for _ in 0..2 {
            assert!(rl.allowed_at("ip1", t0).0);
            rl.record_failure_at("ip1", t0);
        }
        assert!(rl.allowed_at("ip1", t0).0); // 2 failures < 3
        rl.record_failure_at("ip1", t0); // 3rd failure triggers lockout
        let (ok, retry) = rl.allowed_at("ip1", t0);
        assert!(!ok);
        assert_eq!(retry, BASE);
    }

    #[test]
    fn lockout_doubles_per_offence_capped_at_16x() {
        let rl = limiter();
        let mut t = Instant::now();
        for mult in [1u32, 2, 4, 8, 16, 16] {
            for _ in 0..3 {
                rl.record_failure_at("ip1", t);
            }
            let (ok, retry) = rl.allowed_at("ip1", t);
            assert!(!ok);
            assert_eq!(retry, BASE * mult, "offence multiplier {mult}");
            t += retry; // wait out the lockout
            assert!(rl.allowed_at("ip1", t).0);
        }
    }

    #[test]
    fn failures_outside_window_do_not_count() {
        let rl = limiter();
        let t0 = Instant::now();
        rl.record_failure_at("ip1", t0);
        rl.record_failure_at("ip1", t0);
        // Third failure arrives after the window has passed — no lockout.
        let later = t0 + WINDOW + Duration::from_secs(1);
        rl.record_failure_at("ip1", later);
        assert!(rl.allowed_at("ip1", later).0);
    }

    #[test]
    fn reset_clears_failures_and_offences() {
        let rl = limiter();
        let t0 = Instant::now();
        for _ in 0..3 {
            rl.record_failure_at("ip1", t0);
        }
        assert!(!rl.allowed_at("ip1", t0).0);
        rl.reset("ip1");
        assert!(rl.allowed_at("ip1", t0).0);
        // Offence count also cleared: next lockout is base again.
        for _ in 0..3 {
            rl.record_failure_at("ip1", t0);
        }
        assert_eq!(rl.allowed_at("ip1", t0).1, BASE);
    }

    #[test]
    fn keys_are_independent() {
        let rl = limiter();
        let t0 = Instant::now();
        for _ in 0..3 {
            rl.record_failure_at("ip1", t0);
        }
        assert!(rl.allowed_at("ip2", t0).0);
    }

    #[test]
    fn zero_max_attempts_disables_limiting() {
        let rl = RateLimiter::new(0, WINDOW, BASE);
        let t0 = Instant::now();
        for _ in 0..100 {
            rl.record_failure_at("ip1", t0);
        }
        assert!(rl.allowed_at("ip1", t0).0);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ai-dev-conductor ratelimit`
Expected: COMPILE ERROR (`RateLimiter` not defined).

- [ ] **Step 3: Implement RateLimiter**

Prepend to `crates/server/src/auth/ratelimit.rs`:
```rust
//! Per-key (client IP) login throttling. Go parity: after `max_attempts`
//! failures within `window`, lock out for base * 2^offence, capped at
//! 16 * base. Success resets everything. max_attempts == 0 disables.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_LOCKOUT_MULTIPLIER: u32 = 16;

#[derive(Default)]
struct Entry {
    failures: Vec<Instant>,
    offences: u32,
    locked_until: Option<Instant>,
}

pub struct RateLimiter {
    max_attempts: u32,
    window: Duration,
    base_lockout: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window: Duration, base_lockout: Duration) -> Self {
        RateLimiter { max_attempts, window, base_lockout, entries: Mutex::new(HashMap::new()) }
    }

    fn enabled(&self) -> bool {
        self.max_attempts > 0
    }

    pub fn allowed(&self, key: &str) -> (bool, Duration) {
        self.allowed_at(key, Instant::now())
    }

    pub fn allowed_at(&self, key: &str, now: Instant) -> (bool, Duration) {
        if !self.enabled() {
            return (true, Duration::ZERO);
        }
        let entries = self.entries.lock().unwrap();
        match entries.get(key).and_then(|e| e.locked_until) {
            Some(until) if until > now => (false, until - now),
            _ => (true, Duration::ZERO),
        }
    }

    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now())
    }

    pub fn record_failure_at(&self, key: &str, now: Instant) {
        if !self.enabled() {
            return;
        }
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(key.to_string()).or_default();
        entry.failures.retain(|t| now.duration_since(*t) < self.window);
        entry.failures.push(now);
        if entry.failures.len() as u32 >= self.max_attempts {
            let multiplier = 1u32
                .checked_shl(entry.offences)
                .unwrap_or(MAX_LOCKOUT_MULTIPLIER)
                .min(MAX_LOCKOUT_MULTIPLIER);
            entry.locked_until = Some(now + self.base_lockout * multiplier);
            entry.offences += 1;
            entry.failures.clear();
        }
    }

    pub fn reset(&self, key: &str) {
        self.entries.lock().unwrap().remove(key);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ai-dev-conductor ratelimit`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(auth): per-IP login rate limiter with exponential lockout"
```

---

## Task 6: axum app with /api/health

**Files:**
- Create: `crates/server/src/app.rs`, `crates/server/src/handlers.rs`
- Modify: `crates/server/src/main.rs`, `crates/server/Cargo.toml`

- [ ] **Step 1: Add web dependencies**

`crates/server/Cargo.toml` `[dependencies]` add:
```toml
axum = "0.7"
tower = "0.4"
serde = { workspace = true }
serde_json = { workspace = true }
store = { path = "../store" }
```
Add a dev-dependencies section:
```toml
[dev-dependencies]
http-body-util = "0.1"
tempfile = "3"
```

- [ ] **Step 2: Write the failing test**

Create `crates/server/src/app.rs`:
```rust
use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use crate::auth::ratelimit::RateLimiter;
use crate::auth::AuthService;
use crate::config::Config;
use crate::handlers;

pub struct AppState {
    pub cfg: Config,
    pub auth: AuthService,
    pub limiter: RateLimiter,
    pub store: store::Store,
}

pub type SharedState = Arc<AppState>;

pub fn build_state(cfg: Config) -> SharedState {
    let auth = AuthService::new(&cfg.password);
    let limiter = RateLimiter::new(cfg.login_max_attempts, cfg.login_window, cfg.login_lockout);
    let db_path = cfg.data_dir.join("conductor.db");
    let store = store::Store::open(&db_path).expect("cannot open store");
    Arc::new(AppState { cfg, auth, limiter, store })
}

pub fn build_app(state: SharedState) -> Router {
    Router::new()
        .route("/api/health", get(handlers::health))
        .with_state(state)
}

#[cfg(test)]
pub mod test_support {
    use super::*;

    /// App over a throwaway temp data dir; returns the dir to keep it alive.
    pub fn test_app() -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::from_lookup(|key| match key {
            "AI_CONDUCTOR_DATA_DIR" => Some(dir.path().display().to_string()),
            "AI_CONDUCTOR_PASSWORD" => Some("testpass".into()),
            _ => None,
        })
        .unwrap();
        (build_app(build_state(cfg)), dir)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::test_app;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok_json() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"status": "ok"}));
    }
}
```

Create `crates/server/src/handlers.rs`:
```rust
// handlers filled in across Tasks 6-8
```

Update `crates/server/src/main.rs`:
```rust
mod app;
mod auth;
mod config;
mod handlers;

fn main() {
    println!("ai-dev-conductor");
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p ai-dev-conductor health`
Expected: COMPILE ERROR (`handlers::health` not defined).

- [ ] **Step 4: Implement the health handler**

Replace `crates/server/src/handlers.rs`:
```rust
use axum::Json;
use serde_json::{json, Value};

pub async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p ai-dev-conductor health`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(server): axum app skeleton with /api/health"
```

---

## Task 7: Login endpoint (wire-compatible)

**Files:**
- Modify: `crates/server/src/handlers.rs`, `crates/server/src/app.rs`

- [ ] **Step 1: Write failing tests**

Append inside the `tests` module in `crates/server/src/app.rs`:
```rust
    use axum::http::header;

    async fn login(
        app: axum::Router,
        body: &str,
        xff: Option<&str>,
    ) -> axum::http::Response<axum::body::Body> {
        let mut req = Request::post("/api/login").header(header::CONTENT_TYPE, "application/json");
        if let Some(ip) = xff {
            req = req.header("X-Forwarded-For", ip);
        }
        app.oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap()
    }

    #[tokio::test]
    async fn login_success_returns_token_and_cookie() {
        let (app, _dir) = test_app();
        let res = login(app, r#"{"password":"testpass"}"#, None).await;
        assert_eq!(res.status(), StatusCode::OK);
        let cookie = res.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
        assert!(cookie.starts_with("ai_conductor_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["success"], true);
        assert_eq!(v["token"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn login_wrong_password_is_401() {
        let (app, _dir) = test_app();
        let res = login(app, r#"{"password":"nope"}"#, None).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "invalid password"}));
    }

    #[tokio::test]
    async fn login_malformed_json_is_400() {
        let (app, _dir) = test_app();
        let res = login(app, "{not json", None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "invalid request"}));
    }

    #[tokio::test]
    async fn login_throttles_after_max_attempts_with_retry_after() {
        let (app, _dir) = test_app(); // default max_attempts = 5
        for _ in 0..5 {
            let res = login(app.clone(), r#"{"password":"nope"}"#, Some("10.1.1.7")).await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
        let res = login(app.clone(), r#"{"password":"testpass"}"#, Some("10.1.1.7")).await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 =
            res.headers().get("Retry-After").unwrap().to_str().unwrap().parse().unwrap();
        assert!(retry >= 1);
        // Different IP is unaffected.
        let res = login(app, r#"{"password":"testpass"}"#, Some("10.9.9.9")).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ai-dev-conductor login`
Expected: FAIL — `/api/login` route missing (404s) or compile error.

- [ ] **Step 3: Implement the login handler**

Append to `crates/server/src/handlers.rs`:
```rust
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::app::SharedState;
use crate::auth;

/// Go parity: first X-Forwarded-For element, else peer address host.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        let first = xff.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return first.to_string();
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_default()
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

pub async fn login(
    State(state): State<SharedState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_ip(&headers, peer.map(|c| c.0));

    let (allowed, retry_after) = state.limiter.allowed(&ip);
    if !allowed {
        let secs = retry_after.as_secs() + 1;
        tracing::warn!("auth: login throttled, ip={ip} retry_after={secs}s");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, secs.to_string())],
            Json(json!({"error": "too many attempts, try again later"})),
        )
            .into_response();
    }

    #[derive(serde::Deserialize)]
    struct LoginRequest {
        #[serde(default)]
        password: String,
    }
    let Ok(req) = serde_json::from_slice::<LoginRequest>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid request");
    };

    if !state.auth.verify_password(&req.password) {
        state.limiter.record_failure(&ip);
        tracing::warn!("auth: failed login attempt, ip={ip}");
        return json_error(StatusCode::UNAUTHORIZED, "invalid password");
    }

    state.limiter.reset(&ip);

    let token = auth::generate_session_token();
    let expires_at = unix_now() + state.cfg.session_timeout.as_secs() as i64;
    if state.store.add_auth_session(&token, expires_at).is_err() {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        auth::COOKIE_NAME,
        token,
        state.cfg.session_timeout.as_secs()
    );
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(json!({"success": true, "token": token})),
    )
        .into_response()
}
```

In `crates/server/src/app.rs`, change the routing import and add the route:
```rust
use axum::routing::{get, post};
```
and in `build_app`:
```rust
        .route("/api/health", get(handlers::health))
        .route("/api/login", post(handlers::login))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ai-dev-conductor login`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(auth): wire-compatible /api/login with throttling and session cookie"
```

---

## Task 8: Auth middleware gating protected routes

**Files:**
- Create: `crates/server/src/auth/middleware.rs`
- Modify: `crates/server/src/auth/mod.rs`, `crates/server/src/app.rs`

- [ ] **Step 1: Write failing tests**

Append inside the `tests` module in `crates/server/src/app.rs`:
```rust
    async fn obtain_token(app: &axum::Router) -> String {
        let res = login(app.clone(), r#"{"password":"testpass"}"#, None).await;
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        v["token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn terminal_without_token_redirects_to_login() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/terminal").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER); // axum Redirect::to = 303
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/");
    }

    #[tokio::test]
    async fn api_without_token_gets_401_json() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/api/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "unauthorized"}));
    }

    #[tokio::test]
    async fn header_token_grants_access() {
        let (app, _dir) = test_app();
        let token = obtain_token(&app).await;
        let res = app
            .oneshot(
                Request::get("/terminal")
                    .header("X-Session-Token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn query_token_grants_access() {
        let (app, _dir) = test_app();
        let token = obtain_token(&app).await;
        let res = app
            .oneshot(
                Request::get(format!("/terminal?token={token}").as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cookie_token_grants_access() {
        let (app, _dir) = test_app();
        let token = obtain_token(&app).await;
        let res = app
            .oneshot(
                Request::get("/terminal")
                    .header(header::COOKIE, format!("ai_conductor_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn garbage_token_is_rejected() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(
                Request::get("/terminal")
                    .header("X-Session-Token", "deadbeef")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ai-dev-conductor token`
Expected: FAIL (no `/terminal`, no `/api/sessions`, no middleware).

- [ ] **Step 3: Implement the middleware**

Create `crates/server/src/auth/middleware.rs`:
```rust
//! Session-token gate. Token lookup order (Go parity):
//! X-Session-Token header -> ?token= query param -> cookie.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};

use super::COOKIE_NAME;
use crate::app::SharedState;

fn token_from_request(req: &Request) -> Option<String> {
    if let Some(h) = req.headers().get("X-Session-Token").and_then(|v| v.to_str().ok()) {
        if !h.is_empty() {
            return Some(h.to_string());
        }
    }
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("token=") {
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    let cookies = req.headers().get(header::COOKIE).and_then(|v| v.to_str().ok())?;
    for cookie in cookies.split(';') {
        if let Some(value) = cookie.trim().strip_prefix(&format!("{COOKIE_NAME}=")) {
            return Some(value.to_string());
        }
    }
    None
}

fn is_api_request(req: &Request) -> bool {
    let path = req.uri().path();
    path.starts_with("/api") || path.starts_with("/ws")
}

pub async fn require_auth(State(state): State<SharedState>, req: Request, next: Next) -> Response {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let valid = token_from_request(&req)
        .map(|t| state.store.validate_auth_session(&t, now).unwrap_or(false))
        .unwrap_or(false);

    if !valid {
        return if is_api_request(&req) {
            (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error": "unauthorized"})))
                .into_response()
        } else {
            Redirect::to("/").into_response()
        };
    }
    next.run(req).await
}
```

In `crates/server/src/auth/mod.rs` add at the top:
```rust
pub mod middleware;
```

In `crates/server/src/app.rs`, restructure `build_app` to mount protected routes behind the middleware (the placeholder handlers prove the gate; real implementations arrive in M2):
```rust
pub fn build_app(state: SharedState) -> Router {
    let protected = Router::new()
        .route("/terminal", get(|| async { "terminal placeholder (M2)" }))
        .route("/api/sessions", get(|| async { axum::Json(serde_json::json!([])) }))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::middleware::require_auth,
        ));

    Router::new()
        .route("/api/health", get(handlers::health))
        .route("/api/login", post(handlers::login))
        .merge(protected)
        .with_state(state)
}
```

- [ ] **Step 4: Run all server tests**

Run: `cargo test -p ai-dev-conductor`
Expected: all pass (config 3, auth 3, ratelimit 6, health 1, login 4, middleware 6).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(auth): session-token middleware with Go-compatible lookup order"
```

---

## Task 9: Embedded static assets + ported login page

**Files:**
- Create: `crates/server/src/assets.rs`, `web/templates/login.html`, `web/static/css/style.css`
- Modify: `crates/server/src/app.rs`, `crates/server/src/main.rs`, `crates/server/Cargo.toml`

- [ ] **Step 1: Port the frontend files from the Go checkout**

```bash
mkdir -p web/templates web/static/css web/static/js
cp ~/git/ai-dev-conductor/web/templates/login.html web/templates/login.html
cp ~/git/ai-dev-conductor/web/static/css/style.css web/static/css/style.css
```

Then inspect `web/templates/login.html` for Go template directives (`{{...}}`). The file-transfer branch templates take a base path; M1 serves at root, so strip them:

```bash
sed -i 's/{{[^}]*}}//g' web/templates/login.html
grep -n '{{' web/templates/login.html   # expect no output
```

Open the file and verify after stripping: the login form must still POST to `/api/login` with JSON `{"password": ...}` and navigate to `/terminal` on success; static hrefs must resolve to `/static/...` (fix any path the sed left relative/broken, e.g. `href="static/css/style.css"` → `href="/static/css/style.css"`).

- [ ] **Step 2: Add embed dependencies**

`crates/server/Cargo.toml` `[dependencies]` add:
```toml
rust-embed = "8"
mime_guess = "2"
```

- [ ] **Step 3: Write failing tests**

Append inside the `tests` module in `crates/server/src/app.rs`:
```rust
    #[tokio::test]
    async fn root_serves_login_page() {
        let (app, _dir) = test_app();
        let res = app.oneshot(Request::get("/").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap().to_string();
        assert!(ct.starts_with("text/html"));
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("/api/login"), "login page must reference the login API");
    }

    #[tokio::test]
    async fn static_css_is_served_with_mime() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/static/css/style.css").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap().to_string();
        assert!(ct.starts_with("text/css"));
    }

    #[tokio::test]
    async fn unknown_static_path_is_404() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/static/nope.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p ai-dev-conductor static`
Expected: FAIL (routes missing).

- [ ] **Step 5: Implement asset serving**

Create `crates/server/src/assets.rs`:
```rust
//! Embedded web assets (templates + static files), compiled into the binary.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web"]
pub struct WebAssets;

fn serve(path: &str) -> Response {
    match WebAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref().to_string())], file.data).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn login_page() -> Response {
    serve("templates/login.html")
}

pub async fn static_file(Path(rest): Path<String>) -> Response {
    serve(&format!("static/{rest}"))
}
```

Add `mod assets;` to `crates/server/src/main.rs`'s module list:
```rust
mod app;
mod assets;
mod auth;
mod config;
mod handlers;
```

In `build_app` (public section, above `.merge(protected)`) add:
```rust
        .route("/", get(crate::assets::login_page))
        .route("/static/*path", get(crate::assets::static_file))
```

- [ ] **Step 6: Run all tests**

Run: `cargo test --workspace`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(web): embed ported login page and static assets"
```

---

## Task 10: main() — serve, PID file, graceful shutdown

**Files:**
- Modify: `crates/server/src/main.rs`

- [ ] **Step 1: Implement main**

Replace `crates/server/src/main.rs`:
```rust
mod app;
mod assets;
mod auth;
mod config;
mod handlers;

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::Config::from_env().expect("invalid configuration");

    if let Some(pid_file) = &cfg.pid_file {
        std::fs::write(pid_file, std::process::id().to_string()).expect("cannot write pid file");
    }
    let pid_file = cfg.pid_file.clone();
    let addr = cfg.addr.clone();

    let state = app::build_state(cfg);
    let router = app::build_app(state).into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("cannot bind");
    tracing::info!("ai-dev-conductor listening on {addr}");

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("shutdown signal received");
        })
        .await
        .expect("server error");

    if let Some(pid_file) = pid_file {
        std::fs::remove_file(pid_file).ok();
    }
}
```

- [ ] **Step 2: Build and smoke-test manually**

```bash
cargo build
AI_CONDUCTOR_PASSWORD=smoke AI_CONDUCTOR_ADDR=127.0.0.1:8099 ./target/debug/ai-dev-conductor &
sleep 1
curl -s http://127.0.0.1:8099/api/health
# expect: {"status":"ok"}
curl -s -X POST http://127.0.0.1:8099/api/login -d '{"password":"smoke"}'
# expect: {"success":true,"token":"<64 hex>"}
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8099/terminal
# expect: 303
curl -s http://127.0.0.1:8099/ | head -5
# expect: login page HTML
kill %1
```

- [ ] **Step 3: Run the full quality gate**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --check`
Expected: clean. Fix any clippy/fmt findings before committing.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat(server): main entrypoint with graceful shutdown and pid file"
```

---

## Task 11: CI workflow + push

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the workflow**

`.github/workflows/ci.yml`:
```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: sudo apt-get update && sudo apt-get install -y tmux
      - run: cargo fmt --check
      - run: cargo clippy --workspace -- -D warnings
      - run: cargo test --workspace
```

(tmux is unused in M1 but required from M2 on; installing now keeps the workflow stable.)

- [ ] **Step 2: Commit and push**

```bash
git add -A && git commit -m "ci: fmt + clippy + test workflow"
git push origin main
```

- [ ] **Step 3: Verify CI is green**

Check https://github.com/shafqat-a/terminal-hub/actions (or `gh run watch --repo shafqat-a/terminal-hub` from a machine with `gh`).
Expected: workflow passes.

---

## Done — M1 exit criteria

- `cargo test --workspace` green; clippy clean; fmt clean; CI green on GitHub.
- Manual smoke (Task 10 Step 2) reproduces Go wire behavior for health/login/redirect/login-page.
- M2 plan (tmux core: session CRUD, interactive WS with repaint-on-attach, terminal UI port) gets written next, after M1 review.

## Known deviations from Go (accepted)

- Unauthenticated browser routes redirect with `303 See Other` (axum `Redirect::to`) instead of Go's `302 Found`. Browsers treat both identically for GET. If exact parity is later required, build the response manually with `StatusCode::FOUND`.
- Session tokens are persisted (SQLite, hashed) instead of Go's in-memory store — intentional spec upgrade so logins survive restarts.
