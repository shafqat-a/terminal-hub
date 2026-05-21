# M4 — Multi-User + Per-Session Permissions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Important:** Refresh this plan after M3 ships. Concrete struct names (`AuthUser`, `Db`, `audit::log`) and the exact extractor signatures for the cookie middleware need to be reconciled with whatever M3 actually landed before code is written.

**Goal:** Add secondary users with per-session ACLs to the single-user instance built in M3. Primary keeps full access; secondaries see and act only on sessions the primary has explicitly granted, with capability granularity (`attach` / `write` / `manage`). A small "share" modal on each session and a `/admin/users.html` panel make grants and user management drivable from the browser. Federation is out-of-scope; everything in M4 is local (`peer_id = "local"`).

**Architecture:** New `permissions` module wrapping the `permissions` and `peer_create_allowed` SQLite tables plus a `Capabilities` bitmask newtype. A `require_primary` axum extractor and an `effective_caps(db, email, peer_id, session_id) -> Capabilities` helper feed every existing handler in `api.rs` and `attach.rs`. The session manager's `create` path auto-grants the creating secondary and the primary; the kill path cascade-deletes permission rows. `terminal-hub-cli` gains `add-user` / `remove-user` subcommands that hit the DB directly (they run on the server). Audit log writes are best-effort and never fail the request.

**Tech Stack:** Same as M3 — rusqlite (bundled), axum 0.7, tokio, tracing, serde/serde_json, clap (for CLI). No new crates.

**Spec reference:** `docs/superpowers/specs/2026-05-21-terminal-hub-design.md` §6.1 (roles), §7 (permission model — schema, enforcement, grant UI), §13 (threat model rows for secondaries).

---

## Task 1: Migration `0002_permissions.sql`

**Files:**
- Create: `crates/server/migrations/0002_permissions.sql`
- Modify: `crates/server/src/db.rs` (M3 module — add migration to the apply list)
- Create: `crates/server/tests/migrations.rs`

- [ ] **Step 1: Write the migration SQL**

Create `crates/server/migrations/0002_permissions.sql`:

```sql
-- M4: per-session ACLs for secondary users. All rows scoped to a (user, peer, session)
-- tuple; peer_id is the literal 'local' for sessions on this instance. Federation
-- (other peer_id values) lands in M5.

CREATE TABLE IF NOT EXISTS permissions (
  user_email   TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  peer_id      TEXT NOT NULL,
  session_id   TEXT NOT NULL,
  capabilities INTEGER NOT NULL,              -- bitmask: 1=attach, 2=write, 4=manage
  granted_by   TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  granted_at   INTEGER NOT NULL,
  PRIMARY KEY (user_email, peer_id, session_id)
);

CREATE INDEX IF NOT EXISTS idx_permissions_session
  ON permissions(peer_id, session_id);

CREATE INDEX IF NOT EXISTS idx_permissions_user
  ON permissions(user_email);

CREATE TABLE IF NOT EXISTS peer_create_allowed (
  user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  peer_id    TEXT NOT NULL,
  granted_by TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (user_email, peer_id)
);
```

Note: `users` and `audit_log` are created by M3's `0001_initial.sql`. `permissions.user_email` references `users(email)`; the M3 migration must declare `users.email` as a `TEXT PRIMARY KEY` (spec §7.1) for this to apply cleanly. If M3 shipped without `ON DELETE CASCADE` support, run `PRAGMA foreign_keys = ON` at connection open — confirm in `db.rs` after reading what M3 produced.

- [ ] **Step 2: Wire the migration into the apply list**

In `crates/server/src/db.rs` (M3 module), the migration loader should already iterate over a `&[(&str, &str)]` slice of `(filename, sql)` pairs read via `include_str!`. Append the new file:

```rust
const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_initial.sql", include_str!("../migrations/0001_initial.sql")),
    ("0002_permissions.sql", include_str!("../migrations/0002_permissions.sql")),
];
```

If M3 used a different loader shape, adapt — the contract is "applied in lexicographic order, recorded in `schema_migrations`."

- [ ] **Step 3: Migration test**

Create `crates/server/tests/migrations.rs`:

```rust
use terminal_hub_server::db::Db;

#[test]
fn migrations_create_permissions_tables() {
    let db = Db::open_in_memory().expect("open");
    let conn = db.conn();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(names.iter().any(|n| n == "permissions"), "tables: {names:?}");
    assert!(names.iter().any(|n| n == "peer_create_allowed"), "tables: {names:?}");
    assert!(names.iter().any(|n| n == "users"), "M3 tables still present: {names:?}");
}

#[test]
fn permissions_pk_rejects_duplicate_tuple() {
    let db = Db::open_in_memory().unwrap();
    let conn = db.conn();
    conn.execute(
        "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES (?1, x'00', 'primary', 0)",
        ["a@x"],
    ).unwrap();
    conn.execute(
        "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES (?1, x'00', 'secondary', 0)",
        ["b@x"],
    ).unwrap();
    conn.execute(
        "INSERT INTO permissions(user_email, peer_id, session_id, capabilities, granted_by, granted_at)
         VALUES ('b@x', 'local', 's1', 1, 'a@x', 0)", [],
    ).unwrap();
    let err = conn.execute(
        "INSERT INTO permissions(user_email, peer_id, session_id, capabilities, granted_by, granted_at)
         VALUES ('b@x', 'local', 's1', 7, 'a@x', 0)", [],
    );
    assert!(err.is_err(), "duplicate (user, peer, session) must violate PK");
}
```

Run: `cargo test -p terminal-hub-server --test migrations`
Expected: 2 pass.

- [ ] **Step 4: Commit**

```bash
git add crates/server/migrations/0002_permissions.sql crates/server/src/db.rs crates/server/tests/migrations.rs
git commit -m "feat(db): 0002_permissions.sql — permissions and peer_create_allowed tables"
```

---

## Task 2: `Capabilities` newtype + `permissions` module

**Files:**
- Create: `crates/server/src/permissions.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: The Capabilities newtype**

Create `crates/server/src/permissions.rs`:

```rust
//! Per-session ACL helpers. Wraps the `permissions` and `peer_create_allowed` tables.
//!
//! Capabilities are a bitmask: 1=attach, 2=write, 4=manage. Primary users bypass
//! all checks; secondaries are filtered through `permissions` rows.

use crate::db::Db;
use crate::session_id::SessionId;
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub const NONE: Capabilities = Capabilities(0);
    pub const ATTACH: Capabilities = Capabilities(1);
    pub const WRITE: Capabilities = Capabilities(2);
    pub const MANAGE: Capabilities = Capabilities(4);

    /// Auto-grant for sessions a user owns (created themselves) and for the primary.
    pub const fn all_for_owner() -> Capabilities {
        Capabilities(1 | 2 | 4)
    }

    pub fn has(self, cap: Capabilities) -> bool {
        (self.0 & cap.0) == cap.0
    }

    pub fn union(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 | other.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Primary,
    Secondary,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("unknown user: {0}")]
    UnknownUser(String),
}

pub fn lookup_role(db: &Db, email: &str) -> Result<Role, Error> {
    let row: Option<String> = db
        .conn()
        .query_row(
            "SELECT role FROM users WHERE email = ?1",
            params![email],
            |r| r.get(0),
        )
        .ok();
    match row.as_deref() {
        Some("primary") => Ok(Role::Primary),
        Some("secondary") => Ok(Role::Secondary),
        Some(other) => Err(Error::Db(rusqlite::Error::InvalidColumnType(
            0,
            other.into(),
            rusqlite::types::Type::Text,
        ))),
        None => Err(Error::UnknownUser(email.into())),
    }
}

/// Effective capabilities for a (user, peer, session). Primary always returns
/// `all_for_owner()`; secondary returns whatever the `permissions` row says, or
/// `NONE` if no row exists.
pub fn effective_caps(
    db: &Db,
    email: &str,
    peer_id: &str,
    session_id: &SessionId,
) -> Result<Capabilities, Error> {
    if lookup_role(db, email)? == Role::Primary {
        return Ok(Capabilities::all_for_owner());
    }
    let caps: Option<u32> = db
        .conn()
        .query_row(
            "SELECT capabilities FROM permissions
             WHERE user_email = ?1 AND peer_id = ?2 AND session_id = ?3",
            params![email, peer_id, session_id.to_string()],
            |r| r.get(0),
        )
        .ok();
    Ok(Capabilities(caps.unwrap_or(0)))
}

/// Sessions a user can see in `list`. Primary returns `None` (= "all"); secondary
/// returns `Some(Vec<SessionId>)` filtered to rows where caps & ATTACH != 0.
pub fn visible_sessions(
    db: &Db,
    email: &str,
    peer_id: &str,
) -> Result<Option<Vec<SessionId>>, Error> {
    if lookup_role(db, email)? == Role::Primary {
        return Ok(None);
    }
    let mut stmt = db.conn().prepare(
        "SELECT session_id FROM permissions
         WHERE user_email = ?1 AND peer_id = ?2 AND (capabilities & 1) != 0",
    )?;
    let ids: Vec<SessionId> = stmt
        .query_map(params![email, peer_id], |r| r.get::<_, String>(0))?
        .filter_map(Result::ok)
        .filter_map(|s| uuid::Uuid::parse_str(&s).ok().map(SessionId))
        .collect();
    Ok(Some(ids))
}

pub fn peer_create_allowed(db: &Db, email: &str, peer_id: &str) -> Result<bool, Error> {
    if lookup_role(db, email)? == Role::Primary {
        return Ok(true);
    }
    let n: i64 = db.conn().query_row(
        "SELECT COUNT(*) FROM peer_create_allowed WHERE user_email = ?1 AND peer_id = ?2",
        params![email, peer_id],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

pub fn grant(
    db: &Db,
    user_email: &str,
    peer_id: &str,
    session_id: &SessionId,
    caps: Capabilities,
    granted_by: &str,
) -> Result<(), Error> {
    db.conn().execute(
        "INSERT INTO permissions(user_email, peer_id, session_id, capabilities, granted_by, granted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(user_email, peer_id, session_id)
         DO UPDATE SET capabilities = excluded.capabilities,
                       granted_by = excluded.granted_by,
                       granted_at = excluded.granted_at",
        params![
            user_email,
            peer_id,
            session_id.to_string(),
            caps.0,
            granted_by,
            now_secs()
        ],
    )?;
    Ok(())
}

pub fn revoke(
    db: &Db,
    user_email: &str,
    peer_id: &str,
    session_id: &SessionId,
) -> Result<(), Error> {
    db.conn().execute(
        "DELETE FROM permissions WHERE user_email = ?1 AND peer_id = ?2 AND session_id = ?3",
        params![user_email, peer_id, session_id.to_string()],
    )?;
    Ok(())
}

/// On `kill`, cascade-delete every permission row for that session.
pub fn cascade_session_delete(db: &Db, peer_id: &str, session_id: &SessionId) -> Result<(), Error> {
    db.conn().execute(
        "DELETE FROM permissions WHERE peer_id = ?1 AND session_id = ?2",
        params![peer_id, session_id.to_string()],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantRow {
    pub user_email: String,
    pub capabilities: Capabilities,
    pub granted_by: String,
    pub granted_at: i64,
}

pub fn list_grants(
    db: &Db,
    peer_id: &str,
    session_id: &SessionId,
) -> Result<Vec<GrantRow>, Error> {
    let mut stmt = db.conn().prepare(
        "SELECT user_email, capabilities, granted_by, granted_at
         FROM permissions WHERE peer_id = ?1 AND session_id = ?2
         ORDER BY user_email",
    )?;
    let rows = stmt
        .query_map(params![peer_id, session_id.to_string()], |r| {
            Ok(GrantRow {
                user_email: r.get(0)?,
                capabilities: Capabilities(r.get::<_, u32>(1)?),
                granted_by: r.get(2)?,
                granted_at: r.get(3)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

pub fn set_peer_create_allowed(
    db: &Db,
    user_email: &str,
    peer_id: &str,
    allowed: bool,
    granted_by: &str,
) -> Result<(), Error> {
    if allowed {
        db.conn().execute(
            "INSERT INTO peer_create_allowed(user_email, peer_id, granted_by, granted_at)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            params![user_email, peer_id, granted_by, now_secs()],
        )?;
    } else {
        db.conn().execute(
            "DELETE FROM peer_create_allowed WHERE user_email = ?1 AND peer_id = ?2",
            params![user_email, peer_id],
        )?;
    }
    Ok(())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(db: &Db) {
        db.conn().execute(
            "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('p@x', x'00', 'primary', 0)",
            [],
        ).unwrap();
        db.conn().execute(
            "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('s@x', x'00', 'secondary', 0)",
            [],
        ).unwrap();
    }

    #[test]
    fn capabilities_bitmask() {
        let all = Capabilities::all_for_owner();
        assert!(all.has(Capabilities::ATTACH));
        assert!(all.has(Capabilities::WRITE));
        assert!(all.has(Capabilities::MANAGE));
        assert_eq!(all.0, 7);
        let aw = Capabilities::ATTACH.union(Capabilities::WRITE);
        assert!(aw.has(Capabilities::ATTACH));
        assert!(!aw.has(Capabilities::MANAGE));
    }

    #[test]
    fn primary_bypasses_acl() {
        let db = Db::open_in_memory().unwrap();
        seed(&db);
        let id = SessionId::new();
        let caps = effective_caps(&db, "p@x", "local", &id).unwrap();
        assert_eq!(caps, Capabilities::all_for_owner());
    }

    #[test]
    fn secondary_starts_at_zero_caps() {
        let db = Db::open_in_memory().unwrap();
        seed(&db);
        let id = SessionId::new();
        let caps = effective_caps(&db, "s@x", "local", &id).unwrap();
        assert_eq!(caps, Capabilities::NONE);
    }

    #[test]
    fn grant_then_revoke() {
        let db = Db::open_in_memory().unwrap();
        seed(&db);
        let id = SessionId::new();
        grant(&db, "s@x", "local", &id, Capabilities::all_for_owner(), "p@x").unwrap();
        assert_eq!(
            effective_caps(&db, "s@x", "local", &id).unwrap(),
            Capabilities::all_for_owner()
        );
        let visible = visible_sessions(&db, "s@x", "local").unwrap().unwrap();
        assert_eq!(visible, vec![id.clone()]);
        revoke(&db, "s@x", "local", &id).unwrap();
        assert_eq!(effective_caps(&db, "s@x", "local", &id).unwrap(), Capabilities::NONE);
    }

    #[test]
    fn grant_upserts_on_conflict() {
        let db = Db::open_in_memory().unwrap();
        seed(&db);
        let id = SessionId::new();
        grant(&db, "s@x", "local", &id, Capabilities::ATTACH, "p@x").unwrap();
        grant(&db, "s@x", "local", &id,
              Capabilities::ATTACH.union(Capabilities::WRITE), "p@x").unwrap();
        assert_eq!(effective_caps(&db, "s@x", "local", &id).unwrap().0, 3);
    }

    #[test]
    fn peer_create_default_false_for_secondary() {
        let db = Db::open_in_memory().unwrap();
        seed(&db);
        assert!(!peer_create_allowed(&db, "s@x", "local").unwrap());
        set_peer_create_allowed(&db, "s@x", "local", true, "p@x").unwrap();
        assert!(peer_create_allowed(&db, "s@x", "local").unwrap());
        set_peer_create_allowed(&db, "s@x", "local", false, "p@x").unwrap();
        assert!(!peer_create_allowed(&db, "s@x", "local").unwrap());
    }
}
```

Add `pub mod permissions;` to `crates/server/src/lib.rs`.

- [ ] **Step 2: Run unit tests**

Run: `cargo test -p terminal-hub-server permissions`
Expected: 6 tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/server/src/permissions.rs crates/server/src/lib.rs
git commit -m "feat(permissions): Capabilities newtype + grant/revoke/effective_caps helpers"
```

---

## Task 3: `require_primary` extractor + audit-log helper

**Files:**
- Modify: `crates/server/src/auth/cookie.rs` (M3 module — add extractor)
- Create: `crates/server/src/audit.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: `RequirePrimary` extractor**

The M3 plan exposes `AuthUser { email: String }` via a tower middleware that puts it in request extensions. Layer a second extractor on top:

In `crates/server/src/auth/cookie.rs`, append:

```rust
use crate::permissions::{lookup_role, Role};
use crate::AppState;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;

pub struct RequirePrimary(pub String);

#[axum::async_trait]
impl FromRequestParts<AppState> for RequirePrimary {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser { email } = AuthUser::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "not authenticated"))?;
        match lookup_role(&state.db, &email) {
            Ok(Role::Primary) => Ok(RequirePrimary(email)),
            Ok(Role::Secondary) => Err((StatusCode::FORBIDDEN, "primary only")),
            Err(_) => Err((StatusCode::UNAUTHORIZED, "unknown user")),
        }
    }
}
```

If M3's `AuthUser` extractor signature differs (e.g. it takes a different state shape), adjust the bounds — but keep the rejection types intact so handlers can `?` them.

- [ ] **Step 2: Best-effort audit log**

Create `crates/server/src/audit.rs`:

```rust
//! Audit log writes. Best-effort by design — never fail the request on a write error,
//! just log it and continue. The spec promises the log is *written*, not consulted;
//! a viewer ships post-MVP.

use crate::db::Db;
use rusqlite::params;
use serde_json::Value;

pub fn log(
    db: &Db,
    user_email: &str,
    action: &str,
    peer_id: Option<&str>,
    session_id: Option<&str>,
    details: Option<Value>,
) {
    let detail_str = details.as_ref().map(|v| v.to_string());
    let res = db.conn().execute(
        "INSERT INTO audit_log(ts, user_email, action, peer_id, session_id, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![now_secs(), user_email, action, peer_id, session_id, detail_str],
    );
    if let Err(e) = res {
        tracing::warn!(?e, %action, %user_email, "audit log write failed");
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
```

Add `pub mod audit;` to `crates/server/src/lib.rs`.

- [ ] **Step 3: Smoke test for the extractor**

Add to `crates/server/src/auth/cookie.rs` test module (or create one):

```rust
#[cfg(test)]
mod m4_tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn lookup_role_resolves_known_users() {
        let db = Db::open_in_memory().unwrap();
        db.conn().execute(
            "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('a@x', x'00', 'primary', 0)",
            [],
        ).unwrap();
        assert_eq!(crate::permissions::lookup_role(&db, "a@x").unwrap(),
                   crate::permissions::Role::Primary);
    }
}
```

Run: `cargo test -p terminal-hub-server`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/auth/cookie.rs crates/server/src/audit.rs crates/server/src/lib.rs
git commit -m "feat(auth): RequirePrimary extractor + best-effort audit::log helper"
```

---

## Task 4: Enforce ACLs in `api.rs` + `attach.rs`

**Files:**
- Modify: `crates/server/src/api.rs`
- Modify: `crates/server/src/attach.rs`
- Modify: `crates/server/src/sessions.rs`

- [ ] **Step 1: Filter `list`, gate `create`, require `manage` for `rename`/`kill`**

Replace the body of `crates/server/src/api.rs` (keeping its existing imports + `CreateBody`/`RenameBody` definitions):

```rust
use crate::audit;
use crate::auth::cookie::AuthUser;
use crate::permissions::{
    self, effective_caps, peer_create_allowed, visible_sessions, Capabilities,
};
use crate::session_id::SessionId;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::collections::HashSet;

const LOCAL: &str = "local";

#[derive(Deserialize)]
pub struct CreateBody {
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct RenameBody {
    pub display_name: String,
}

pub async fn list(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let all = s.mgr.list().await.map_err(e500)?;
    let filtered = match visible_sessions(&s.db, &email, LOCAL).map_err(perm500)? {
        None => all, // primary
        Some(ids) => {
            let allowed: HashSet<SessionId> = ids.into_iter().collect();
            all.into_iter().filter(|si| allowed.contains(&si.id)).collect()
        }
    };
    Ok(Json(serde_json::json!({ "sessions": filtered })))
}

pub async fn create(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
    Json(b): Json<CreateBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !peer_create_allowed(&s.db, &email, LOCAL).map_err(perm500)? {
        return Err((StatusCode::FORBIDDEN, "create not allowed on this peer".into()));
    }
    let info = s.mgr.create(&b.display_name, &email).await.map_err(e500)?;

    // Auto-grant the creator and (if creator is secondary) the primary.
    permissions::grant(
        &s.db,
        &email,
        LOCAL,
        &info.id,
        Capabilities::all_for_owner(),
        &email,
    ).map_err(perm500)?;
    if let Some(primary) = s.primary_email().map_err(perm500)? {
        if primary != email {
            permissions::grant(
                &s.db,
                &primary,
                LOCAL,
                &info.id,
                Capabilities::all_for_owner(),
                &email,
            ).map_err(perm500)?;
        }
    }

    audit::log(
        &s.db,
        &email,
        "create",
        Some(LOCAL),
        Some(&info.id.to_string()),
        Some(serde_json::json!({ "display_name": b.display_name })),
    );
    Ok(Json(serde_json::json!({ "session": info })))
}

pub async fn rename(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<RenameBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = parse_id(&id)?;
    require_cap(&s, &email, &id, Capabilities::MANAGE)?;
    s.mgr.rename(&id, &b.display_name).await.map_err(e500)?;
    audit::log(
        &s.db,
        &email,
        "rename",
        Some(LOCAL),
        Some(&id.to_string()),
        Some(serde_json::json!({ "display_name": b.display_name })),
    );
    Ok(StatusCode::NO_CONTENT)
}

pub async fn kill(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = parse_id(&id)?;
    require_cap(&s, &email, &id, Capabilities::MANAGE)?;
    s.mgr.kill(&id).await.map_err(e500)?;
    permissions::cascade_session_delete(&s.db, LOCAL, &id).map_err(perm500)?;
    audit::log(
        &s.db,
        &email,
        "kill",
        Some(LOCAL),
        Some(&id.to_string()),
        None,
    );
    Ok(StatusCode::NO_CONTENT)
}

fn require_cap(
    s: &AppState,
    email: &str,
    id: &SessionId,
    cap: Capabilities,
) -> Result<(), (StatusCode, String)> {
    let caps = effective_caps(&s.db, email, LOCAL, id).map_err(perm500)?;
    if caps.has(cap) {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, format!("missing capability {:?}", cap)))
    }
}

fn parse_id(s: &str) -> Result<SessionId, (StatusCode, String)> {
    uuid::Uuid::parse_str(s)
        .map(SessionId)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

fn e500(e: crate::sessions::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn perm500(e: crate::permissions::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
```

- [ ] **Step 2: Add `primary_email` helper to `AppState`**

In `crates/server/src/lib.rs`, give `AppState` a small accessor (the primary email is needed in the create handler and in admin paths):

```rust
impl AppState {
    /// Return the primary user's email, if one has been bootstrapped.
    pub fn primary_email(&self) -> Result<Option<String>, crate::permissions::Error> {
        let row: Option<String> = self
            .db
            .conn()
            .query_row(
                "SELECT email FROM users WHERE role = 'primary' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();
        Ok(row)
    }
}
```

- [ ] **Step 3: Gate `/ws/attach/:id` on `ATTACH` + silently drop input without `WRITE`**

Update `crates/server/src/attach.rs`. The existing handler shape (from M2) takes `Path` + `State` + `WebSocketUpgrade`; add the `AuthUser` extractor and an attach check before upgrading, then plumb a "write allowed" bool into the per-socket loop:

```rust
use crate::auth::cookie::AuthUser;
use crate::permissions::{effective_caps, Capabilities};
use crate::session_id::SessionId;
use crate::{audit, AppState};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tokio::sync::broadcast;

const LOCAL: &str = "local";

pub async fn ws_attach(
    AuthUser { email }: AuthUser,
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = match uuid::Uuid::parse_str(&id_str) {
        Ok(u) => SessionId(u),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let caps = match effective_caps(&state.db, &email, LOCAL, &id) {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if !caps.has(Capabilities::ATTACH) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let writable = caps.has(Capabilities::WRITE);
    audit::log(
        &state.db,
        &email,
        "attach",
        Some(LOCAL),
        Some(&id.to_string()),
        Some(serde_json::json!({ "writable": writable })),
    );
    ws.on_upgrade(move |socket| handle(socket, state, id, writable))
}

async fn handle(mut socket: WebSocket, state: AppState, id: SessionId, writable: bool) {
    let (mut rx, tx_in) = match state.hub.subscribe(&id).await {
        Ok(p) => p,
        Err(e) => {
            let _ = socket.send(Message::Text(format!("attach error: {e}"))).await;
            return;
        }
    };
    if let Ok(scroll) = state.hub.capture_scrollback(&id, 5000).await {
        if !scroll.is_empty() {
            let _ = socket.send(Message::Binary(scroll)).await;
        }
    }
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Ok(b) => { if socket.send(Message::Binary(b)).await.is_err() { return; } }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            },
            m = socket.recv() => {
                let Some(Ok(m)) = m else { return; };
                let text = match m {
                    Message::Text(t) => t,
                    Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    Message::Close(_) => return,
                    _ => continue,
                };
                // Spec §7.2: secondaries without WRITE can attach (observe) but their
                // input is silently dropped. No error frame — keeps the read-only UX clean.
                if !writable { continue; }
                if tx_in.send(text).await.is_err() { return; }
            }
        }
    }
}

pub fn unescape_octal(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let o = &b[i + 1..i + 4];
            if o.iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push((o[0] - b'0') * 64 + (o[1] - b'0') * 8 + (o[2] - b'0'));
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}
```

- [ ] **Step 4: Sessions module — owner email comes from `email`, not `"local"`**

In `crates/server/src/sessions.rs`, the `create` call in M2 took `owner: &str` and hardcoded "local" at the API layer. Keep the signature; the API now passes the authenticated `email`. No code change is required if `Manager::create(&display_name, &email)` already worked; if M3 changed it, reconcile.

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/api.rs crates/server/src/attach.rs crates/server/src/lib.rs
git commit -m "feat(api): enforce per-session ACLs in list/create/rename/kill/attach"
```

---

## Task 5: User-management endpoints + CLI subcommands

**Files:**
- Create: `crates/server/src/users.rs`
- Modify: `crates/server/src/lib.rs`
- Modify: `crates/cli/Cargo.toml`
- Modify: `crates/cli/src/main.rs`
- Create: `crates/server/tests/users.rs`

- [ ] **Step 1: User DAL**

Create `crates/server/src/users.rs`:

```rust
use crate::db::Db;
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct UserRow {
    pub email: String,
    pub role: String,
    pub enrolled_at: i64,
    pub passkey_registered: bool,
}

#[derive(Debug, Deserialize)]
pub struct AddUserBody {
    pub email: String,
    /// SSH pubkey in OpenSSH single-line format ("ssh-ed25519 AAAA… comment").
    pub pubkey: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("primary user not bootstrapped — run `terminal-hub bootstrap` first")]
    NoPrimary,
    #[error("user already exists: {0}")]
    AlreadyExists(String),
    #[error("cannot remove the primary user via this endpoint")]
    RemovingPrimary,
}

pub fn list(db: &Db) -> Result<Vec<UserRow>, Error> {
    let mut stmt = db.conn().prepare(
        "SELECT email, role, enrolled_at, passkey_creds IS NOT NULL FROM users ORDER BY email",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(UserRow {
                email: r.get(0)?,
                role: r.get(1)?,
                enrolled_at: r.get(2)?,
                passkey_registered: r.get::<_, i64>(3)? != 0,
            })
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

/// Add a secondary user. Requires a primary to already exist.
pub fn add_secondary(db: &Db, email: &str, pubkey: &str) -> Result<UserRow, Error> {
    // Confirm primary exists.
    let primary: Option<String> = db
        .conn()
        .query_row(
            "SELECT email FROM users WHERE role = 'primary' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok();
    if primary.is_none() {
        return Err(Error::NoPrimary);
    }
    let exists: i64 = db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM users WHERE email = ?1",
            params![email],
            |r| r.get(0),
        )?;
    if exists > 0 {
        return Err(Error::AlreadyExists(email.into()));
    }
    let now = now_secs();
    db.conn().execute(
        "INSERT INTO users(email, pubkey, passkey_creds, role, enrolled_at)
         VALUES (?1, ?2, NULL, 'secondary', ?3)",
        params![email, pubkey.as_bytes(), now],
    )?;
    Ok(UserRow {
        email: email.into(),
        role: "secondary".into(),
        enrolled_at: now,
        passkey_registered: false,
    })
}

/// Remove a user and all their grants + session cookies. Refuses to remove the primary.
pub fn remove(db: &Db, email: &str) -> Result<(), Error> {
    let role: Option<String> = db
        .conn()
        .query_row(
            "SELECT role FROM users WHERE email = ?1",
            params![email],
            |r| r.get(0),
        )
        .ok();
    if role.as_deref() == Some("primary") {
        return Err(Error::RemovingPrimary);
    }
    // Cascade via foreign keys handles permissions + peer_create_allowed. Explicitly
    // delete sessions cookies (the M3 `sessions_cookies` table, if it exists; this is
    // a no-op if the FK isn't present yet).
    let _ = db.conn().execute(
        "DELETE FROM sessions_cookies WHERE user_email = ?1",
        params![email],
    );
    db.conn().execute("DELETE FROM users WHERE email = ?1", params![email])?;
    Ok(())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
```

Add `pub mod users;` to `crates/server/src/lib.rs`.

- [ ] **Step 2: HTTP handlers for `/api/users` and permission endpoints**

Append to `crates/server/src/api.rs`:

```rust
use crate::auth::cookie::RequirePrimary;
use crate::permissions::{
    list_grants, set_peer_create_allowed, revoke as perm_revoke, GrantRow,
};
use crate::users;

pub async fn users_list(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let role = crate::permissions::lookup_role(&s.db, &email).map_err(perm500)?;
    let all = users::list(&s.db).map_err(users500)?;
    let filtered: Vec<_> = match role {
        crate::permissions::Role::Primary => all,
        crate::permissions::Role::Secondary => {
            all.into_iter().filter(|u| u.email == email).collect()
        }
    };
    Ok(Json(serde_json::json!({ "users": filtered })))
}

pub async fn users_add(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Json(body): Json<users::AddUserBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let row = users::add_secondary(&s.db, &body.email, &body.pubkey).map_err(users500)?;
    audit::log(
        &s.db,
        &actor,
        "add-user",
        None,
        None,
        Some(serde_json::json!({ "added": body.email })),
    );
    Ok(Json(serde_json::json!({ "user": row })))
}

pub async fn users_remove(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Path(email): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    users::remove(&s.db, &email).map_err(users500)?;
    audit::log(
        &s.db,
        &actor,
        "remove-user",
        None,
        None,
        Some(serde_json::json!({ "removed": email })),
    );
    Ok(StatusCode::NO_CONTENT)
}

pub async fn perm_list(
    RequirePrimary(_): RequirePrimary,
    State(s): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let id = parse_id(&session_id)?;
    let grants: Vec<GrantRow> = list_grants(&s.db, LOCAL, &id).map_err(perm500)?;
    Ok(Json(serde_json::json!({ "grants": grants })))
}

#[derive(Deserialize)]
pub struct GrantBody {
    pub user_email: String,
    pub capabilities: u32,
}

pub async fn perm_grant(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Path(session_id): Path<String>,
    Json(body): Json<GrantBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = parse_id(&session_id)?;
    crate::permissions::grant(
        &s.db,
        &body.user_email,
        LOCAL,
        &id,
        Capabilities(body.capabilities),
        &actor,
    ).map_err(perm500)?;
    audit::log(
        &s.db,
        &actor,
        "grant",
        Some(LOCAL),
        Some(&id.to_string()),
        Some(serde_json::json!({
            "user_email": body.user_email,
            "capabilities": body.capabilities,
        })),
    );
    Ok(StatusCode::NO_CONTENT)
}

pub async fn perm_revoke_handler(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Path((session_id, user_email)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = parse_id(&session_id)?;
    perm_revoke(&s.db, &user_email, LOCAL, &id).map_err(perm500)?;
    audit::log(
        &s.db,
        &actor,
        "revoke",
        Some(LOCAL),
        Some(&id.to_string()),
        Some(serde_json::json!({ "user_email": user_email })),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PeerCreateBody {
    pub user_email: String,
    pub peer_id: String,
    pub allowed: bool,
}

pub async fn peer_create_toggle(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Json(body): Json<PeerCreateBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    if body.peer_id != "local" {
        // M4 is local-only; federation in M5.
        return Err((StatusCode::BAD_REQUEST, "only peer_id=local supported in M4".into()));
    }
    set_peer_create_allowed(&s.db, &body.user_email, &body.peer_id, body.allowed, &actor)
        .map_err(perm500)?;
    audit::log(
        &s.db,
        &actor,
        "peer-create-toggle",
        Some(&body.peer_id),
        None,
        Some(serde_json::json!({ "user_email": body.user_email, "allowed": body.allowed })),
    );
    Ok(StatusCode::NO_CONTENT)
}

fn users500(e: users::Error) -> (StatusCode, String) {
    let code = match &e {
        users::Error::AlreadyExists(_) => StatusCode::CONFLICT,
        users::Error::NoPrimary => StatusCode::PRECONDITION_FAILED,
        users::Error::RemovingPrimary => StatusCode::FORBIDDEN,
        users::Error::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, e.to_string())
}
```

- [ ] **Step 3: Wire routes**

In `crates/server/src/lib.rs` `router_with`, add:

```rust
        .route("/api/users", get(api::users_list).post(api::users_add))
        .route("/api/users/:email", axum::routing::delete(api::users_remove))
        .route("/api/permissions/session/:session_id",
               get(api::perm_list).post(api::perm_grant))
        .route("/api/permissions/session/:session_id/:user_email",
               axum::routing::delete(api::perm_revoke_handler))
        .route("/api/permissions/peer-create",
               axum::routing::post(api::peer_create_toggle))
```

- [ ] **Step 4: CLI subcommands**

Update `crates/cli/Cargo.toml`:

```toml
[dependencies]
anyhow = { workspace = true }
clap = { version = "4", features = ["derive"] }
terminal-hub-server = { path = "../server" }
```

Replace `crates/cli/src/main.rs`:

```rust
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use terminal_hub_server::{db::Db, users};

#[derive(Parser)]
#[command(name = "terminal-hub-cli", version)]
struct Cli {
    /// Path to the state.db file. Defaults to the platform config dir.
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Add a secondary user. Requires the primary to already be bootstrapped.
    AddUser {
        #[arg(long)]
        email: String,
        /// Path to the user's SSH public key file (.pub).
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Remove a user and cascade-delete their grants + active cookies.
    RemoveUser {
        #[arg(long)]
        email: String,
    },
    /// List all users in the local DB.
    ListUsers,
}

fn open_db(path: Option<PathBuf>) -> Result<Db> {
    let p = match path {
        Some(p) => p,
        None => terminal_hub_server::config::default_db_path()
            .context("resolving default db path")?,
    };
    Db::open(&p).with_context(|| format!("opening {}", p.display()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db = open_db(cli.db)?;
    match cli.cmd {
        Cmd::AddUser { email, pubkey } => {
            let bytes = std::fs::read_to_string(&pubkey)
                .with_context(|| format!("reading {}", pubkey.display()))?;
            let trimmed = bytes.trim();
            if !(trimmed.starts_with("ssh-") || trimmed.starts_with("ecdsa-")) {
                bail!("not an OpenSSH public key (expected `ssh-…` prefix): {}", pubkey.display());
            }
            let row = users::add_secondary(&db, &email, trimmed)?;
            println!("added secondary: {} (enrolled_at={})", row.email, row.enrolled_at);
            println!("next: have the user run `terminal-hub enroll --email {}` from their laptop", row.email);
        }
        Cmd::RemoveUser { email } => {
            users::remove(&db, &email)?;
            println!("removed: {email}");
        }
        Cmd::ListUsers => {
            let rows = users::list(&db)?;
            for r in rows {
                println!(
                    "{:8} {} (passkey: {})",
                    r.role,
                    r.email,
                    if r.passkey_registered { "yes" } else { "no" }
                );
            }
        }
    }
    Ok(())
}
```

`config::default_db_path()` is the M3 helper that resolves the platform config dir; if M3 named it differently, adjust. The CLI deliberately re-uses the server crate's `users::` and `db::` modules so the DB schema lives in exactly one place.

- [ ] **Step 5: Integration test for users + grants**

Create `crates/server/tests/users.rs`:

```rust
use std::net::SocketAddr;
use std::process::Command;
use tokio::net::TcpListener;

const SOCKET: &str = "terminal-hub-test-m4-users";
const BOOT: &str = "_boot";

fn ensure_tmux() {
    let _ = Command::new("tmux")
        .args(["-L", SOCKET, "new-session", "-d", "-s", BOOT])
        .status();
}
fn kill_tmux() {
    let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status();
}

async fn spawn() -> (SocketAddr, terminal_hub_server::AppState) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: SOCKET.into(),
        tmux_session: BOOT.into(),
        ..Default::default()
    };
    let (app, state) = terminal_hub_server::router_with_state(cfg).await.unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
    (addr, state)
}

#[tokio::test(flavor = "multi_thread")]
async fn primary_can_add_and_remove_secondary() {
    ensure_tmux();
    let (_addr, state) = spawn().await;
    state.db.conn().execute(
        "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('p@x', x'00', 'primary', 0)",
        [],
    ).unwrap();
    let row = terminal_hub_server::users::add_secondary(&state.db, "s@x", "ssh-ed25519 AAAA fake").unwrap();
    assert_eq!(row.role, "secondary");
    terminal_hub_server::users::remove(&state.db, "s@x").unwrap();
    let n: i64 = state.db.conn().query_row(
        "SELECT COUNT(*) FROM users WHERE email='s@x'", [], |r| r.get(0),
    ).unwrap();
    assert_eq!(n, 0);
    kill_tmux();
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_remove_primary() {
    let (_, state) = spawn().await;
    state.db.conn().execute(
        "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('p@x', x'00', 'primary', 0)",
        [],
    ).unwrap();
    assert!(terminal_hub_server::users::remove(&state.db, "p@x").is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn add_secondary_requires_primary() {
    let (_, state) = spawn().await;
    let err = terminal_hub_server::users::add_secondary(&state.db, "s@x", "ssh-ed25519 AAAA fake");
    assert!(matches!(err, Err(terminal_hub_server::users::Error::NoPrimary)));
}
```

Note the test uses a hypothetical `router_with_state` that returns both the `Router` and `AppState`; if M3's `router_with` only returns a `Router`, expose a `state()` helper or split the constructor. The integration tests need direct DB access to seed users without going through the HTTP auth ceremony.

- [ ] **Step 6: Run**

Run: `cargo test -p terminal-hub-server --test users -- --nocapture`
Expected: 3 pass.

Run: `cargo test --workspace`
Expected: all M1–M4 tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/server/src/users.rs crates/server/src/api.rs crates/server/src/lib.rs crates/cli/ crates/server/tests/users.rs
git commit -m "feat(users): add/remove user endpoints + CLI + ACL-gated permission routes"
```

---

## Task 6: End-to-end ACL test (secondary sees only granted sessions)

**Files:**
- Create: `crates/server/tests/acl.rs`

- [ ] **Step 1: Test the full enforcement matrix**

Create `crates/server/tests/acl.rs`:

```rust
//! End-to-end: secondaries see only granted sessions; rename/kill require manage;
//! attach without ATTACH is rejected; WebSocket input is dropped silently without WRITE.

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const SOCKET: &str = "terminal-hub-test-m4-acl";
const BOOT: &str = "_boot";

fn ensure() { let _ = Command::new("tmux").args(["-L", SOCKET, "new-session", "-d", "-s", BOOT]).status(); }
fn kill_t() { let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status(); }

async fn spawn() -> (SocketAddr, terminal_hub_server::AppState) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: SOCKET.into(),
        tmux_session: BOOT.into(),
        ..Default::default()
    };
    let (app, state) = terminal_hub_server::router_with_state(cfg).await.unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
    (addr, state)
}

/// M3 will provide a test helper that mints a cookie for a given email without
/// going through the WebAuthn ceremony. Reuse it here; if it doesn't exist yet,
/// add `pub fn test_cookie(state: &AppState, email: &str) -> String` to the
/// `auth::cookie` module behind `#[cfg(any(test, feature = "test-cookies"))]`.
fn test_cookie(state: &terminal_hub_server::AppState, email: &str) -> String {
    terminal_hub_server::auth::cookie::test_cookie(state, email)
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_only_sees_granted_sessions() {
    ensure();
    let (addr, state) = spawn().await;
    state.db.conn().execute(
        "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('p@x', x'00', 'primary', 0)", [],
    ).unwrap();
    state.db.conn().execute(
        "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('s@x', x'00', 'secondary', 0)", [],
    ).unwrap();
    let c = reqwest::Client::builder().cookie_store(false).build().unwrap();
    let p_cookie = test_cookie(&state, "p@x");
    let s_cookie = test_cookie(&state, "s@x");

    // Primary creates two sessions.
    let a: serde_json::Value = c.post(format!("http://{addr}/api/sessions"))
        .header("Cookie", &p_cookie)
        .json(&serde_json::json!({ "display_name": "alpha" }))
        .send().await.unwrap().json().await.unwrap();
    let b: serde_json::Value = c.post(format!("http://{addr}/api/sessions"))
        .header("Cookie", &p_cookie)
        .json(&serde_json::json!({ "display_name": "beta" }))
        .send().await.unwrap().json().await.unwrap();
    let id_a = a["session"]["id"].as_str().unwrap().to_string();
    let id_b = b["session"]["id"].as_str().unwrap().to_string();

    // Grant the secondary attach-only on alpha.
    let st = c.post(format!("http://{addr}/api/permissions/session/{id_a}"))
        .header("Cookie", &p_cookie)
        .json(&serde_json::json!({ "user_email": "s@x", "capabilities": 1u32 }))
        .send().await.unwrap().status();
    assert_eq!(st, 204);

    // Secondary lists → only alpha.
    let listed: serde_json::Value = c.get(format!("http://{addr}/api/sessions"))
        .header("Cookie", &s_cookie)
        .send().await.unwrap().json().await.unwrap();
    let ids: Vec<&str> = listed["sessions"].as_array().unwrap().iter()
        .map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec![id_a.as_str()]);

    // Secondary cannot rename or kill (no MANAGE).
    let rn = c.patch(format!("http://{addr}/api/sessions/{id_a}"))
        .header("Cookie", &s_cookie)
        .json(&serde_json::json!({ "display_name": "owned" }))
        .send().await.unwrap().status();
    assert_eq!(rn, 403);
    let rm = c.delete(format!("http://{addr}/api/sessions/{id_a}"))
        .header("Cookie", &s_cookie)
        .send().await.unwrap().status();
    assert_eq!(rm, 403);

    // Secondary cannot attach to beta (no row at all → 403).
    let url_b = format!("ws://{addr}/ws/attach/{id_b}");
    let req = http::Request::builder().uri(&url_b).header("Cookie", &s_cookie)
        .body(()).unwrap();
    let res = tokio_tungstenite::connect_async(req).await;
    assert!(res.is_err(), "secondary must not connect to ungranted session");

    // Secondary CAN attach to alpha, but their typed input is silently dropped (no WRITE).
    let url_a = format!("ws://{addr}/ws/attach/{id_a}");
    let req = http::Request::builder().uri(&url_a).header("Cookie", &s_cookie)
        .body(()).unwrap();
    let (mut ws_s, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    ws_s.send(Message::Text("echo SHOULD-NOT-APPEAR\r".into())).await.unwrap();
    // Give it a moment; no marker should appear in the pane.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Primary attaches and confirms the marker is absent.
    let req = http::Request::builder().uri(&url_a).header("Cookie", &p_cookie)
        .body(()).unwrap();
    let (mut ws_p, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let mut saw_marker = false;
    let dl = tokio::time::Instant::now() + Duration::from_millis(500);
    while tokio::time::Instant::now() < dl {
        if let Ok(Some(Ok(Message::Binary(by)))) =
            tokio::time::timeout(Duration::from_millis(100), ws_p.next()).await
        {
            if std::str::from_utf8(&by).map(|s| s.contains("SHOULD-NOT-APPEAR")).unwrap_or(false) {
                saw_marker = true;
            }
        }
    }
    assert!(!saw_marker, "secondary input must be dropped silently when WRITE is missing");

    kill_t();
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_create_requires_peer_create_allowed() {
    ensure();
    let (addr, state) = spawn().await;
    state.db.conn().execute(
        "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('p@x', x'00', 'primary', 0)", [],
    ).unwrap();
    state.db.conn().execute(
        "INSERT INTO users(email, pubkey, role, enrolled_at) VALUES ('s@x', x'00', 'secondary', 0)", [],
    ).unwrap();
    let c = reqwest::Client::builder().cookie_store(false).build().unwrap();
    let s_cookie = test_cookie(&state, "s@x");

    let st = c.post(format!("http://{addr}/api/sessions"))
        .header("Cookie", &s_cookie)
        .json(&serde_json::json!({ "display_name": "nope" }))
        .send().await.unwrap().status();
    assert_eq!(st, 403, "create denied without peer_create_allowed");

    // Primary toggles the flag.
    let p_cookie = test_cookie(&state, "p@x");
    let st = c.post(format!("http://{addr}/api/permissions/peer-create"))
        .header("Cookie", &p_cookie)
        .json(&serde_json::json!({ "user_email": "s@x", "peer_id": "local", "allowed": true }))
        .send().await.unwrap().status();
    assert_eq!(st, 204);

    let st = c.post(format!("http://{addr}/api/sessions"))
        .header("Cookie", &s_cookie)
        .json(&serde_json::json!({ "display_name": "yes" }))
        .send().await.unwrap().status();
    assert_eq!(st, 200, "create allowed once peer_create_allowed is set");
    kill_t();
}
```

This test depends on M3 exposing `test_cookie` (or an equivalent test seam) and `router_with_state`. If they don't exist, add them now — they pay for themselves immediately in every milestone after this.

- [ ] **Step 2: Run**

Run: `cargo test -p terminal-hub-server --test acl -- --nocapture`
Expected: both tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/server/tests/acl.rs
git commit -m "test(acl): end-to-end secondary user permission enforcement"
```

---

## Task 7: Grant modal in the sidebar

This is HTML/JS; skipping TDD here in favour of a manual smoke check at the end of the task. The handlers it calls are already covered by Task 6.

**Files:**
- Modify: `crates/server/static/app.css`
- Modify: `crates/server/static/app.js`

- [ ] **Step 1: Modal styles**

Append to `crates/server/static/app.css`:

```css
.share-btn { background: transparent; border: 0; color: #888; cursor: pointer; margin-right: 6px; }
.share-btn:hover { color: #6cf; }

.modal-backdrop {
  position: fixed; inset: 0; background: rgba(0,0,0,0.6);
  display: flex; align-items: center; justify-content: center; z-index: 50;
}
.modal {
  background: #1c1c1c; color: #ddd; border: 1px solid #333;
  border-radius: 6px; padding: 16px 20px; width: 380px; max-width: 90vw;
  font-size: 13px;
}
.modal h2 { margin: 0 0 12px 0; font-size: 14px; }
.modal table { width: 100%; border-collapse: collapse; }
.modal th, .modal td { text-align: left; padding: 4px 6px; }
.modal th { color: #888; font-weight: 400; font-size: 11px; text-transform: uppercase; }
.modal tr + tr td { border-top: 1px solid #2a2a2a; }
.modal .actions { margin-top: 12px; display: flex; gap: 8px; justify-content: flex-end; }
.modal button { background: #2a2a2a; color: #ddd; border: 0; padding: 6px 12px; cursor: pointer; }
.modal button.primary { background: #2d6cdf; color: #fff; }
.modal button:hover { background: #353535; }
.modal button.primary:hover { background: #3a7ae8; }
```

- [ ] **Step 2: Modal logic**

Append to `crates/server/static/app.js`:

```js
// ---- Share / grants UI ---------------------------------------------------

const CAP = { ATTACH: 1, WRITE: 2, MANAGE: 4 };

async function openShareModal(session) {
  const [grantsRes, usersRes] = await Promise.all([
    fetch(`/api/permissions/session/${session.id}`),
    fetch(`/api/users`),
  ]);
  if (!grantsRes.ok || !usersRes.ok) {
    alert("Failed to load grants (are you the primary?)");
    return;
  }
  const { grants } = await grantsRes.json();
  const { users } = await usersRes.json();
  const grantsByEmail = new Map(grants.map((g) => [g.user_email, g.capabilities]));

  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.innerHTML = `
    <div class="modal" role="dialog" aria-labelledby="share-title">
      <h2 id="share-title">Share "${escapeHtml(session.display_name)}"</h2>
      <table>
        <thead>
          <tr><th>User</th><th>Attach</th><th>Write</th><th>Manage</th></tr>
        </thead>
        <tbody></tbody>
      </table>
      <div class="actions">
        <button data-act="cancel">Close</button>
        <button class="primary" data-act="save">Save</button>
      </div>
    </div>`;
  const tbody = backdrop.querySelector("tbody");
  for (const u of users) {
    if (u.role === "primary") continue; // primary always has full access; not editable
    const caps = grantsByEmail.get(u.email) ?? 0;
    const tr = document.createElement("tr");
    tr.dataset.email = u.email;
    tr.innerHTML = `
      <td>${escapeHtml(u.email)}</td>
      <td><input type="checkbox" data-cap="1" ${caps & 1 ? "checked" : ""}></td>
      <td><input type="checkbox" data-cap="2" ${caps & 2 ? "checked" : ""}></td>
      <td><input type="checkbox" data-cap="4" ${caps & 4 ? "checked" : ""}></td>`;
    tbody.append(tr);
  }
  backdrop.querySelector("[data-act=cancel]").addEventListener("click", () => backdrop.remove());
  backdrop.querySelector("[data-act=save]").addEventListener("click", async () => {
    for (const tr of tbody.querySelectorAll("tr")) {
      const email = tr.dataset.email;
      let mask = 0;
      for (const cb of tr.querySelectorAll("input[data-cap]")) {
        if (cb.checked) mask |= Number(cb.dataset.cap);
      }
      const prior = grantsByEmail.get(email) ?? 0;
      if (mask === prior) continue;
      if (mask === 0) {
        await fetch(`/api/permissions/session/${session.id}/${encodeURIComponent(email)}`,
                    { method: "DELETE" });
      } else {
        await fetch(`/api/permissions/session/${session.id}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_email: email, capabilities: mask }),
        });
      }
    }
    backdrop.remove();
  });
  backdrop.addEventListener("click", (ev) => { if (ev.target === backdrop) backdrop.remove(); });
  document.body.append(backdrop);
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}
```

- [ ] **Step 3: Add the share button to each sidebar row**

Modify the inner loop of `refreshSessions()` in `app.js` so each `<li>` gets a share button between the label and the kill button:

```js
    const share = document.createElement("button");
    share.className = "share-btn";
    share.textContent = "⤴";
    share.title = "share session";
    share.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      await openShareModal(s);
    });
    li.append(label, share, kill);
```

The share button is rendered for everyone; the modal-open call hits `/api/permissions/...` which is `RequirePrimary`-gated, so a secondary clicking it gets the `alert("Failed to load grants…")` fallback. (Hiding the button for secondaries is a polish item; tracked in the M4 done-criteria as "primary smoke test only.")

- [ ] **Step 4: Manual smoke**

1. Start the server, log in as primary, create two sessions.
2. Run on the same host: `terminal-hub-cli add-user --email s@x --pubkey ~/.ssh/id_ed25519.pub`.
3. Enroll `s@x` via the M3 CLI flow.
4. As primary, click ⤴ on session "alpha", check "Attach" + "Write" for `s@x`, Save.
5. Open an incognito window, log in as `s@x`. Sidebar should show only "alpha". Type into it and see output.
6. Uncheck "Write" in the modal as primary; reload `s@x`'s tab. Typing should produce no output.

- [ ] **Step 5: Commit**

```bash
git add crates/server/static/app.css crates/server/static/app.js
git commit -m "feat(frontend): per-session share modal with capability checkboxes"
```

---

## Task 8: `/admin/users.html` user-management panel

Static HTML page that calls the existing JSON API. Primary-only by virtue of the API being `RequirePrimary`-gated.

**Files:**
- Create: `crates/server/static/admin/users.html`
- Create: `crates/server/static/admin/users.js`
- Modify: `crates/server/src/lib.rs` (only if the existing `ServeDir` fallback doesn't already cover `/admin/...`)

- [ ] **Step 1: HTML**

Create `crates/server/static/admin/users.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>terminal-hub — admin / users</title>
    <link rel="stylesheet" href="/app.css">
    <style>
      body { display: block; padding: 24px; max-width: 720px; margin: 0 auto; }
      h1 { font-size: 16px; text-transform: uppercase; letter-spacing: 0.08em; color: #888; }
      table { width: 100%; border-collapse: collapse; margin-top: 16px; }
      th, td { padding: 8px; text-align: left; border-bottom: 1px solid #2a2a2a; }
      th { color: #888; font-weight: 400; font-size: 11px; text-transform: uppercase; }
      form { margin-top: 24px; display: grid; gap: 8px; grid-template-columns: 1fr 1fr auto; }
      input, textarea { background: #181818; color: #ddd; border: 1px solid #2a2a2a;
        padding: 6px 8px; font-family: inherit; font-size: 13px; }
      textarea { grid-column: 1 / -1; min-height: 60px; font-family: Menlo, monospace; }
      button { background: #2d6cdf; color: #fff; border: 0; padding: 6px 14px; cursor: pointer; }
      button.danger { background: transparent; color: #f55; }
      .err { color: #f55; margin-top: 12px; }
    </style>
  </head>
  <body>
    <p><a href="/" style="color:#6cf">&larr; back to sessions</a></p>
    <h1>Users</h1>
    <table>
      <thead><tr><th>Email</th><th>Role</th><th>Passkey</th><th></th></tr></thead>
      <tbody id="user-rows"></tbody>
    </table>
    <h1 style="margin-top:32px">Add secondary</h1>
    <form id="add-form">
      <input id="add-email" type="email" placeholder="alice@example.com" required>
      <span></span>
      <button type="submit">Add</button>
      <textarea id="add-pubkey" placeholder="ssh-ed25519 AAAA… comment" required></textarea>
    </form>
    <p id="err" class="err"></p>
    <script src="/admin/users.js" type="module"></script>
  </body>
</html>
```

- [ ] **Step 2: JS**

Create `crates/server/static/admin/users.js`:

```js
const errEl = document.getElementById("err");

function showError(msg) { errEl.textContent = msg || ""; }
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

async function refresh() {
  showError("");
  const r = await fetch("/api/users");
  if (r.status === 401) { window.location = "/login"; return; }
  if (r.status === 403) { showError("Primary user only."); return; }
  if (!r.ok) { showError(`Failed: ${r.status}`); return; }
  const { users } = await r.json();
  const tbody = document.getElementById("user-rows");
  tbody.innerHTML = "";
  for (const u of users) {
    const tr = document.createElement("tr");
    const removeBtn = u.role === "primary"
      ? ""
      : `<button class="danger" data-email="${escapeHtml(u.email)}">remove</button>`;
    tr.innerHTML = `
      <td>${escapeHtml(u.email)}</td>
      <td>${u.role}</td>
      <td>${u.passkey_registered ? "yes" : "no"}</td>
      <td>${removeBtn}</td>`;
    tbody.append(tr);
  }
  for (const btn of tbody.querySelectorAll("button.danger")) {
    btn.addEventListener("click", async () => {
      const email = btn.dataset.email;
      if (!confirm(`Remove ${email}? Their grants and cookies will be deleted.`)) return;
      const r = await fetch(`/api/users/${encodeURIComponent(email)}`, { method: "DELETE" });
      if (!r.ok) { showError(`Remove failed: ${r.status}`); return; }
      refresh();
    });
  }
}

document.getElementById("add-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError("");
  const email = document.getElementById("add-email").value.trim();
  const pubkey = document.getElementById("add-pubkey").value.trim();
  if (!pubkey.startsWith("ssh-") && !pubkey.startsWith("ecdsa-")) {
    showError("pubkey must be in OpenSSH single-line format");
    return;
  }
  const r = await fetch("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, pubkey }),
  });
  if (!r.ok) { showError(`Add failed: ${r.status} ${await r.text()}`); return; }
  document.getElementById("add-email").value = "";
  document.getElementById("add-pubkey").value = "";
  refresh();
});

refresh();
```

- [ ] **Step 3: Confirm static serving covers `/admin/`**

The M2 `router_with` ends with `.fallback_service(ServeDir::new(static_dir()))`, which already serves any path under `static/`. `/admin/users.html` should resolve without code changes — verify with `curl -i http://127.0.0.1:5999/admin/users.html` after rebuild. If a route earlier in the chain swallows `/admin/*`, add an explicit `.route("/admin/users.html", get_service(ServeFile::new(…)))`.

- [ ] **Step 4: Manual smoke**

Log in as primary, open `http://127.0.0.1:5999/admin/users.html`. Add a secondary, confirm they appear in the table. Remove them, confirm the row disappears. Open the page as a secondary, confirm "Primary user only." renders.

- [ ] **Step 5: Commit**

```bash
git add crates/server/static/admin/
git commit -m "feat(frontend): /admin/users.html primary-only user management panel"
```

---

## Task 9: Audit-log coverage check + README/CLAUDE.md status update

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- (Optional) Modify: `crates/server/src/auth/cookie.rs` to call `audit::log` for `login`.

- [ ] **Step 1: Confirm login is audited**

Spec §7 lists `login` as a required audit action. The M3 cookie-issuance path (the WebAuthn assertion success handler) must call:

```rust
crate::audit::log(&state.db, &email, "login", None, None, None);
```

If M3 didn't wire this, add it now in a small follow-up commit:

```bash
git add crates/server/src/auth/cookie.rs
git commit -m "feat(audit): log successful logins"
```

The other actions — `attach`, `create`, `kill`, `rename`, `grant`, `revoke`, `add-user`, `remove-user` — were wired in Tasks 4 and 5.

- [ ] **Step 2: README**

Append to `README.md` under a new "M4" section:

```markdown
## M4 — Multi-user

Secondary users with per-session ACLs.

Add a secondary on the server host:

    terminal-hub-cli add-user --email alice@example.com --pubkey ~alice/.ssh/id_ed25519.pub

Then have alice enroll a passkey from her laptop (M3 flow):

    terminal-hub enroll --server https://your-host:5999 --email alice@example.com

The primary user grants per-session access via the "⤴" button on each session in
the sidebar, or via `POST /api/permissions/session/:session_id`. Capabilities
are a bitmask: 1 = attach (read-only), 2 = write, 4 = manage (rename/kill).

By default secondaries cannot create sessions. Toggle this per user with the
peer-create allowlist:

    curl -X POST -H "Content-Type: application/json" --cookie 'sid=...' \
      -d '{"user_email":"alice@example.com","peer_id":"local","allowed":true}' \
      https://your-host:5999/api/permissions/peer-create

The primary's admin panel lives at `/admin/users.html`.
```

- [ ] **Step 3: CLAUDE.md**

Replace the `## Repository status` block:

```markdown
## Repository status

M4 (multi-user + per-session ACLs) complete. Schema gains `permissions` and `peer_create_allowed` tables. Every handler in `api.rs` and `/ws/attach/:id` enforces capabilities for secondaries; primary bypasses. `terminal-hub-cli add-user` / `remove-user` manage secondaries on the server. Grant UI is a modal on each sidebar row; admin panel at `/admin/users.html`. Audit log records login / attach / create / kill / rename / grant / revoke / add-user / remove-user (best-effort writes).

Federation is not yet implemented — `peer_id` is always `"local"` in M4. Next: M5.

Build: `cargo build --workspace`
Test: `cargo test --workspace` (some tests require `tmux` on PATH)
Run: `cargo run -p terminal-hub-server`
```

- [ ] **Step 4: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: README and CLAUDE.md status for M4 completion"
```

---

## Done criteria for M4

- `cargo build --workspace` passes.
- `cargo test --workspace` passes; in particular `tests::acl`, `tests::users`, and `tests::migrations` pass.
- `cargo clippy --workspace -- -D warnings` clean.
- Manual smoke (Task 7 Step 4 + Task 8 Step 4):
  - Primary adds a secondary via `/admin/users.html`.
  - Primary grants `attach|write` on one session via the ⤴ modal.
  - Secondary logs in (incognito window), sees only that session, can type.
  - Primary revokes `write`; secondary's typing is silently ignored on next reload.
  - Primary removes the secondary; their cookies are invalidated immediately.
- `audit_log` table contains rows for every required action after a primary + secondary session of activity.
- `git log --oneline` shows ~9 commits (one per task plus the optional login-audit follow-up).

Out of scope for M4 (handled in later milestones):
- Federation (`peer_id != "local"`, peer instance proxying) — M5.
- Audit log viewer UI — post-MVP.
- Hiding the share button from secondaries (cosmetic) — backlog.
- WebAuthn re-enrollment flow for secondaries who lose their device — covered by the M3 SSH-key recovery factor.

**Next milestone:** M5 — federation (peer keypair, `authorized_peers`, lazy on-demand connections, sidebar groups per peer, cross-peer permission rows). See `docs/superpowers/plans/2026-05-21-m5-federation.md`.
