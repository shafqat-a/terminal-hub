//! SQLite-backed persistence. Single connection guarded by a Mutex — M3 traffic
//! is small enough that a pool isn't worth the dependency.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_initial", include_str!("migrations/0001_initial.sql")),
    ("0002_permissions", include_str!("migrations/0002_permissions.sql")),
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
        let store = Self {
            inner: Arc::new(Mutex::new(conn)),
        };
        store.run_migrations_blocking()?;
        Ok(store)
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self {
            inner: Arc::new(Mutex::new(conn)),
        };
        store.run_migrations_blocking()?;
        Ok(store)
    }

    fn run_migrations_blocking(&self) -> anyhow::Result<()> {
        let g = self
            .inner
            .try_lock()
            .expect("fresh store, no contention");
        g.execute(
            "CREATE TABLE IF NOT EXISTS _migrations (
                 name TEXT PRIMARY KEY,
                 applied_at INTEGER NOT NULL
             )",
            [],
        )?;
        for (name, sql) in MIGRATIONS {
            let applied: Option<i64> = g
                .query_row(
                    "SELECT applied_at FROM _migrations WHERE name = ?1",
                    params![name],
                    |r| r.get(0),
                )
                .optional()?;
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

    pub async fn upsert_user(
        &self,
        email: &str,
        pubkey_openssh: &str,
        role: &str,
    ) -> anyhow::Result<()> {
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
        let row = g
            .query_row(
                "SELECT email, pubkey_openssh, passkey_creds, role, enrolled_at
                 FROM users WHERE email = ?1",
                params![email],
                |r| {
                    Ok(UserRow {
                        email: r.get(0)?,
                        pubkey_openssh: r.get(1)?,
                        passkey_creds: r.get(2)?,
                        role: r.get(3)?,
                        enrolled_at: r.get(4)?,
                    })
                },
            )
            .optional()?;
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

    pub async fn insert_bootstrap_token(
        &self,
        hash: &[u8],
        email: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        let now = now_secs();
        g.execute(
            "INSERT INTO bootstrap_tokens(token_hash, user_email, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![hash, email, now, now + ttl_secs],
        )?;
        Ok(())
    }

    pub async fn list_bootstrap_tokens_for(
        &self,
        email: &str,
    ) -> anyhow::Result<Vec<BootstrapTokenRow>> {
        let g = self.inner.lock().await;
        let mut stmt = g.prepare(
            "SELECT token_hash, user_email, issued_at, expires_at, consumed_at
             FROM bootstrap_tokens WHERE user_email = ?1 AND consumed_at IS NULL
             AND expires_at > ?2",
        )?;
        let rows = stmt
            .query_map(params![email, now_secs()], |r| {
                Ok(BootstrapTokenRow {
                    token_hash: r.get(0)?,
                    user_email: r.get(1)?,
                    issued_at: r.get(2)?,
                    expires_at: r.get(3)?,
                    consumed_at: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn list_bootstrap_tokens_for_all_users(
        &self,
    ) -> anyhow::Result<Vec<BootstrapTokenRow>> {
        let g = self.inner.lock().await;
        let mut stmt = g.prepare(
            "SELECT token_hash, user_email, issued_at, expires_at, consumed_at
             FROM bootstrap_tokens WHERE consumed_at IS NULL AND expires_at > ?1",
        )?;
        let rows = stmt
            .query_map(params![now_secs()], |r| {
                Ok(BootstrapTokenRow {
                    token_hash: r.get(0)?,
                    user_email: r.get(1)?,
                    issued_at: r.get(2)?,
                    expires_at: r.get(3)?,
                    consumed_at: r.get(4)?,
                })
            })?
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

    pub async fn insert_session(
        &self,
        hash: &[u8],
        email: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
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
        let row = g
            .query_row(
                "SELECT cookie_hash, user_email, issued_at, expires_at FROM sessions
                 WHERE cookie_hash = ?1 AND expires_at > ?2",
                params![hash, now_secs()],
                |r| {
                    Ok(SessionRow {
                        cookie_hash: r.get(0)?,
                        user_email: r.get(1)?,
                        issued_at: r.get(2)?,
                        expires_at: r.get(3)?,
                    })
                },
            )
            .optional()?;
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
        g.execute(
            "DELETE FROM sessions WHERE cookie_hash = ?1",
            params![hash],
        )?;
        Ok(())
    }

    // ---------- audit ----------

    pub async fn audit(
        &self,
        user_email: Option<&str>,
        action: &str,
        details_json: Option<&str>,
    ) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "INSERT INTO audit_log(ts, user_email, action, details) VALUES (?1, ?2, ?3, ?4)",
            params![now_secs(), user_email, action, details_json],
        )?;
        Ok(())
    }

    /// M4: write a full audit row including peer/session context.
    pub async fn audit_full(
        &self,
        user_email: Option<&str>,
        action: &str,
        peer_id: Option<&str>,
        session_id: Option<&str>,
        details_json: Option<&str>,
    ) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "INSERT INTO audit_log(ts, user_email, action, peer_id, session_id, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![now_secs(), user_email, action, peer_id, session_id, details_json],
        )?;
        Ok(())
    }

    // ---------- M4 permissions ----------

    pub async fn get_permission_caps(
        &self,
        user_email: &str,
        peer_id: &str,
        session_id: &str,
    ) -> anyhow::Result<Option<u32>> {
        let g = self.inner.lock().await;
        let row = g
            .query_row(
                "SELECT capabilities FROM permissions
                 WHERE user_email = ?1 AND peer_id = ?2 AND session_id = ?3",
                params![user_email, peer_id, session_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        Ok(row.map(|v| v as u32))
    }

    pub async fn list_visible_session_ids(
        &self,
        user_email: &str,
        peer_id: &str,
    ) -> anyhow::Result<Vec<String>> {
        let g = self.inner.lock().await;
        let mut stmt = g.prepare(
            "SELECT session_id FROM permissions
             WHERE user_email = ?1 AND peer_id = ?2 AND (capabilities & 1) != 0",
        )?;
        let rows = stmt
            .query_map(params![user_email, peer_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn upsert_permission(
        &self,
        user_email: &str,
        peer_id: &str,
        session_id: &str,
        capabilities: u32,
        granted_by: &str,
    ) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "INSERT INTO permissions(user_email, peer_id, session_id, capabilities, granted_by, granted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user_email, peer_id, session_id)
             DO UPDATE SET capabilities = excluded.capabilities,
                           granted_by   = excluded.granted_by,
                           granted_at   = excluded.granted_at",
            params![user_email, peer_id, session_id, capabilities as i64, granted_by, now_secs()],
        )?;
        Ok(())
    }

    pub async fn delete_permission(
        &self,
        user_email: &str,
        peer_id: &str,
        session_id: &str,
    ) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "DELETE FROM permissions WHERE user_email = ?1 AND peer_id = ?2 AND session_id = ?3",
            params![user_email, peer_id, session_id],
        )?;
        Ok(())
    }

    pub async fn delete_permissions_for_session(
        &self,
        peer_id: &str,
        session_id: &str,
    ) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "DELETE FROM permissions WHERE peer_id = ?1 AND session_id = ?2",
            params![peer_id, session_id],
        )?;
        Ok(())
    }

    pub async fn list_grants_for_session(
        &self,
        peer_id: &str,
        session_id: &str,
    ) -> anyhow::Result<Vec<(String, u32, String, i64)>> {
        let g = self.inner.lock().await;
        let mut stmt = g.prepare(
            "SELECT user_email, capabilities, granted_by, granted_at
             FROM permissions
             WHERE peer_id = ?1 AND session_id = ?2
             ORDER BY user_email",
        )?;
        let rows = stmt
            .query_map(params![peer_id, session_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u32,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn peer_create_allowed(
        &self,
        user_email: &str,
        peer_id: &str,
    ) -> anyhow::Result<bool> {
        let g = self.inner.lock().await;
        let n: i64 = g.query_row(
            "SELECT COUNT(*) FROM peer_create_allowed WHERE user_email = ?1 AND peer_id = ?2",
            params![user_email, peer_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    pub async fn set_peer_create_allowed(
        &self,
        user_email: &str,
        peer_id: &str,
        allowed: bool,
        granted_by: &str,
    ) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        if allowed {
            g.execute(
                "INSERT INTO peer_create_allowed(user_email, peer_id, granted_by, granted_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(user_email, peer_id) DO NOTHING",
                params![user_email, peer_id, granted_by, now_secs()],
            )?;
        } else {
            g.execute(
                "DELETE FROM peer_create_allowed WHERE user_email = ?1 AND peer_id = ?2",
                params![user_email, peer_id],
            )?;
        }
        Ok(())
    }

    // ---------- M4 users ----------

    pub async fn primary_email(&self) -> anyhow::Result<Option<String>> {
        let g = self.inner.lock().await;
        let row = g
            .query_row(
                "SELECT email FROM users WHERE role = 'primary' LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(row)
    }

    pub async fn list_users(&self) -> anyhow::Result<Vec<(String, String, i64, bool)>> {
        let g = self.inner.lock().await;
        let mut stmt = g.prepare(
            "SELECT email, role, enrolled_at, passkey_creds IS NOT NULL FROM users ORDER BY email",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)? != 0,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn insert_secondary_user(
        &self,
        email: &str,
        pubkey_openssh: &str,
    ) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "INSERT INTO users(email, pubkey_openssh, role, enrolled_at)
             VALUES (?1, ?2, 'secondary', ?3)",
            params![email, pubkey_openssh, now_secs()],
        )?;
        Ok(())
    }

    pub async fn delete_user(&self, email: &str) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        // FK ON DELETE CASCADE on permissions/peer_create_allowed/sessions/
        // bootstrap_tokens carries everything else with it.
        g.execute("DELETE FROM users WHERE email = ?1", params![email])?;
        Ok(())
    }

    pub async fn delete_sessions_for_user(&self, email: &str) -> anyhow::Result<()> {
        let g = self.inner.lock().await;
        g.execute(
            "DELETE FROM sessions WHERE user_email = ?1",
            params![email],
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
        s.upsert_user("you@example.com", "ssh-ed25519 AAAA...", "primary")
            .await
            .unwrap();
        let u = s.get_user("you@example.com").await.unwrap().unwrap();
        assert_eq!(u.role, "primary");
        assert!(u.passkey_creds.is_none());
        s.set_passkey_creds("you@example.com", b"{}").await.unwrap();
        assert_eq!(
            s.get_user("you@example.com")
                .await
                .unwrap()
                .unwrap()
                .passkey_creds
                .unwrap(),
            b"{}"
        );
    }

    #[tokio::test]
    async fn bootstrap_token_consume_once() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary").await.unwrap();
        s.insert_bootstrap_token(b"hash1", "a@b", 300).await.unwrap();
        assert!(s.consume_bootstrap_token(b"hash1").await.unwrap());
        assert!(
            !s.consume_bootstrap_token(b"hash1").await.unwrap(),
            "second consume must fail"
        );
    }

    #[tokio::test]
    async fn expired_session_not_found() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary").await.unwrap();
        s.insert_session(b"cookieX", "a@b", -1).await.unwrap();
        assert!(s.lookup_session(b"cookieX").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_bootstrap_tokens_for_user() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary").await.unwrap();
        s.insert_bootstrap_token(b"hash1", "a@b", 300).await.unwrap();
        let rows = s.list_bootstrap_tokens_for("a@b").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user_email, "a@b");
    }
}
