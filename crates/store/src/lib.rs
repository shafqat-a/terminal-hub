//! rusqlite-backed persistence for ai-dev-conductor.
//! M1: auth sessions only. M2: terminal sessions table.

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

#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Mutex<Connection>,
}

const MIGRATIONS: &str = "
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
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
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    pub fn add_auth_session(&self, token: &str, expires_at: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO auth_sessions (token_hash, expires_at) VALUES (?1, ?2)",
            params![hash_token(token), expires_at],
        )?;
        Ok(())
    }

    /// Returns true when the token exists and has not expired (`now` is unix
    /// seconds). Expired rows are deleted opportunistically.
    pub fn validate_auth_session(&self, token: &str, now: i64) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ?1",
            params![now],
        )?;
        let mut stmt =
            conn.prepare("SELECT 1 FROM auth_sessions WHERE token_hash = ?1 AND expires_at > ?2")?;
        Ok(stmt.exists(params![hash_token(token), now])?)
    }

    /// Insert or replace a terminal session row (status = 'running').
    pub fn upsert_session(&self, id: &str, name: &str, created_at: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, name, created_at, status) VALUES (?1, ?2, ?3, 'running')",
            params![id, name, created_at],
        )?;
        Ok(())
    }

    /// Rename a session. Returns `true` if the row existed, `false` if not found.
    pub fn rename_session(&self, id: &str, name: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let rows = conn.execute(
            "UPDATE sessions SET name = ?1 WHERE id = ?2",
            params![name, id],
        )?;
        Ok(rows > 0)
    }

    /// Delete a session. Returns `true` if the row existed, `false` if not found.
    pub fn delete_session(&self, id: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let rows = conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    /// List all sessions ordered by `created_at` ascending.
    /// Returns tuples of (id, name, created_at, status).
    pub fn list_sessions(&self) -> Result<Vec<(String, String, i64, String)>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt =
            conn.prepare("SELECT id, name, created_at, status FROM sessions ORDER BY created_at")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

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
            .query_row("SELECT token_hash FROM auth_sessions LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_ne!(token, "tok-secret");
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn open_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/conductor.db");
        assert!(Store::open(&nested).is_ok());
    }

    #[test]
    fn re_adding_token_updates_expiry() {
        let (store, _d) = open_temp();
        store.add_auth_session("tok-abc", 1000).unwrap();
        store.add_auth_session("tok-abc", 5000).unwrap();
        assert!(store.validate_auth_session("tok-abc", 2000).unwrap());
    }

    #[test]
    fn upsert_and_list_roundtrip() {
        let (store, _d) = open_temp();
        store
            .upsert_session("aabbccdd", "my-session", 1_000_000)
            .unwrap();
        let list = store.list_sessions().unwrap();
        assert_eq!(list.len(), 1);
        let (id, name, created_at, status) = &list[0];
        assert_eq!(id, "aabbccdd");
        assert_eq!(name, "my-session");
        assert_eq!(*created_at, 1_000_000);
        assert_eq!(status, "running");
    }

    #[test]
    fn rename_session_found() {
        let (store, _d) = open_temp();
        store
            .upsert_session("aabbccdd", "old-name", 1_000_000)
            .unwrap();
        let found = store.rename_session("aabbccdd", "new-name").unwrap();
        assert!(found);
        let list = store.list_sessions().unwrap();
        assert_eq!(list[0].1, "new-name");
    }

    #[test]
    fn rename_session_not_found() {
        let (store, _d) = open_temp();
        let found = store.rename_session("doesnotexist", "x").unwrap();
        assert!(!found);
    }

    #[test]
    fn delete_session_found() {
        let (store, _d) = open_temp();
        store.upsert_session("aabbccdd", "sess", 1_000_000).unwrap();
        let found = store.delete_session("aabbccdd").unwrap();
        assert!(found);
        assert!(store.list_sessions().unwrap().is_empty());
    }

    #[test]
    fn delete_session_not_found() {
        let (store, _d) = open_temp();
        let found = store.delete_session("doesnotexist").unwrap();
        assert!(!found);
    }

    #[test]
    fn migration_idempotent_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conductor.db");
        {
            let store = Store::open(&path).unwrap();
            store.upsert_session("aabbccdd", "sess", 1_000_000).unwrap();
        }
        {
            let store = Store::open(&path).unwrap();
            let list = store.list_sessions().unwrap();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].0, "aabbccdd");
        }
    }

    #[test]
    fn list_sessions_ordered_by_created_at() {
        let (store, _d) = open_temp();
        store
            .upsert_session("bbbbbbbb", "second", 2_000_000)
            .unwrap();
        store
            .upsert_session("aaaaaaaa", "first", 1_000_000)
            .unwrap();
        let list = store.list_sessions().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "aaaaaaaa");
        assert_eq!(list[1].0, "bbbbbbbb");
    }
}
