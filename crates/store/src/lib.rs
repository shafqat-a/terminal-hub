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

#[derive(Debug)]
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
            .query_row("SELECT token_hash FROM auth_sessions LIMIT 1", [], |r| {
                r.get(0)
            })
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

    #[test]
    fn re_adding_token_updates_expiry() {
        let (store, _d) = open_temp();
        store.add_auth_session("tok-abc", 1000).unwrap();
        store.add_auth_session("tok-abc", 5000).unwrap();
        // New expiry wins: still valid past the original expiry.
        assert!(store.validate_auth_session("tok-abc", 2000).unwrap());
    }
}
