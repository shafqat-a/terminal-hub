//! rusqlite-backed persistence for ai-dev-conductor.
//! M1: auth sessions only. M2: terminal sessions table. M3: versioned migrations + lifecycle.
//! M4-U1: share_links table (v3 migration) + mint/list/revoke/redeem.

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

/// A fully-typed row returned by get_session / list_sessions.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub status: String,
    pub last_activity_at: i64,
    pub last_client_disconnect_at: i64,
    pub cols: i64,
    pub rows: i64,
}

/// A share link row (token_hash is never exposed).
#[derive(Debug, Clone)]
pub struct ShareRow {
    pub id: String,
    pub session_id: String,
    pub mode: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

/// One chat turn (a question or a reply) bound to a terminal session.
/// Timestamps are unix **milliseconds** so turns order correctly within a
/// second (unlike the seconds-granularity session stamps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRow {
    pub id: i64,
    pub session_id: String,
    /// "user" | "assistant"
    pub role: String,
    pub content: String,
    /// "pending" | "done" | "timeout" | "cancelled" | "interrupted" | "error"
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// For assistant rows: id of the user row this reply answers.
    pub request_id: Option<i64>,
    /// "chat" (asked through the API) | "import" (parsed from the console's
    /// scrollback).
    pub source: String,
}

/// Per-session chat digest for the mobile overview screen.
#[derive(Debug, Clone)]
pub struct ChatSummary {
    pub session_id: String,
    pub count: i64,
    pub pending: bool,
    pub last: ChatRow,
}

#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Mutex<Connection>,
}

// ---- V1 DDL (does NOT include v2 columns, so the ALTER TABLE path is the
//              only way they are added -- keeping both paths schema-identical).
const V1_DDL: &str = "
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
        run_migrations(&conn)?;
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
        // Chat history is meaningless without its console.
        conn.execute(
            "DELETE FROM chat_messages WHERE session_id = ?1",
            params![id],
        )?;
        conn.execute(
            "DELETE FROM chat_clear_marks WHERE session_id = ?1",
            params![id],
        )?;
        Ok(rows > 0)
    }

    // ---- Chat turns (v4) --------------------------------------------------

    /// Insert one chat turn (source "chat"); returns its id.
    pub fn insert_chat_message(
        &self,
        session_id: &str,
        role: &str,
        content: &str,
        status: &str,
        request_id: Option<i64>,
        now_ms: i64,
    ) -> Result<i64, StoreError> {
        self.insert_chat_message_from(
            session_id, role, content, status, request_id, now_ms, "chat",
        )
    }

    /// Insert one chat turn with an explicit `source`; returns its id.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_chat_message_from(
        &self,
        session_id: &str,
        role: &str,
        content: &str,
        status: &str,
        request_id: Option<i64>,
        now_ms: i64,
        source: &str,
    ) -> Result<i64, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, status, created_at, updated_at, request_id, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7)",
            params![session_id, role, content, status, now_ms, request_id, source],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// The `limit` most recent user turns of a session, newest first, with
    /// the reply row (if any) that answers each. Used to align a parsed
    /// console transcript with what is already stored.
    pub fn recent_user_turns(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<(ChatRow, Option<ChatRow>)>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHAT_COLS} FROM chat_messages m
             WHERE session_id = ?1 AND role = 'user' ORDER BY id DESC LIMIT ?2"
        ))?;
        let users: Vec<ChatRow> = stmt
            .query_map(params![session_id, limit as i64], chat_row)?
            .collect::<Result<_, _>>()?;
        let mut reply_stmt = conn.prepare(&format!(
            "SELECT {CHAT_COLS} FROM chat_messages m
             WHERE session_id = ?1 AND role = 'assistant' AND request_id = ?2
             ORDER BY id ASC LIMIT 1"
        ))?;
        let mut out = Vec::with_capacity(users.len());
        for u in users {
            let reply = reply_stmt
                .query_map(params![session_id, u.id], chat_row)?
                .next()
                .transpose()?;
            out.push((u, reply));
        }
        Ok(out)
    }

    /// Overwrite content + status of a turn (used while a reply streams in and
    /// when it settles). Returns `false` when the id does not exist.
    pub fn update_chat_message(
        &self,
        id: i64,
        content: &str,
        status: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let rows = conn.execute(
            "UPDATE chat_messages SET content = ?1, status = ?2, updated_at = ?3 WHERE id = ?4",
            params![content, status, now_ms, id],
        )?;
        Ok(rows > 0)
    }

    pub fn get_chat_message(&self, id: i64) -> Result<Option<ChatRow>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHAT_COLS} FROM chat_messages m WHERE id = ?1"
        ))?;
        let mut rows = stmt.query_map(params![id], chat_row)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Cursor-paginated turns for one session, always returned in ascending
    /// id order.
    ///
    /// * `after = Some(id)` → the `limit` turns newer than `id` (catch-up /
    ///   live tail).
    /// * `before = Some(id)` → the `limit` turns older than `id` (scrolling
    ///   back through history).
    /// * neither → the newest `limit` turns (initial screen).
    ///
    /// The second element reports whether more rows exist beyond the page in
    /// the direction that was walked.
    pub fn list_chat_messages(
        &self,
        session_id: &str,
        after: Option<i64>,
        before: Option<i64>,
        limit: usize,
    ) -> Result<(Vec<ChatRow>, bool), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // Fetch one extra row to learn whether a further page exists.
        let probe = limit as i64 + 1;
        let mut rows: Vec<ChatRow> = match (after, before) {
            (Some(after), _) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {CHAT_COLS} FROM chat_messages m
                     WHERE session_id = ?1 AND id > ?2 ORDER BY id ASC LIMIT ?3"
                ))?;
                let it = stmt.query_map(params![session_id, after, probe], chat_row)?;
                it.collect::<Result<_, _>>()?
            }
            (None, Some(before)) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {CHAT_COLS} FROM chat_messages m
                     WHERE session_id = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3"
                ))?;
                let it = stmt.query_map(params![session_id, before, probe], chat_row)?;
                it.collect::<Result<_, _>>()?
            }
            (None, None) => {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {CHAT_COLS} FROM chat_messages m
                     WHERE session_id = ?1 ORDER BY id DESC LIMIT ?2"
                ))?;
                let it = stmt.query_map(params![session_id, probe], chat_row)?;
                it.collect::<Result<_, _>>()?
            }
        };
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        if after.is_none() {
            // DESC queries: flip back to ascending for the wire.
            rows.reverse();
        }
        Ok((rows, has_more))
    }

    /// Newest turn + count + pending flag for every session that has chat
    /// history. One query, so the overview screen costs a single round-trip.
    pub fn chat_summaries(&self) -> Result<Vec<ChatSummary>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(&format!(
            "SELECT {CHAT_COLS}, agg.n, agg.pending
             FROM chat_messages m
             JOIN (
               SELECT session_id, MAX(id) AS max_id, COUNT(*) AS n,
                      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending
               FROM chat_messages GROUP BY session_id
             ) agg ON agg.max_id = m.id"
        ))?;
        let it = stmt.query_map([], |row| {
            let last = chat_row(row)?;
            let count: i64 = row.get(9)?;
            let pending: i64 = row.get(10)?;
            Ok(ChatSummary {
                session_id: last.session_id.clone(),
                count,
                pending: pending > 0,
                last,
            })
        })?;
        Ok(it.collect::<Result<_, _>>()?)
    }

    /// Remember where the console transcript stood when its chat history was
    /// cleared, so a later scrollback sync does not resurrect the cleared
    /// turns. `anchor` is the text of the last question visible at that time.
    pub fn set_chat_clear_mark(&self, session_id: &str, anchor: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO chat_clear_marks (session_id, anchor) VALUES (?1, ?2)",
            params![session_id, anchor],
        )?;
        Ok(())
    }

    pub fn chat_clear_mark(&self, session_id: &str) -> Result<Option<String>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT anchor FROM chat_clear_marks WHERE session_id = ?1")?;
        let mut rows = stmt.query_map(params![session_id], |r| r.get::<_, String>(0))?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Wipe a session's chat history. Returns the number of turns removed.
    pub fn clear_chat(&self, session_id: &str) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(conn.execute(
            "DELETE FROM chat_messages WHERE session_id = ?1",
            params![session_id],
        )?)
    }

    /// Replies still `pending` when the server starts were orphaned by a
    /// restart: their capture task is gone. Mark them so clients stop waiting.
    pub fn abandon_pending_chat(&self, now_ms: i64) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(conn.execute(
            "UPDATE chat_messages SET status = 'interrupted', updated_at = ?1 WHERE status = 'pending'",
            params![now_ms],
        )?)
    }

    /// Set the status of a session row.
    pub fn set_status(&self, id: &str, status: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE sessions SET status = ?1 WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    /// Update `last_activity_at` for a session.
    pub fn set_activity(&self, id: &str, unix: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE sessions SET last_activity_at = ?1 WHERE id = ?2",
            params![unix, id],
        )?;
        Ok(())
    }

    /// Update `cols` and `rows` for a session.
    pub fn set_size(&self, id: &str, cols: i64, rows: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE sessions SET cols = ?1, rows = ?2 WHERE id = ?3",
            params![cols, rows, id],
        )?;
        Ok(())
    }

    /// Mark every 'running' session as 'detached' (called on startup before re-adoption).
    pub fn mark_all_detached(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE sessions SET status = 'detached' WHERE status = 'running'",
            [],
        )?;
        Ok(())
    }

    /// Fetch a single session row by id.
    pub fn get_session(&self, id: &str) -> Result<Option<SessionRow>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, status, last_activity_at, last_client_disconnect_at, cols, rows \
             FROM sessions WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], map_session_row)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// List all sessions ordered by (created_at, id).
    pub fn list_sessions(&self) -> Result<Vec<SessionRow>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, status, last_activity_at, last_client_disconnect_at, cols, rows \
             FROM sessions ORDER BY created_at, id",
        )?;
        let rows = stmt.query_map([], map_session_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // ---- Share link methods (M4-U1) -----------------------------------------

    /// Insert a new share link. `token_hash` is the raw SHA-256 digest bytes;
    /// only the hash is stored -- the raw token is never persisted.
    pub fn insert_share(
        &self,
        id: &str,
        token_hash: &[u8],
        session_id: &str,
        mode: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO share_links (id, token_hash, session_id, mode, created_at, expires_at, revoked) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            params![id, token_hash, session_id, mode, created_at, expires_at],
        )?;
        Ok(())
    }

    /// List share links for a session, newest first (DESC by created_at).
    pub fn list_shares(&self, session_id: &str) -> Result<Vec<ShareRow>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT id, session_id, mode, created_at, expires_at, revoked \
             FROM share_links WHERE session_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![session_id], map_share_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Revoke a share link by its public id.
    ///
    /// Returns `true` if a row was found and updated, `false` if no row matched.
    ///
    /// Go parity: Go's `RevokeShare` executes `UPDATE share_links SET revoked=1
    /// WHERE id=?` and does NOT inspect rows_affected -- it always returns nil
    /// (HTTP 200 success) even for unknown ids. Our handler mirrors this: it calls
    /// `revoke_share` and always returns 200 regardless of the bool result.
    pub fn revoke_share(&self, id: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let rows = conn.execute(
            "UPDATE share_links SET revoked = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(rows > 0)
    }

    /// Resolve a token hash to `(session_id, mode)` if the link is valid (not
    /// revoked, not expired). `now` is unix seconds.
    pub fn redeem_share(
        &self,
        token_hash: &[u8],
        now: i64,
    ) -> Result<Option<(String, String)>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT session_id, mode FROM share_links \
             WHERE token_hash = ?1 AND revoked = 0 AND expires_at > ?2",
        )?;
        let mut rows = stmt.query_map(params![token_hash, now], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }
}

fn map_session_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        id: row.get(0)?,
        name: row.get(1)?,
        created_at: row.get(2)?,
        status: row.get(3)?,
        last_activity_at: row.get(4)?,
        last_client_disconnect_at: row.get(5)?,
        cols: row.get(6)?,
        rows: row.get(7)?,
    })
}

fn map_share_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShareRow> {
    Ok(ShareRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        mode: row.get(2)?,
        created_at: row.get(3)?,
        expires_at: row.get(4)?,
        revoked: row.get::<_, i64>(5)? != 0,
    })
}

const CHAT_COLS: &str =
    "m.id, m.session_id, m.role, m.content, m.status, m.created_at, m.updated_at, m.request_id, m.source";

fn chat_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatRow> {
    Ok(ChatRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        role: row.get(2)?,
        content: row.get(3)?,
        status: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        request_id: row.get(7)?,
        source: row.get(8)?,
    })
}

// ---- Versioned migration runner ----

fn run_migrations(conn: &Connection) -> Result<(), StoreError> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    if version < 1 {
        conn.execute_batch(&format!(
            "BEGIN;\n{}\nPRAGMA user_version = 1;\nCOMMIT;",
            V1_DDL
        ))?;
    }

    if version < 2 {
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE sessions ADD COLUMN last_activity_at INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE sessions ADD COLUMN last_client_disconnect_at INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE sessions ADD COLUMN cols INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE sessions ADD COLUMN rows INTEGER NOT NULL DEFAULT 0;
             PRAGMA user_version = 2;
             COMMIT;",
        )?;
    }

    if version < 3 {
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS share_links (
               id          TEXT PRIMARY KEY,
               token_hash  BLOB NOT NULL UNIQUE,
               session_id  TEXT NOT NULL,
               mode        TEXT NOT NULL DEFAULT 'read',
               created_at  INTEGER NOT NULL,
               expires_at  INTEGER NOT NULL,
               revoked     INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_share_links_session ON share_links(session_id);
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    }

    if version < 4 {
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS chat_messages (
               id          INTEGER PRIMARY KEY AUTOINCREMENT,
               session_id  TEXT NOT NULL,
               role        TEXT NOT NULL,
               content     TEXT NOT NULL DEFAULT '',
               status      TEXT NOT NULL DEFAULT 'done',
               created_at  INTEGER NOT NULL,
               updated_at  INTEGER NOT NULL,
               request_id  INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON chat_messages(session_id, id);
             PRAGMA user_version = 4;
             COMMIT;",
        )?;
    }

    if version < 5 {
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE chat_messages ADD COLUMN source TEXT NOT NULL DEFAULT 'chat';
             PRAGMA user_version = 5;
             COMMIT;",
        )?;
    }

    if version < 6 {
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS chat_clear_marks (
               session_id TEXT PRIMARY KEY,
               anchor     TEXT NOT NULL
             );
             PRAGMA user_version = 6;
             COMMIT;",
        )?;
    }

    Ok(())
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
        let row = &list[0];
        assert_eq!(row.id, "aabbccdd");
        assert_eq!(row.name, "my-session");
        assert_eq!(row.created_at, 1_000_000);
        assert_eq!(row.status, "running");
        assert_eq!(row.last_activity_at, 0);
        assert_eq!(row.last_client_disconnect_at, 0);
        assert_eq!(row.cols, 0);
        assert_eq!(row.rows, 0);
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
        assert_eq!(list[0].name, "new-name");
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
            assert_eq!(list[0].id, "aabbccdd");
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
        assert_eq!(list[0].id, "aaaaaaaa");
        assert_eq!(list[1].id, "bbbbbbbb");
    }

    #[test]
    fn set_status_updates_row() {
        let (store, _d) = open_temp();
        store.upsert_session("aabbccdd", "sess", 1_000_000).unwrap();
        store.set_status("aabbccdd", "detached").unwrap();
        let row = store.get_session("aabbccdd").unwrap().unwrap();
        assert_eq!(row.status, "detached");
    }

    #[test]
    fn set_activity_updates_row() {
        let (store, _d) = open_temp();
        store.upsert_session("aabbccdd", "sess", 1_000_000).unwrap();
        store.set_activity("aabbccdd", 9_999_999).unwrap();
        let row = store.get_session("aabbccdd").unwrap().unwrap();
        assert_eq!(row.last_activity_at, 9_999_999);
    }

    #[test]
    fn set_size_updates_row() {
        let (store, _d) = open_temp();
        store.upsert_session("aabbccdd", "sess", 1_000_000).unwrap();
        store.set_size("aabbccdd", 120, 40).unwrap();
        let row = store.get_session("aabbccdd").unwrap().unwrap();
        assert_eq!(row.cols, 120);
        assert_eq!(row.rows, 40);
    }

    #[test]
    fn mark_all_detached_changes_running_to_detached() {
        let (store, _d) = open_temp();
        store.upsert_session("aaaaaaaa", "a", 1_000).unwrap();
        store.upsert_session("bbbbbbbb", "b", 2_000).unwrap();
        store.set_status("bbbbbbbb", "dead").unwrap();
        store.mark_all_detached().unwrap();
        let rows = store.list_sessions().unwrap();
        assert_eq!(rows[0].status, "detached");
        assert_eq!(rows[1].status, "dead");
    }

    #[test]
    fn get_session_returns_none_for_unknown() {
        let (store, _d) = open_temp();
        assert!(store.get_session("nope").unwrap().is_none());
    }

    #[test]
    fn v1_to_v2_upgrade_preserves_data_and_adds_columns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conductor.db");

        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(V1_DDL).unwrap();
            conn.execute_batch("PRAGMA user_version = 1").unwrap();
            conn.execute(
                "INSERT INTO sessions (id, name, created_at, status) VALUES ('aa112233', 'legacy', 42, 'running')",
                [],
            )
            .unwrap();
        }

        let store = Store::open(&path).unwrap();

        let row = store.get_session("aa112233").unwrap().unwrap();
        assert_eq!(row.id, "aa112233");
        assert_eq!(row.name, "legacy");
        assert_eq!(row.created_at, 42);
        assert_eq!(row.status, "running");
        assert_eq!(row.last_activity_at, 0);
        assert_eq!(row.last_client_disconnect_at, 0);
        assert_eq!(row.cols, 0);
        assert_eq!(row.rows, 0);

        let ver: i64 = store
            .conn
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ver, 6);
    }

    #[test]
    fn fresh_and_upgraded_schema_are_identical() {
        let dir = tempfile::tempdir().unwrap();

        let fresh_path = dir.path().join("fresh.db");
        let fresh_store = Store::open(&fresh_path).unwrap();
        let fresh_cols = table_info(&fresh_store, "sessions");

        let upgrade_path = dir.path().join("upgrade.db");
        {
            let conn = Connection::open(&upgrade_path).unwrap();
            conn.execute_batch(V1_DDL).unwrap();
            conn.execute_batch("PRAGMA user_version = 1").unwrap();
        }
        let upgrade_store = Store::open(&upgrade_path).unwrap();
        let upgrade_cols = table_info(&upgrade_store, "sessions");

        assert_eq!(
            fresh_cols, upgrade_cols,
            "fresh and upgraded sessions table columns must match"
        );

        let fresh_share_cols = table_info(&fresh_store, "share_links");
        let upgrade_share_cols = table_info(&upgrade_store, "share_links");
        assert_eq!(
            fresh_share_cols, upgrade_share_cols,
            "share_links columns must match between fresh and upgraded DB"
        );
        let col_names: Vec<&str> = fresh_share_cols.iter().map(|(n, _)| n.as_str()).collect();
        assert!(col_names.contains(&"id"), "share_links must have id column");
        assert!(
            col_names.contains(&"token_hash"),
            "share_links must have token_hash column"
        );
        assert!(
            col_names.contains(&"session_id"),
            "share_links must have session_id column"
        );
        assert!(
            col_names.contains(&"revoked"),
            "share_links must have revoked column"
        );
    }

    fn table_info(store: &Store, table: &str) -> Vec<(String, String)> {
        let conn = store.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    // ---- Share link tests (M4-U1) -------------------------------------------

    fn sha256_bytes(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).to_vec()
    }

    #[test]
    fn share_roundtrip() {
        let (store, _d) = open_temp();
        let hash = sha256_bytes(b"rawtoken");
        store
            .insert_share("share001", &hash, "sess001", "read", 1000, 9999)
            .unwrap();
        let result = store.redeem_share(&hash, 1000).unwrap();
        assert_eq!(result, Some(("sess001".to_string(), "read".to_string())));
    }

    #[test]
    fn share_list_desc_order() {
        let (store, _d) = open_temp();
        let h1 = sha256_bytes(b"token1");
        let h2 = sha256_bytes(b"token2");
        store
            .insert_share("share001", &h1, "sess001", "read", 1000, 9999)
            .unwrap();
        store
            .insert_share("share002", &h2, "sess001", "read", 2000, 9999)
            .unwrap();
        let list = store.list_shares("sess001").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, "share002");
        assert_eq!(list[1].id, "share001");
    }

    #[test]
    fn revoke_then_redeem_returns_none() {
        let (store, _d) = open_temp();
        let hash = sha256_bytes(b"rawtoken");
        store
            .insert_share("share001", &hash, "sess001", "read", 1000, 9999)
            .unwrap();
        let found = store.revoke_share("share001").unwrap();
        assert!(found, "revoke must return true for known id");
        let result = store.redeem_share(&hash, 1000).unwrap();
        assert!(result.is_none(), "revoked share must not redeem");
    }

    #[test]
    fn revoke_unknown_id_returns_false() {
        let (store, _d) = open_temp();
        let found = store.revoke_share("nonexistent").unwrap();
        assert!(!found, "revoke of unknown id must return false");
    }

    #[test]
    fn expired_share_not_redeemed() {
        let (store, _d) = open_temp();
        let hash = sha256_bytes(b"rawtoken");
        store
            .insert_share("share001", &hash, "sess001", "read", 1000, 2000)
            .unwrap();
        let result = store.redeem_share(&hash, 2001).unwrap();
        assert!(result.is_none(), "expired share must not redeem");
        // Boundary: expires_at == now is also rejected (strict >, Go parity).
        let at_boundary = store.redeem_share(&hash, 2000).unwrap();
        assert!(
            at_boundary.is_none(),
            "share at exact expiry must not redeem"
        );
    }

    #[test]
    fn wrong_hash_not_redeemed() {
        let (store, _d) = open_temp();
        let hash = sha256_bytes(b"rawtoken");
        store
            .insert_share("share001", &hash, "sess001", "read", 1000, 9999)
            .unwrap();
        let wrong = sha256_bytes(b"wrongtoken");
        let result = store.redeem_share(&wrong, 1000).unwrap();
        assert!(result.is_none(), "wrong hash must not redeem");
    }

    // ---- chat_messages (v4) ------------------------------------------------

    #[test]
    fn chat_insert_update_get_roundtrip() {
        let (store, _d) = open_temp();
        let q = store
            .insert_chat_message("s1", "user", "hello", "done", None, 1000)
            .unwrap();
        let a = store
            .insert_chat_message("s1", "assistant", "", "pending", Some(q), 1001)
            .unwrap();
        assert!(a > q, "ids are monotonic");
        assert!(store
            .update_chat_message(a, "hi there", "done", 1500)
            .unwrap());
        let row = store.get_chat_message(a).unwrap().expect("row");
        assert_eq!(row.role, "assistant");
        assert_eq!(row.content, "hi there");
        assert_eq!(row.status, "done");
        assert_eq!(row.created_at, 1001);
        assert_eq!(row.updated_at, 1500);
        assert_eq!(row.request_id, Some(q));
        assert!(!store.update_chat_message(9999, "", "done", 0).unwrap());
        assert!(store.get_chat_message(9999).unwrap().is_none());
    }

    #[test]
    fn chat_list_pagination_after_before_latest() {
        let (store, _d) = open_temp();
        let ids: Vec<i64> = (0..7)
            .map(|i| {
                store
                    .insert_chat_message("s1", "user", &format!("m{i}"), "done", None, i)
                    .unwrap()
            })
            .collect();
        store
            .insert_chat_message("other", "user", "x", "done", None, 99)
            .unwrap();

        // Latest page: newest 3, ascending, more exist.
        let (rows, more) = store.list_chat_messages("s1", None, None, 3).unwrap();
        assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), &ids[4..7]);
        assert!(more);

        // Scroll back before the oldest of that page.
        let (rows, more) = store
            .list_chat_messages("s1", None, Some(ids[4]), 3)
            .unwrap();
        assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), &ids[1..4]);
        assert!(more);
        let (rows, more) = store
            .list_chat_messages("s1", None, Some(ids[1]), 3)
            .unwrap();
        assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), &ids[0..1]);
        assert!(!more);

        // Catch up after a cursor.
        let (rows, more) = store
            .list_chat_messages("s1", Some(ids[5]), None, 10)
            .unwrap();
        assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), &ids[6..7]);
        assert!(!more);

        // Other sessions never leak in.
        assert!(rows.iter().all(|r| r.session_id == "s1"));
    }

    #[test]
    fn chat_summaries_clear_and_abandon() {
        let (store, _d) = open_temp();
        assert!(store.chat_summaries().unwrap().is_empty());
        let q = store
            .insert_chat_message("s1", "user", "q", "done", None, 1)
            .unwrap();
        let a = store
            .insert_chat_message("s1", "assistant", "partial", "pending", Some(q), 2)
            .unwrap();
        store
            .insert_chat_message("s2", "user", "only", "done", None, 3)
            .unwrap();

        let mut sums = store.chat_summaries().unwrap();
        sums.sort_by(|x, y| x.session_id.cmp(&y.session_id));
        assert_eq!(sums.len(), 2);
        assert_eq!(sums[0].session_id, "s1");
        assert_eq!(sums[0].count, 2);
        assert!(sums[0].pending);
        assert_eq!(sums[0].last.id, a);
        assert_eq!(sums[1].count, 1);
        assert!(!sums[1].pending);

        assert_eq!(store.abandon_pending_chat(50).unwrap(), 1);
        let row = store.get_chat_message(a).unwrap().unwrap();
        assert_eq!(row.status, "interrupted");
        assert_eq!(row.updated_at, 50);

        assert_eq!(store.clear_chat("s1").unwrap(), 2);
        assert_eq!(store.chat_summaries().unwrap().len(), 1);
    }

    #[test]
    fn chat_source_and_recent_user_turns() {
        let (store, _d) = open_temp();
        let q1 = store
            .insert_chat_message("s1", "user", "one", "done", None, 1)
            .unwrap();
        store
            .insert_chat_message("s1", "assistant", "1", "done", Some(q1), 2)
            .unwrap();
        let q2 = store
            .insert_chat_message_from("s1", "user", "two", "done", None, 3, "import")
            .unwrap();
        let a2 = store
            .insert_chat_message_from("s1", "assistant", "2", "done", Some(q2), 4, "import")
            .unwrap();
        store
            .insert_chat_message("s1", "user", "three", "done", None, 5)
            .unwrap();
        assert_eq!(store.get_chat_message(q1).unwrap().unwrap().source, "chat");
        assert_eq!(
            store.get_chat_message(a2).unwrap().unwrap().source,
            "import"
        );

        let recent = store.recent_user_turns("s1", 2).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].0.content, "three");
        assert!(recent[0].1.is_none(), "no reply yet");
        assert_eq!(recent[1].0.content, "two");
        assert_eq!(recent[1].1.as_ref().unwrap().id, a2);
    }

    #[test]
    fn chat_clear_mark_roundtrip() {
        let (store, _d) = open_temp();
        assert!(store.chat_clear_mark("s1").unwrap().is_none());
        store.set_chat_clear_mark("s1", "last question").unwrap();
        assert_eq!(
            store.chat_clear_mark("s1").unwrap().as_deref(),
            Some("last question")
        );
        store.set_chat_clear_mark("s1", "newer").unwrap();
        assert_eq!(
            store.chat_clear_mark("s1").unwrap().as_deref(),
            Some("newer")
        );
        store.upsert_session("s1", "n", 1).unwrap();
        store.delete_session("s1").unwrap();
        assert!(store.chat_clear_mark("s1").unwrap().is_none());
    }

    #[test]
    fn delete_session_drops_its_chat() {
        let (store, _d) = open_temp();
        store.upsert_session("s1", "n", 1).unwrap();
        store
            .insert_chat_message("s1", "user", "q", "done", None, 1)
            .unwrap();
        assert!(store.delete_session("s1").unwrap());
        let (rows, _) = store.list_chat_messages("s1", None, None, 10).unwrap();
        assert!(rows.is_empty());
    }
}
