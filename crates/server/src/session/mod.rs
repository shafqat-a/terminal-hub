//! Session manager: metadata, viewer tracking, and CRUD over PTY-backed sessions.

pub mod pty;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};
use tokio::sync::RwLock;

use crate::session::pty::PtyHandle;

// ---- Session metadata -------------------------------------------------------

pub struct Session {
    pub id: String,
    pub name: Mutex<String>,
    pub created_at: i64,
    /// (cols, rows)
    pub size: Mutex<(u16, u16)>,
    pub last_client_disconnect: AtomicI64,
    pub viewers: AtomicUsize,
    pub pty: Arc<PtyHandle>,
}

impl Session {
    /// Call when a viewer connects: increments viewer count, clears disconnect stamp.
    pub fn viewer_attached(&self) {
        self.viewers.fetch_add(1, Ordering::Relaxed);
        self.last_client_disconnect.store(0, Ordering::Relaxed);
    }

    /// Call when a viewer disconnects: decrements viewer count; sets disconnect stamp when last viewer leaves.
    pub fn viewer_detached(&self) {
        let prev = self.viewers.fetch_sub(1, Ordering::Relaxed);
        if prev == 1 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            self.last_client_disconnect.store(now, Ordering::Relaxed);
        }
    }
}

// ---- SessionInfo wire shape -------------------------------------------------

const DATE_FMT: &[FormatItem<'_>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

/// Format a unix timestamp as "YYYY-MM-DD HH:MM:SS" in local time.
pub fn format_created_at(unix: i64) -> String {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let dt = OffsetDateTime::from_unix_timestamp(unix)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .to_offset(offset);
    dt.format(DATE_FMT).unwrap_or_else(|_| unix.to_string())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub status: String,
    pub last_activity_at: i64,
    pub last_client_disconnect_at: i64,
    pub cols: u16,
    pub rows: u16,
}

// ---- Error types ------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("pty spawn failed: {0}")]
    Spawn(#[from] pty::PtyError),
    #[error("store error: {0}")]
    Store(#[from] store::StoreError),
}

#[derive(Debug, thiserror::Error)]
#[error("session not found")]
pub struct NotFound;

// ---- Manager ----------------------------------------------------------------

pub struct Manager {
    data_dir: PathBuf,
    shell: String,
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    store: Arc<store::Store>,
}

impl Manager {
    pub fn new(data_dir: PathBuf, shell: String, store: Arc<store::Store>) -> Self {
        Manager {
            data_dir,
            shell,
            sessions: RwLock::new(HashMap::new()),
            store,
        }
    }

    /// Create a new session. `name` defaults to the generated id.
    pub async fn create(&self, name: Option<String>) -> Result<Arc<Session>, CreateError> {
        let full_uuid = uuid::Uuid::new_v4().simple().to_string();
        let id = full_uuid[..8].to_string();
        let session_name = name.unwrap_or_else(|| id.clone());

        let tmux_name = tmux::session_name(&id);
        let pty = PtyHandle::spawn(&self.data_dir, &tmux_name, &self.shell, 24, 80)?;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let session = Arc::new(Session {
            id: id.clone(),
            name: Mutex::new(session_name.clone()),
            created_at,
            size: Mutex::new((80, 24)),
            last_client_disconnect: AtomicI64::new(0),
            viewers: AtomicUsize::new(0),
            pty,
        });

        self.sessions
            .write()
            .await
            .insert(id.clone(), Arc::clone(&session));

        self.store.upsert_session(&id, &session_name, created_at)?;

        Ok(session)
    }

    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        let mut infos: Vec<SessionInfo> = sessions
            .values()
            .map(|s| {
                let name = s.name.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let (cols, rows) = *s.size.lock().unwrap_or_else(|e| e.into_inner());
                SessionInfo {
                    id: s.id.clone(),
                    name,
                    created_at: format_created_at(s.created_at),
                    status: "running".into(),
                    last_activity_at: s.pty.last_activity.load(Ordering::Relaxed),
                    last_client_disconnect_at: s.last_client_disconnect.load(Ordering::Relaxed),
                    cols,
                    rows,
                }
            })
            .collect();
        // Stable ordering by id (which is uuid-prefix, monotone within a process run).
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    pub async fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.read().await.get(id).cloned()
    }

    /// Rename session. Returns `Err(NotFound)` if id is absent.
    pub async fn rename(&self, id: &str, name: &str) -> Result<(), NotFound> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(id).ok_or(NotFound)?;
        *session.name.lock().unwrap_or_else(|e| e.into_inner()) = name.to_string();
        drop(sessions);
        self.store.rename_session(id, name).map_err(|_| NotFound)?;
        Ok(())
    }

    /// Delete a session: detach PTY, kill tmux session, remove from in-memory map and store.
    pub async fn delete(&self, id: &str) -> Result<(), NotFound> {
        let session = self.sessions.write().await.remove(id).ok_or(NotFound)?;

        session.pty.detach();
        tmux::kill_session(&self.data_dir, &tmux::session_name(id))
            .await
            .ok();
        self.store.delete_session(id).map_err(|_| NotFound)?;
        Ok(())
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    fn make_manager(dir: &std::path::Path) -> Manager {
        let store = Arc::new(store::Store::open(&dir.join("conductor.db")).expect("store open"));
        Manager::new(dir.to_path_buf(), "/bin/sh".into(), store)
    }

    #[tokio::test]
    async fn create_produces_8char_id_and_tmux_session() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let sess = mgr.create(None).await.expect("create");

        assert_eq!(sess.id.len(), 8, "id must be 8 chars");
        let tmux_name = tmux::session_name(&sess.id);

        // Poll up to 2s for tmux to register the session (startup latency).
        let mut alive = false;
        for _ in 0..20 {
            if tmux::has_session(dir.path(), &tmux_name).await {
                alive = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(alive, "tmux session should exist within 2s");

        let rows = mgr.store.list_sessions().expect("list store");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, sess.id);

        mgr.delete(&sess.id).await.expect("delete");
    }

    #[tokio::test]
    async fn list_returns_session_info_with_correct_json_keys() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let sess = mgr.create(None).await.expect("create");

        let list = mgr.list().await;
        assert_eq!(list.len(), 1);
        let info = &list[0];

        let json = serde_json::to_string(info).expect("serialize");
        assert!(json.contains("\"createdAt\""), "missing createdAt: {json}");
        assert!(
            json.contains("\"lastActivityAt\""),
            "missing lastActivityAt: {json}"
        );
        assert!(
            json.contains("\"lastClientDisconnectAt\""),
            "missing lastClientDisconnectAt: {json}"
        );
        assert!(json.contains("\"status\""), "missing status: {json}");
        assert!(json.contains("\"cols\""), "missing cols: {json}");
        assert!(json.contains("\"rows\""), "missing rows: {json}");

        assert_eq!(
            info.created_at.len(),
            19,
            "createdAt must be 19 chars: {}",
            info.created_at
        );
        let ca: Vec<char> = info.created_at.chars().collect();
        assert_eq!(ca[4], '-');
        assert_eq!(ca[7], '-');
        assert_eq!(ca[10], ' ');
        assert_eq!(ca[13], ':');
        assert_eq!(ca[16], ':');

        assert_eq!(info.status, "running");
        assert_eq!(info.cols, 80);
        assert_eq!(info.rows, 24);

        mgr.delete(&sess.id).await.expect("delete");
    }

    #[tokio::test]
    async fn rename_updates_name_in_list_and_store() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let sess = mgr.create(Some("original".into())).await.expect("create");

        mgr.rename(&sess.id, "updated").await.expect("rename");

        let list = mgr.list().await;
        assert_eq!(list[0].name, "updated");

        let store_rows = mgr.store.list_sessions().expect("list store");
        assert_eq!(store_rows[0].1, "updated");

        mgr.delete(&sess.id).await.expect("delete");
    }

    #[tokio::test]
    async fn delete_kills_tmux_and_removes_from_store() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let sess = mgr.create(None).await.expect("create");
        let id = sess.id.clone();
        let tmux_name = tmux::session_name(&id);

        mgr.delete(&id).await.expect("delete");

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !tmux::has_session(dir.path(), &tmux_name).await,
            "tmux session should be gone"
        );
        assert!(mgr.store.list_sessions().expect("list").is_empty());
        assert!(mgr.get(&id).await.is_none());
    }

    #[tokio::test]
    async fn get_unknown_returns_none() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        assert!(mgr.get("zzzzzzzz").await.is_none());
    }

    #[tokio::test]
    async fn viewer_attached_and_detached_stamps() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let sess = mgr.create(None).await.expect("create");

        assert_eq!(sess.last_client_disconnect.load(Ordering::Relaxed), 0);
        assert_eq!(sess.viewers.load(Ordering::Relaxed), 0);

        sess.viewer_attached();
        assert_eq!(sess.viewers.load(Ordering::Relaxed), 1);
        assert_eq!(sess.last_client_disconnect.load(Ordering::Relaxed), 0);

        sess.viewer_detached();
        assert_eq!(sess.viewers.load(Ordering::Relaxed), 0);
        assert!(sess.last_client_disconnect.load(Ordering::Relaxed) > 0);

        mgr.delete(&sess.id).await.expect("delete");
    }

    #[test]
    fn format_created_at_has_correct_shape() {
        // Fixed timestamp: 2024-01-15 12:30:45 UTC = 1705318245
        let ts = 1_705_318_245_i64;
        let formatted = format_created_at(ts);
        assert_eq!(formatted.len(), 19, "must be 19 chars: {formatted}");
        let chars: Vec<char> = formatted.chars().collect();
        assert_eq!(chars[4], '-');
        assert_eq!(chars[7], '-');
        assert_eq!(chars[10], ' ');
        assert_eq!(chars[13], ':');
        assert_eq!(chars[16], ':');
        for (i, &c) in chars.iter().enumerate() {
            if ![4, 7, 10, 13, 16].contains(&i) {
                assert!(c.is_ascii_digit(), "pos {i} should be digit, got {c}");
            }
        }
    }
}
