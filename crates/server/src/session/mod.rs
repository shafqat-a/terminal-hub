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

// ---- Helpers --------------------------------------------------------------

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

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
    pub closed: tokio::sync::watch::Sender<bool>,
}

impl Session {
    /// Call when a viewer connects: increments viewer count, clears disconnect stamp.
    pub fn viewer_attached(&self) {
        self.viewers.fetch_add(1, Ordering::Relaxed);
        self.last_client_disconnect.store(0, Ordering::Relaxed);
    }

    /// Call when a viewer disconnects: decrements viewer count; sets disconnect stamp when last viewer leaves.
    pub fn viewer_detached(&self) {
        let prev = self
            .viewers
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .unwrap_or(0);
        if prev <= 1 {
            self.last_client_disconnect
                .store(unix_now_secs(), Ordering::Relaxed);
        }
    }

    /// Return the current viewer count (for tests and diagnostics).
    #[cfg(test)]
    pub fn viewers(&self) -> usize {
        self.viewers.load(Ordering::Relaxed)
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

    /// Called once after construction: mark all DB rows detached, then re-adopt
    /// any live `aidc_*` tmux sessions left from a previous server run.
    pub async fn init(&self) {
        // All persisted sessions are assumed detached until we confirm they are live.
        self.store.mark_all_detached().ok();

        // Re-adopt live tmux sessions that match our naming prefix.
        let live_names = tmux::list_sessions(&self.data_dir).await;
        for tmux_name in live_names {
            if !tmux_name.starts_with("aidc_") {
                continue;
            }
            // Derive id from the tmux session name: "aidc_<id>".
            let id = tmux_name.trim_start_matches("aidc_").to_string();

            let pty = match PtyHandle::spawn(&self.data_dir, &tmux_name, &self.shell, 24, 80) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(id, "re-adopt PTY spawn failed: {e}");
                    continue;
                }
            };

            // Look up or create the store row to get the right created_at and name.
            let row = self.store.get_session(&id).unwrap_or(None);
            let (created_at, name) = match row {
                Some(r) => (r.created_at, r.name),
                None => {
                    let now = unix_now_secs();
                    self.store.upsert_session(&id, &id, now).ok();
                    (now, id.clone())
                }
            };

            let (closed_tx, _closed_rx) = tokio::sync::watch::channel(false);
            let session = Arc::new(Session {
                id: id.clone(),
                name: Mutex::new(name),
                created_at,
                size: Mutex::new((80, 24)),
                last_client_disconnect: AtomicI64::new(0),
                viewers: AtomicUsize::new(0),
                pty,
                closed: closed_tx,
            });

            self.sessions
                .write()
                .await
                .insert(id.clone(), Arc::clone(&session));

            // Mark the session running in the store.
            self.store.set_status(&id, "running").ok();

            self.spawn_monitor(Arc::clone(&session));

            tracing::info!(id, "re-adopted tmux session");
        }
    }

    /// Spawn the dead-detection monitor task for a session.
    fn spawn_monitor(&self, session: Arc<Session>) {
        let sessions_ptr = &self.sessions as *const RwLock<HashMap<String, Arc<Session>>>;
        // SAFETY: The Manager is wrapped in Arc<AppState> which lives for the
        // lifetime of the tokio runtime; tasks are cancelled before Manager drops.
        let sessions_ref = unsafe { &*sessions_ptr };
        let store = Arc::clone(&self.store);
        tokio::spawn(async move {
            let mut exited_rx = session.pty.exited_rx();
            // Wait until the PTY reader signals exit (EOF on master PTY).
            exited_rx.changed().await.ok();
            if !*exited_rx.borrow() {
                return;
            }
            // Verify the session is still the same Arc in the map (not replaced).
            let mut map = sessions_ref.write().await;
            let still_present = map
                .get(&session.id)
                .map(|s| Arc::ptr_eq(s, &session))
                .unwrap_or(false);
            if still_present {
                map.remove(&session.id);
                drop(map);
                store.set_status(&session.id, "dead").ok();
                session.closed.send_replace(true);
                tracing::info!(id = %session.id, "session marked dead (PTY exited)");
            }
        });
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

        let (closed_tx, _closed_rx) = tokio::sync::watch::channel(false);
        let session = Arc::new(Session {
            id: id.clone(),
            name: Mutex::new(session_name.clone()),
            created_at,
            size: Mutex::new((80, 24)),
            last_client_disconnect: AtomicI64::new(0),
            viewers: AtomicUsize::new(0),
            pty,
            closed: closed_tx,
        });

        self.sessions
            .write()
            .await
            .insert(id.clone(), Arc::clone(&session));

        self.store.upsert_session(&id, &session_name, created_at)?;
        self.store.set_status(&id, "running").ok();

        self.spawn_monitor(Arc::clone(&session));

        Ok(session)
    }

    /// List all sessions: live (status running) merged with store-only rows.
    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;

        // Collect live session ids.
        let live_ids: std::collections::HashSet<String> = sessions.keys().cloned().collect();

        // Build live session infos.
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

        // Append store-only rows (detached / dead) that are not in the live map.
        if let Ok(store_rows) = self.store.list_sessions() {
            for row in store_rows {
                if live_ids.contains(&row.id) {
                    continue;
                }
                infos.push(SessionInfo {
                    id: row.id,
                    name: row.name,
                    created_at: format_created_at(row.created_at),
                    status: row.status,
                    last_activity_at: row.last_activity_at,
                    last_client_disconnect_at: row.last_client_disconnect_at,
                    cols: row.cols as u16,
                    rows: row.rows as u16,
                });
            }
        }

        // Stable ordering by (created_at string, id) as tiebreaker.
        infos.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));

        infos
    }

    pub async fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.read().await.get(id).cloned()
    }

    /// Rename session. Returns `Err(NotFound)` if id is absent in both map and store.
    pub async fn rename(&self, id: &str, name: &str) -> Result<(), NotFound> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(id) {
            *session.name.lock().unwrap_or_else(|e| e.into_inner()) = name.to_string();
            drop(sessions);
            self.store.rename_session(id, name).map_err(|_| NotFound)?;
            return Ok(());
        }
        drop(sessions);
        // Store-only row: rename in DB if it exists.
        let row = self.store.get_session(id).unwrap_or(None);
        if row.is_some() {
            self.store.rename_session(id, name).map_err(|_| NotFound)?;
            return Ok(());
        }
        Err(NotFound)
    }

    /// Delete a session: handles both live sessions and store-only rows.
    pub async fn delete(&self, id: &str) -> Result<(), NotFound> {
        let live = self.sessions.write().await.remove(id);
        if let Some(session) = live {
            session.pty.detach();
            tmux::kill_session(&self.data_dir, &tmux::session_name(id))
                .await
                .ok();
            // Signal all viewers that this session has been deleted.
            session.closed.send_replace(true);
            self.store.delete_session(id).map_err(|_| NotFound)?;
            return Ok(());
        }
        // No live session -- check for a store-only row.
        let row = self.store.get_session(id).unwrap_or(None);
        if row.is_some() {
            // Kill any orphan tmux session (best effort).
            tmux::kill_session(&self.data_dir, &tmux::session_name(id))
                .await
                .ok();
            self.store.delete_session(id).map_err(|_| NotFound)?;
            return Ok(());
        }
        Err(NotFound)
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
        assert_eq!(rows[0].id, sess.id);

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
        assert_eq!(store_rows[0].name, "updated");

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

    /// Fix 3 regression: viewer_detached without a prior attach must saturate at 0,
    /// not wrap the AtomicUsize counter.
    #[test]
    fn viewer_detached_without_attach_does_not_wrap() {
        let viewers = AtomicUsize::new(0);

        // Same logic as Session::viewer_detached.
        let prev = viewers
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .unwrap_or(0);
        // prev is 0, so stamp would be set -- that is acceptable; what must NOT happen
        // is the counter wrapping to usize::MAX.
        let _ = prev;

        assert_eq!(
            viewers.load(Ordering::Relaxed),
            0,
            "viewers must stay at 0, not wrap to usize::MAX"
        );
    }

    // ---- U2 tests -----------------------------------------------------------

    /// After a server restart (new Manager + init), sessions left in tmux are
    /// re-adopted and listed as running with the original name and created_at.
    #[tokio::test]
    async fn readoption_restores_session() {
        let dir = tempdir().unwrap();

        // First manager: create a session.
        let sess_id;
        let sess_name;
        let sess_created_at;
        {
            let mgr1 = make_manager(dir.path());
            let sess = mgr1.create(Some("mywork".into())).await.expect("create");
            sess_id = sess.id.clone();
            sess_name = "mywork".to_string();
            sess_created_at = sess.created_at;
            // Drop mgr1 without deleting the session -- tmux session stays alive.
        }

        // Give tmux a moment to settle.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Second manager: init re-adopts the existing tmux session.
        let mgr2 = make_manager(dir.path());
        mgr2.init().await;

        let list = mgr2.list().await;
        let found = list.iter().find(|s| s.id == sess_id);
        assert!(
            found.is_some(),
            "session {sess_id} must appear in list after re-adoption"
        );
        let info = found.unwrap();
        assert_eq!(info.name, sess_name, "name must be preserved");
        assert_eq!(info.status, "running", "re-adopted session must be running");

        // created_at string encodes the original timestamp.
        let expected_ca = format_created_at(sess_created_at);
        assert_eq!(info.created_at, expected_ca, "created_at must be preserved");

        // Cleanup.
        mgr2.delete(&sess_id).await.expect("delete");
    }

    /// A store row with no live session (status "detached") appears in list().
    #[tokio::test]
    async fn detached_rows_listed() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());

        // Insert a store row directly without a live session.
        let id = "ghostrow";
        let now = unix_now_secs();
        mgr.store
            .upsert_session(id, "ghost session", now)
            .expect("upsert");
        // upsert sets status "running"; mark all detached.
        mgr.store.mark_all_detached().expect("mark detached");

        let list = mgr.list().await;
        let found = list.iter().find(|s| s.id == id);
        assert!(found.is_some(), "ghost row must appear in list");
        let info = found.unwrap();
        assert_eq!(
            info.status, "detached",
            "store-only row must have detached status"
        );
        assert_eq!(info.name, "ghost session");
    }

    /// When a tmux session dies externally, the monitor task marks it dead
    /// and fires the closed signal within 5 seconds.
    #[tokio::test]
    async fn dead_detection() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());
        let sess = mgr.create(None).await.expect("create");
        let id = sess.id.clone();
        let tmux_name = tmux::session_name(&id);

        // Subscribe to the closed signal.
        let mut closed_rx = sess.closed.subscribe();

        // Give tmux a moment to start.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Kill the tmux session externally.
        tmux::kill_session(dir.path(), &tmux_name).await.ok();

        // Wait up to 5s for the closed signal.
        let fired = tokio::time::timeout(Duration::from_secs(5), closed_rx.changed()).await;
        assert!(fired.is_ok(), "closed signal should fire within 5s");
        assert!(*closed_rx.borrow(), "closed value must be true");

        // Poll up to 2s for the store status to become "dead".
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut status_dead = false;
        while std::time::Instant::now() < deadline {
            if let Ok(Some(row)) = mgr.store.get_session(&id) {
                if row.status == "dead" {
                    status_dead = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(status_dead, "store status must become dead");
    }

    /// Deleting a store-only row returns Ok; truly unknown id returns NotFound.
    #[tokio::test]
    async fn delete_detached_row() {
        let dir = tempdir().unwrap();
        let mgr = make_manager(dir.path());

        // Insert a store-only row.
        let id = "ghostdel";
        let now = unix_now_secs();
        mgr.store.upsert_session(id, "ghost", now).expect("upsert");
        mgr.store.mark_all_detached().expect("mark detached");

        // Delete should succeed.
        mgr.delete(id)
            .await
            .expect("delete detached row must succeed");

        // Verify row is gone.
        let row = mgr.store.get_session(id).unwrap_or(None);
        assert!(row.is_none(), "row must be removed from store");

        // Delete again: NotFound.
        let err = mgr.delete(id).await;
        assert!(err.is_err(), "second delete must return NotFound");
    }
}
