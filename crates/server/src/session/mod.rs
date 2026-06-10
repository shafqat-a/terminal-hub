//! Session manager: metadata, viewer tracking, and CRUD over PTY-backed sessions.

pub mod pty;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

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
    #[error("session limit reached")]
    SessionLimit,
}

#[derive(Debug, thiserror::Error)]
#[error("session not found")]
pub struct NotFound;

// ---- Free helper: delete a session by id given bare Arc fields --------------
//
// Used by both Manager::delete and the reap loop (which can't call &self
// methods because it only holds Arc clones of the fields, not a &Manager).

async fn delete_session_by_id(
    sessions: &Arc<RwLock<HashMap<String, Arc<Session>>>>,
    store: &Arc<store::Store>,
    data_dir: &Path,
    id: &str,
) -> Result<(), NotFound> {
    let live = sessions.write().await.remove(id);
    if let Some(session) = live {
        session.pty.detach();
        tmux::kill_session(data_dir, &tmux::session_name(id))
            .await
            .ok();
        session.closed.send_replace(true);
        store.delete_session(id).map_err(|_| NotFound)?;
        return Ok(());
    }
    // No live session -- check for a store-only row.
    let row = store.get_session(id).unwrap_or(None);
    if row.is_some() {
        tmux::kill_session(data_dir, &tmux::session_name(id))
            .await
            .ok();
        store.delete_session(id).map_err(|_| NotFound)?;
        return Ok(());
    }
    Err(NotFound)
}

// ---- Manager ----------------------------------------------------------------

pub struct Manager {
    data_dir: PathBuf,
    shell: String,
    sessions: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    store: Arc<store::Store>,
    idle_timeout: Duration,
    max_sessions: u32,
    flush_interval: Duration,
    /// Background loop handles; aborted on Drop.
    loop_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for Manager {
    fn drop(&mut self) {
        let handles = self.loop_handles.lock().unwrap_or_else(|e| e.into_inner());
        for h in handles.iter() {
            h.abort();
        }
    }
}

impl Manager {
    pub fn new(
        data_dir: PathBuf,
        shell: String,
        store: Arc<store::Store>,
        idle_timeout: Duration,
        max_sessions: u32,
        flush_interval: Duration,
    ) -> Self {
        Manager {
            data_dir,
            shell,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            store,
            idle_timeout,
            max_sessions,
            flush_interval,
            loop_handles: Mutex::new(Vec::new()),
        }
    }

    /// Called once after construction: mark all DB rows detached, then re-adopt
    /// any live `aidc_*` tmux sessions left from a previous server run.
    /// Spawns background loops (reap + flush) at the end.
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
            let Some(id) = tmux_name.strip_prefix("aidc_") else {
                continue;
            };
            let id = id.to_string();

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

        // ---- Spawn background loops -----------------------------------------

        // Reap loop: only if idle_timeout > 0.
        if self.idle_timeout > Duration::ZERO {
            let raw_half = self.idle_timeout / 2;
            let interval = raw_half
                .max(Duration::from_secs(1))
                .min(Duration::from_secs(60));
            let idle_timeout = self.idle_timeout;
            let sessions = Arc::clone(&self.sessions);
            let store = Arc::clone(&self.store);
            let data_dir = self.data_dir.clone();

            let handle = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let now = unix_now_secs();
                    // Idle bookkeeping is in whole unix seconds (Go compares
                    // nanosecond stamps), so a configured timeout in (0, 1s)
                    // would truncate to 0 and reap on any second-boundary
                    // crossing — clamp the effective timeout to 1s instead.
                    // Sub-second timeouts therefore behave as 1s (documented
                    // divergence from Go's exact sub-second reaping).
                    let idle_secs = (idle_timeout.as_secs() as i64).max(1);

                    // Collect victims: viewers == 0 AND idle basis older than idle_timeout.
                    //
                    // TOCTOU: a viewer can attach between this selection (under
                    // the read lock) and the kill in delete_session_by_id below.
                    // Accepted, matching Go (reapOnce collects victim ids under
                    // RLock, then Deletes them lock-free): the window is a
                    // single loop iteration, it only affects a session that was
                    // already idle past the timeout, and the worst case is one
                    // just-attached viewer seeing its session close — the
                    // client simply creates a new session.
                    let victims: Vec<String> = {
                        let map = sessions.read().await;
                        map.values()
                            .filter(|s| {
                                let viewers = s.viewers.load(Ordering::Relaxed);
                                if viewers > 0 {
                                    return false;
                                }
                                let disconnect = s.last_client_disconnect.load(Ordering::Relaxed);
                                let basis = if disconnect > 0 {
                                    disconnect
                                } else {
                                    s.created_at
                                };
                                (now - basis) > idle_secs
                            })
                            .map(|s| s.id.clone())
                            .collect()
                    };

                    for id in victims {
                        tracing::info!("session {id}: reaped (idle > {idle_timeout:?})");
                        delete_session_by_id(&sessions, &store, &data_dir, &id)
                            .await
                            .ok();
                    }
                }
            });

            self.loop_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(handle);
        }

        // Flush loop: always active.
        {
            let flush_interval = self.flush_interval;
            let sessions = Arc::clone(&self.sessions);
            let store = Arc::clone(&self.store);

            let handle = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(flush_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let map = sessions.read().await;
                    for s in map.values() {
                        let activity = s.pty.last_activity.load(Ordering::Relaxed);
                        store.set_activity(&s.id, activity).ok();
                        let (cols, rows) = *s.size.lock().unwrap_or_else(|e| e.into_inner());
                        store.set_size(&s.id, cols as i64, rows as i64).ok();
                    }
                }
            });

            self.loop_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(handle);
        }
    }

    /// Spawn the dead-detection monitor task for a session.
    fn spawn_monitor(&self, session: Arc<Session>) {
        let sessions = Arc::clone(&self.sessions);
        let store = Arc::clone(&self.store);
        tokio::spawn(async move {
            let mut exited_rx = session.pty.exited_rx();
            // Wait until the PTY reader signals exit (EOF on master PTY).
            exited_rx.changed().await.ok();
            if !*exited_rx.borrow() {
                return;
            }
            // Verify the session is still the same Arc in the map (not replaced).
            let mut map = sessions.write().await;
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
        // Cap check: if max_sessions > 0 and the live map is at or over the limit, reject.
        if self.max_sessions > 0 {
            let count = self.sessions.read().await.len();
            if count >= self.max_sessions as usize {
                return Err(CreateError::SessionLimit);
            }
        }

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

        // Build live session infos as (unix_ts, id, SessionInfo) for sort key.
        let mut keyed: Vec<(i64, String, SessionInfo)> = sessions
            .values()
            .map(|s| {
                let name = s.name.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let (cols, rows) = *s.size.lock().unwrap_or_else(|e| e.into_inner());
                let info = SessionInfo {
                    id: s.id.clone(),
                    name,
                    created_at: format_created_at(s.created_at),
                    status: "running".into(),
                    last_activity_at: s.pty.last_activity.load(Ordering::Relaxed),
                    last_client_disconnect_at: s.last_client_disconnect.load(Ordering::Relaxed),
                    cols,
                    rows,
                };
                (s.created_at, s.id.clone(), info)
            })
            .collect();

        // Append store-only rows (detached / dead) that are not in the live map.
        if let Ok(store_rows) = self.store.list_sessions() {
            for row in store_rows {
                if live_ids.contains(&row.id) {
                    continue;
                }
                let unix = row.created_at;
                let id = row.id.clone();
                keyed.push((
                    unix,
                    id,
                    SessionInfo {
                        id: row.id,
                        name: row.name,
                        created_at: format_created_at(row.created_at),
                        status: row.status,
                        last_activity_at: row.last_activity_at,
                        last_client_disconnect_at: row.last_client_disconnect_at,
                        cols: row.cols as u16,
                        rows: row.rows as u16,
                    },
                ));
            }
        }

        // Stable ordering by (created_at unix i64, id) as tiebreaker.
        keyed.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let infos: Vec<SessionInfo> = keyed.into_iter().map(|(_, _, info)| info).collect();

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
        delete_session_by_id(&self.sessions, &self.store, &self.data_dir, id).await
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
        Manager::new(
            dir.to_path_buf(),
            "/bin/sh".into(),
            store,
            Duration::ZERO,
            0,
            Duration::from_secs(15),
        )
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

        // Fix 5: write to the re-adopted session PTY and verify output via capture-pane.
        {
            let sess = mgr2
                .get(&sess_id)
                .await
                .expect("session must be gettable after re-adoption");
            // Give tmux a moment for the re-attached PTY to be ready.
            tokio::time::sleep(Duration::from_millis(500)).await;
            sess.pty
                .write(b"echo ADOPT_WRITE_OK\n")
                .expect("pty write must succeed");

            let tmux_name = tmux::session_name(&sess_id);
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut found = false;
            while std::time::Instant::now() < deadline {
                if let Ok(bytes) = tmux::capture_pane(dir.path(), &tmux_name, 50).await {
                    if String::from_utf8_lossy(&bytes).contains("ADOPT_WRITE_OK") {
                        found = true;
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(found, "capture_pane must contain ADOPT_WRITE_OK within 5s");
        }

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

    // ---- U3 tests -----------------------------------------------------------

    /// Idle session (never attached) is reaped within the deadline.
    #[tokio::test]
    async fn reap_idle_session() {
        let dir = tempdir().unwrap();
        let store =
            Arc::new(store::Store::open(&dir.path().join("conductor.db")).expect("store open"));
        let mgr = Manager::new(
            dir.path().to_path_buf(),
            "/bin/sh".into(),
            Arc::clone(&store),
            Duration::from_secs(2), // idle_timeout = 2s
            0,
            Duration::from_millis(100),
        );
        mgr.init().await;

        let sess = mgr.create(None).await.expect("create");
        let id = sess.id.clone();
        let tmux_name = tmux::session_name(&id);

        // Never attach -- poll list() until empty (≤8s).
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut reaped = false;
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if mgr.list().await.is_empty() {
                reaped = true;
                break;
            }
        }
        assert!(reaped, "idle session must be reaped within 8s");
        // tmux session must also be gone.
        assert!(
            !tmux::has_session(dir.path(), &tmux_name).await,
            "tmux session must be killed by reaper"
        );
    }

    /// Sub-second idle_timeout (0 < t < reaper tick resolution) is clamped to
    /// 1s of effective idle and still reaps — never disabled, never instant.
    #[tokio::test]
    async fn reap_subsecond_idle_timeout() {
        let dir = tempdir().unwrap();
        let store =
            Arc::new(store::Store::open(&dir.path().join("conductor.db")).expect("store open"));
        let mgr = Manager::new(
            dir.path().to_path_buf(),
            "/bin/sh".into(),
            Arc::clone(&store),
            Duration::from_millis(500), // sub-second idle_timeout
            0,
            Duration::from_millis(100),
        );
        mgr.init().await;

        let sess = mgr.create(None).await.expect("create");
        let id = sess.id.clone();
        let tmux_name = tmux::session_name(&id);

        // Never attach -- poll list() until empty (≤8s).
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut reaped = false;
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if mgr.list().await.is_empty() {
                reaped = true;
                break;
            }
        }
        assert!(
            reaped,
            "sub-second idle_timeout must still reap (clamped to 1s)"
        );
        assert!(
            !tmux::has_session(dir.path(), &tmux_name).await,
            "tmux session must be killed by reaper"
        );
    }

    /// Session with an attached viewer is NOT reaped during the idle window.
    #[tokio::test]
    async fn attached_session_not_reaped() {
        let dir = tempdir().unwrap();
        let store =
            Arc::new(store::Store::open(&dir.path().join("conductor.db")).expect("store open"));
        let mgr = Manager::new(
            dir.path().to_path_buf(),
            "/bin/sh".into(),
            Arc::clone(&store),
            Duration::from_secs(2),
            0,
            Duration::from_millis(100),
        );
        mgr.init().await;

        let sess = mgr.create(None).await.expect("create");
        let id = sess.id.clone();

        // Attach a viewer.
        sess.viewer_attached();

        // Wait 3s (> idle_timeout) -- session must still be present.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            mgr.get(&id).await.is_some(),
            "attached session must NOT be reaped"
        );

        // Detach -- now it becomes idle.
        sess.viewer_detached();

        // Poll until reaped (≤8s).
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut reaped = false;
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if mgr.get(&id).await.is_none() {
                reaped = true;
                break;
            }
        }
        assert!(reaped, "session must be reaped after viewer detaches");
    }

    /// Flush loop persists last_activity_at and size within the deadline.
    #[tokio::test]
    async fn flush_persists_activity_and_size() {
        let dir = tempdir().unwrap();
        let store =
            Arc::new(store::Store::open(&dir.path().join("conductor.db")).expect("store open"));
        let mgr = Manager::new(
            dir.path().to_path_buf(),
            "/bin/sh".into(),
            Arc::clone(&store),
            Duration::ZERO,
            0,
            Duration::from_millis(200), // fast flush for test
        );
        mgr.init().await;

        let sess = mgr.create(None).await.expect("create");
        let id = sess.id.clone();

        // Give tmux a moment to start.
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Write to PTY to drive last_activity.
        sess.pty.write(b"echo FLUSH_TEST\n").ok();

        // Update size via session.size and pty.resize.
        {
            let mut sz = sess.size.lock().unwrap_or_else(|e| e.into_inner());
            *sz = (132, 40);
        }
        sess.pty.resize(40, 132).ok();

        // Poll store for ≤3s until last_activity_at > 0 and cols/rows correct.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut ok = false;
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(Some(row)) = store.get_session(&id) {
                if row.last_activity_at > 0 && row.cols == 132 && row.rows == 40 {
                    ok = true;
                    break;
                }
            }
        }
        assert!(
            ok,
            "flush loop must persist last_activity_at > 0 and cols=132 rows=40 within 3s"
        );

        mgr.delete(&id).await.expect("delete");
    }
}
