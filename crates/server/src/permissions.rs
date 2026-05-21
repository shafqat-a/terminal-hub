//! Per-session ACL helpers. Wraps the `permissions` and `peer_create_allowed`
//! tables.
//!
//! Capabilities are a bitmask: 1=attach, 2=write, 4=manage. Primary users
//! bypass all checks; secondaries are filtered through `permissions` rows.
//!
//! All DB access here goes through the async `Store` API; the table is small
//! (one row per (user, peer, session) tuple) so a per-call mutex acquire is
//! fine for M4 traffic. If contention shows up, switch to a read-mostly cache
//! keyed by `(user_email, peer_id)`.

use crate::db::Store;
use crate::session_id::SessionId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub const NONE: Capabilities = Capabilities(0);
    pub const ATTACH: Capabilities = Capabilities(1);
    pub const WRITE: Capabilities = Capabilities(2);
    pub const MANAGE: Capabilities = Capabilities(4);

    /// Auto-grant for sessions a user owns (created themselves) and for the
    /// primary. Bitmask `0b111 = 7`.
    pub const fn all_for_owner() -> Capabilities {
        Capabilities(1 | 2 | 4)
    }

    pub fn has(self, cap: Capabilities) -> bool {
        (self.0 & cap.0) == cap.0
    }

    pub fn union(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 | other.0)
    }

    pub fn intersect(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 & other.0)
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
    Db(#[from] anyhow::Error),
    #[error("rusqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("unknown user: {0}")]
    UnknownUser(String),
}

pub async fn lookup_role(store: &Store, email: &str) -> Result<Role, Error> {
    let row = store.get_user(email).await?;
    match row {
        Some(u) => match u.role.as_str() {
            "primary" => Ok(Role::Primary),
            "secondary" => Ok(Role::Secondary),
            other => Err(Error::UnknownUser(format!(
                "{email} has unknown role {other}"
            ))),
        },
        None => Err(Error::UnknownUser(email.into())),
    }
}

/// Effective capabilities for a (user, peer, session). Primary always returns
/// `all_for_owner()`; secondary returns whatever the `permissions` row says, or
/// `NONE` if no row exists.
pub async fn effective_caps(
    store: &Store,
    email: &str,
    peer_id: &str,
    session_id: &SessionId,
) -> Result<Capabilities, Error> {
    if lookup_role(store, email).await? == Role::Primary {
        return Ok(Capabilities::all_for_owner());
    }
    let caps = store
        .get_permission_caps(email, peer_id, &session_id.to_string())
        .await?;
    Ok(Capabilities(caps.unwrap_or(0)))
}

/// Sessions a user can see in `list`. Primary returns `None` (= "all");
/// secondary returns `Some(Vec<SessionId>)` filtered to rows where the ATTACH
/// bit is set.
pub async fn visible_sessions(
    store: &Store,
    email: &str,
    peer_id: &str,
) -> Result<Option<Vec<SessionId>>, Error> {
    if lookup_role(store, email).await? == Role::Primary {
        return Ok(None);
    }
    let raw = store.list_visible_session_ids(email, peer_id).await?;
    let ids = raw
        .into_iter()
        .filter_map(|s| uuid::Uuid::parse_str(&s).ok().map(SessionId))
        .collect();
    Ok(Some(ids))
}

pub async fn peer_create_allowed(
    store: &Store,
    email: &str,
    peer_id: &str,
) -> Result<bool, Error> {
    if lookup_role(store, email).await? == Role::Primary {
        return Ok(true);
    }
    Ok(store.peer_create_allowed(email, peer_id).await?)
}

pub async fn grant(
    store: &Store,
    user_email: &str,
    peer_id: &str,
    session_id: &SessionId,
    caps: Capabilities,
    granted_by: &str,
) -> Result<(), Error> {
    store
        .upsert_permission(
            user_email,
            peer_id,
            &session_id.to_string(),
            caps.0,
            granted_by,
        )
        .await?;
    Ok(())
}

pub async fn revoke(
    store: &Store,
    user_email: &str,
    peer_id: &str,
    session_id: &SessionId,
) -> Result<(), Error> {
    store
        .delete_permission(user_email, peer_id, &session_id.to_string())
        .await?;
    Ok(())
}

/// On `kill`, cascade-delete every permission row for that session.
pub async fn cascade_session_delete(
    store: &Store,
    peer_id: &str,
    session_id: &SessionId,
) -> Result<(), Error> {
    store
        .delete_permissions_for_session(peer_id, &session_id.to_string())
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantRow {
    pub user_email: String,
    pub capabilities: Capabilities,
    pub granted_by: String,
    pub granted_at: i64,
}

pub async fn list_grants(
    store: &Store,
    peer_id: &str,
    session_id: &SessionId,
) -> Result<Vec<GrantRow>, Error> {
    let raw = store
        .list_grants_for_session(peer_id, &session_id.to_string())
        .await?;
    Ok(raw
        .into_iter()
        .map(|(user_email, caps, granted_by, granted_at)| GrantRow {
            user_email,
            capabilities: Capabilities(caps),
            granted_by,
            granted_at,
        })
        .collect())
}

pub async fn set_peer_create_allowed(
    store: &Store,
    user_email: &str,
    peer_id: &str,
    allowed: bool,
    granted_by: &str,
) -> Result<(), Error> {
    store
        .set_peer_create_allowed(user_email, peer_id, allowed, granted_by)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed(store: &Store) {
        store
            .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
            .await
            .unwrap();
        store
            .upsert_user("s@x", "ssh-ed25519 AAA", "secondary")
            .await
            .unwrap();
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
        assert!(aw.has(Capabilities::WRITE));
        assert!(!aw.has(Capabilities::MANAGE));
        let only_attach = aw.intersect(Capabilities::ATTACH);
        assert_eq!(only_attach, Capabilities::ATTACH);
    }

    #[tokio::test]
    async fn primary_bypasses_acl() {
        let store = Store::in_memory().unwrap();
        seed(&store).await;
        let id = SessionId::new();
        let caps = effective_caps(&store, "p@x", "local", &id).await.unwrap();
        assert_eq!(caps, Capabilities::all_for_owner());
    }

    #[tokio::test]
    async fn secondary_starts_with_no_rows() {
        let store = Store::in_memory().unwrap();
        seed(&store).await;
        let id = SessionId::new();
        let caps = effective_caps(&store, "s@x", "local", &id).await.unwrap();
        assert_eq!(caps, Capabilities::NONE);
    }

    #[tokio::test]
    async fn grant_then_revoke_round_trip() {
        let store = Store::in_memory().unwrap();
        seed(&store).await;
        let id = SessionId::new();
        grant(
            &store,
            "s@x",
            "local",
            &id,
            Capabilities::all_for_owner(),
            "p@x",
        )
        .await
        .unwrap();
        assert_eq!(
            effective_caps(&store, "s@x", "local", &id).await.unwrap(),
            Capabilities::all_for_owner()
        );
        // Upsert: re-granting with different caps replaces the row.
        grant(&store, "s@x", "local", &id, Capabilities::ATTACH, "p@x")
            .await
            .unwrap();
        assert_eq!(
            effective_caps(&store, "s@x", "local", &id).await.unwrap(),
            Capabilities::ATTACH
        );
        revoke(&store, "s@x", "local", &id).await.unwrap();
        assert_eq!(
            effective_caps(&store, "s@x", "local", &id).await.unwrap(),
            Capabilities::NONE
        );
    }

    #[tokio::test]
    async fn visible_sessions_filters_by_attach_bit() {
        let store = Store::in_memory().unwrap();
        seed(&store).await;
        let attached = SessionId::new();
        let manage_only = SessionId::new();
        grant(
            &store,
            "s@x",
            "local",
            &attached,
            Capabilities::ATTACH.union(Capabilities::WRITE),
            "p@x",
        )
        .await
        .unwrap();
        grant(
            &store,
            "s@x",
            "local",
            &manage_only,
            Capabilities::MANAGE,
            "p@x",
        )
        .await
        .unwrap();
        let visible = visible_sessions(&store, "s@x", "local").await.unwrap();
        let ids = visible.expect("secondary must return Some");
        assert!(ids.contains(&attached), "attached should be visible");
        assert!(
            !ids.contains(&manage_only),
            "MANAGE-only must not be listed (no ATTACH bit)"
        );
        // Primary returns None (= "all sessions").
        assert!(visible_sessions(&store, "p@x", "local")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn cascade_session_delete_removes_all_grants() {
        let store = Store::in_memory().unwrap();
        seed(&store).await;
        store
            .upsert_user("s2@x", "ssh-ed25519 AAA", "secondary")
            .await
            .unwrap();
        let id = SessionId::new();
        grant(
            &store,
            "s@x",
            "local",
            &id,
            Capabilities::all_for_owner(),
            "p@x",
        )
        .await
        .unwrap();
        grant(&store, "s2@x", "local", &id, Capabilities::ATTACH, "p@x")
            .await
            .unwrap();
        cascade_session_delete(&store, "local", &id).await.unwrap();
        assert_eq!(
            effective_caps(&store, "s@x", "local", &id).await.unwrap(),
            Capabilities::NONE
        );
        assert_eq!(
            effective_caps(&store, "s2@x", "local", &id).await.unwrap(),
            Capabilities::NONE
        );
    }

    #[tokio::test]
    async fn peer_create_toggle() {
        let store = Store::in_memory().unwrap();
        seed(&store).await;
        assert!(!peer_create_allowed(&store, "s@x", "local").await.unwrap());
        // Primary always allowed.
        assert!(peer_create_allowed(&store, "p@x", "local").await.unwrap());
        set_peer_create_allowed(&store, "s@x", "local", true, "p@x")
            .await
            .unwrap();
        assert!(peer_create_allowed(&store, "s@x", "local").await.unwrap());
        set_peer_create_allowed(&store, "s@x", "local", false, "p@x")
            .await
            .unwrap();
        assert!(!peer_create_allowed(&store, "s@x", "local").await.unwrap());
    }

    #[tokio::test]
    async fn list_grants_returns_all_users_for_session() {
        let store = Store::in_memory().unwrap();
        seed(&store).await;
        let id = SessionId::new();
        grant(&store, "s@x", "local", &id, Capabilities::ATTACH, "p@x")
            .await
            .unwrap();
        let grants = list_grants(&store, "local", &id).await.unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].user_email, "s@x");
        assert_eq!(grants[0].capabilities, Capabilities::ATTACH);
        assert_eq!(grants[0].granted_by, "p@x");
    }
}
