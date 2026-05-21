//! User-management DAL. Wraps the `users` table for M4 admin endpoints and
//! the `terminal-hub-cli add-user / remove-user / list-users` subcommands.

use crate::db::Store;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    Db(#[from] anyhow::Error),
    #[error("primary user not bootstrapped — run `terminal-hub-cli bootstrap` first")]
    NoPrimary,
    #[error("user already exists: {0}")]
    AlreadyExists(String),
    #[error("cannot remove the primary user via this endpoint")]
    RemovingPrimary,
}

pub async fn list(store: &Store) -> Result<Vec<UserRow>, Error> {
    let raw = store.list_users().await?;
    Ok(raw
        .into_iter()
        .map(
            |(email, role, enrolled_at, passkey_registered)| UserRow {
                email,
                role,
                enrolled_at,
                passkey_registered,
            },
        )
        .collect())
}

/// Add a secondary user. Requires a primary to already exist.
pub async fn add_secondary(store: &Store, email: &str, pubkey: &str) -> Result<UserRow, Error> {
    if store.primary_email().await?.is_none() {
        return Err(Error::NoPrimary);
    }
    if store.get_user(email).await?.is_some() {
        return Err(Error::AlreadyExists(email.into()));
    }
    store.insert_secondary_user(email, pubkey).await?;
    let row = store
        .get_user(email)
        .await?
        .expect("just inserted");
    Ok(UserRow {
        email: row.email,
        role: row.role,
        enrolled_at: row.enrolled_at,
        passkey_registered: row.passkey_creds.is_some(),
    })
}

/// Remove a user and all their grants + session cookies. Refuses to remove
/// the primary.
pub async fn remove(store: &Store, email: &str) -> Result<(), Error> {
    let row = store.get_user(email).await?;
    let Some(u) = row else { return Ok(()) };
    if u.role == "primary" {
        return Err(Error::RemovingPrimary);
    }
    // Active cookies must die immediately so a logged-in secondary loses
    // access on the next request. permissions/peer_create_allowed cascade
    // via FK.
    store.delete_sessions_for_user(email).await?;
    store.delete_user(email).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_requires_primary() {
        let store = Store::in_memory().unwrap();
        let err = add_secondary(&store, "s@x", "ssh-ed25519 AAA fake").await;
        assert!(matches!(err, Err(Error::NoPrimary)));
    }

    #[tokio::test]
    async fn add_and_remove_round_trip() {
        let store = Store::in_memory().unwrap();
        store
            .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
            .await
            .unwrap();
        let r = add_secondary(&store, "s@x", "ssh-ed25519 BBB").await.unwrap();
        assert_eq!(r.role, "secondary");
        assert!(!r.passkey_registered);
        let dup = add_secondary(&store, "s@x", "ssh-ed25519 BBB").await;
        assert!(matches!(dup, Err(Error::AlreadyExists(_))));
        remove(&store, "s@x").await.unwrap();
        assert!(store.get_user("s@x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cannot_remove_primary() {
        let store = Store::in_memory().unwrap();
        store
            .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
            .await
            .unwrap();
        assert!(matches!(
            remove(&store, "p@x").await,
            Err(Error::RemovingPrimary)
        ));
    }

    #[tokio::test]
    async fn remove_nonexistent_is_ok() {
        let store = Store::in_memory().unwrap();
        store
            .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
            .await
            .unwrap();
        remove(&store, "ghost@x").await.unwrap();
    }

    #[tokio::test]
    async fn list_returns_both_roles() {
        let store = Store::in_memory().unwrap();
        store
            .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
            .await
            .unwrap();
        add_secondary(&store, "s@x", "ssh-ed25519 BBB").await.unwrap();
        let rows = list(&store).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.role == "primary"));
        assert!(rows.iter().any(|r| r.role == "secondary"));
    }
}
