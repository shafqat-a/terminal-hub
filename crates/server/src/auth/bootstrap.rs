//! Bootstrap tokens are the one-time secret that lets the user open the enrollment
//! URL in the browser after the CLI has proved possession of the SSH key.
//!
//! The raw token (b64) is shown to the user once. Only its argon2 hash lives in the DB.

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use base64::Engine;
use rand::RngCore;

use crate::db::Store;

pub const TTL_SECS: i64 = 5 * 60;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("argon2: {0}")]
    Argon(String),
    #[error("db: {0}")]
    Db(#[from] anyhow::Error),
    #[error("expired or unknown token")]
    Invalid,
}

/// Generate a new token, store its argon2 hash in `bootstrap_tokens`, return the raw value
/// (encoded as URL-safe b64 — what we hand to the user via the CLI).
pub async fn mint(store: &Store, email: &str) -> Result<String, Error> {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let raw_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);

    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon = Argon2::default();
    let hash = argon
        .hash_password(raw_b64.as_bytes(), &salt)
        .map_err(|e| Error::Argon(e.to_string()))?
        .to_string();

    store
        .insert_bootstrap_token(hash.as_bytes(), email, TTL_SECS)
        .await?;
    Ok(raw_b64)
}

/// Look up an unconsumed, unexpired token whose hash verifies against `raw_b64`.
/// On success, marks it consumed and returns the email.
pub async fn redeem(store: &Store, raw_b64: &str) -> Result<String, Error> {
    // We can't index by raw token (we don't store it). Scan unexpired rows
    // and argon2-verify each. The set is tiny (one user, 5-min TTL, max a few
    // outstanding tokens), so the O(n) cost is irrelevant.
    let rows = store.list_bootstrap_tokens_for_all_users().await?;
    for row in rows {
        let stored = std::str::from_utf8(&row.token_hash).map_err(|_| Error::Invalid)?;
        let parsed =
            argon2::PasswordHash::new(stored).map_err(|e| Error::Argon(e.to_string()))?;
        if Argon2::default()
            .verify_password(raw_b64.as_bytes(), &parsed)
            .is_ok()
            && store.consume_bootstrap_token(&row.token_hash).await?
        {
            return Ok(row.user_email);
        }
    }
    Err(Error::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mint_redeem_consume_once() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary")
            .await
            .unwrap();
        let raw = mint(&s, "a@b").await.unwrap();
        assert_eq!(redeem(&s, &raw).await.unwrap(), "a@b");
        assert!(matches!(redeem(&s, &raw).await, Err(Error::Invalid)));
    }

    #[tokio::test]
    async fn redeem_with_garbage_fails() {
        let s = Store::in_memory().unwrap();
        s.upsert_user("a@b", "ssh-ed25519 AAA", "primary")
            .await
            .unwrap();
        let _raw = mint(&s, "a@b").await.unwrap();
        assert!(matches!(
            redeem(&s, "not-a-real-token").await,
            Err(Error::Invalid)
        ));
    }
}
