//! webauthn-rs wrapper. One Webauthn instance per server boot, keyed off
//! TERMINAL_HUB_PUBLIC_URL. The RP-ID is derived from that URL's host.

use crate::db::Store;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

const STATE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("webauthn: {0}")]
    Webauthn(#[from] WebauthnError),
    #[error("db: {0}")]
    Db(#[from] anyhow::Error),
    #[error("no such user")]
    NoUser,
    #[error("registration state expired or unknown")]
    BadState,
    #[error("user has no passkey enrolled")]
    NoCreds,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config: {0}")]
    Config(String),
}

#[derive(Clone)]
pub struct PasskeySvc {
    wan: Arc<Webauthn>,
    reg_state: Arc<Mutex<HashMap<Uuid, (String, PasskeyRegistration, Instant)>>>,
    auth_state: Arc<Mutex<HashMap<Uuid, (String, PasskeyAuthentication, Instant)>>>,
}

impl PasskeySvc {
    /// Builds the Webauthn instance from `TERMINAL_HUB_PUBLIC_URL`
    /// (e.g. `https://hub.local:5999/`). Fails loudly if unset — RP-ID is mandatory.
    pub fn from_env() -> Result<Self, Error> {
        let raw = std::env::var("TERMINAL_HUB_PUBLIC_URL")
            .map_err(|_| Error::Config("TERMINAL_HUB_PUBLIC_URL must be set".into()))?;
        let url = Url::parse(&raw).map_err(|e| Error::Config(format!("bad public url: {e}")))?;
        let rp_id = url
            .host_str()
            .ok_or_else(|| Error::Config("public url has no host".into()))?
            .to_string();
        let origin_str = match url.port() {
            Some(p) => format!("{}://{}:{}", url.scheme(), rp_id, p),
            None => format!("{}://{}", url.scheme(), rp_id),
        };
        let origin = Url::parse(&origin_str).map_err(|e| Error::Config(e.to_string()))?;
        let wan = WebauthnBuilder::new(&rp_id, &origin)
            .map_err(Error::Webauthn)?
            .rp_name("terminal-hub")
            .build()
            .map_err(Error::Webauthn)?;
        Ok(Self {
            wan: Arc::new(wan),
            reg_state: Default::default(),
            auth_state: Default::default(),
        })
    }

    // ---------- registration ----------

    pub async fn start_registration(
        &self,
        store: &Store,
        email: &str,
    ) -> Result<(Uuid, CreationChallengeResponse), Error> {
        let user = store.get_user(email).await?.ok_or(Error::NoUser)?;
        let existing: Vec<Passkey> = match &user.passkey_creds {
            Some(b) => serde_json::from_slice(b).unwrap_or_default(),
            None => Vec::new(),
        };
        let exclude: Vec<CredentialID> = existing.iter().map(|p| p.cred_id().clone()).collect();
        let user_id = stable_user_uuid(email);
        let (ccr, reg) = self.wan.start_passkey_registration(
            user_id,
            email,
            email,
            if exclude.is_empty() {
                None
            } else {
                Some(exclude)
            },
        )?;
        let token = Uuid::new_v4();
        let mut g = self.reg_state.lock().await;
        gc(&mut g);
        g.insert(token, (email.to_string(), reg, Instant::now()));
        Ok((token, ccr))
    }

    pub async fn finish_registration(
        &self,
        store: &Store,
        token: Uuid,
        rpkc: &RegisterPublicKeyCredential,
    ) -> Result<(), Error> {
        let (email, reg) = {
            let mut g = self.reg_state.lock().await;
            let (email, reg, t) = g.remove(&token).ok_or(Error::BadState)?;
            if t.elapsed() > STATE_TTL {
                return Err(Error::BadState);
            }
            (email, reg)
        };
        let pk = self.wan.finish_passkey_registration(rpkc, &reg)?;
        let user = store.get_user(&email).await?.ok_or(Error::NoUser)?;
        let mut existing: Vec<Passkey> = match user.passkey_creds {
            Some(b) => serde_json::from_slice(&b).unwrap_or_default(),
            None => Vec::new(),
        };
        existing.push(pk);
        let blob = serde_json::to_vec(&existing)?;
        store.set_passkey_creds(&email, &blob).await?;
        let _ = store.audit(Some(&email), "passkey-register", None).await;
        Ok(())
    }

    // ---------- authentication ----------

    pub async fn start_authentication(
        &self,
        store: &Store,
        email: &str,
    ) -> Result<(Uuid, RequestChallengeResponse), Error> {
        let user = store.get_user(email).await?.ok_or(Error::NoUser)?;
        let creds: Vec<Passkey> = serde_json::from_slice(
            user.passkey_creds.as_deref().ok_or(Error::NoCreds)?,
        )
        .map_err(Error::Json)?;
        if creds.is_empty() {
            return Err(Error::NoCreds);
        }
        let (rcr, st) = self.wan.start_passkey_authentication(&creds)?;
        let token = Uuid::new_v4();
        let mut g = self.auth_state.lock().await;
        gc(&mut g);
        g.insert(token, (email.to_string(), st, Instant::now()));
        Ok((token, rcr))
    }

    pub async fn finish_authentication(
        &self,
        store: &Store,
        token: Uuid,
        pkc: &PublicKeyCredential,
    ) -> Result<String, Error> {
        let (email, st) = {
            let mut g = self.auth_state.lock().await;
            let (email, st, t) = g.remove(&token).ok_or(Error::BadState)?;
            if t.elapsed() > STATE_TTL {
                return Err(Error::BadState);
            }
            (email, st)
        };
        let result = self.wan.finish_passkey_authentication(pkc, &st)?;
        // Update counters in stored creds.
        let user = store.get_user(&email).await?.ok_or(Error::NoUser)?;
        let mut creds: Vec<Passkey> = serde_json::from_slice(
            user.passkey_creds.as_deref().ok_or(Error::NoCreds)?,
        )?;
        for c in creds.iter_mut() {
            c.update_credential(&result);
        }
        let blob = serde_json::to_vec(&creds)?;
        store.set_passkey_creds(&email, &blob).await?;
        let _ = store.audit(Some(&email), "passkey-login", None).await;
        Ok(email)
    }
}

/// Deterministic user-handle UUID, derived from the email.
fn stable_user_uuid(email: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, email.as_bytes())
}

fn gc<V>(map: &mut HashMap<Uuid, (String, V, Instant)>) {
    map.retain(|_, (_, _, t)| t.elapsed() <= STATE_TTL);
}
