//! Outbound federation: this instance talking to its configured peers.
//!
//! Lazy connections — we don't hold persistent sockets to peers. On demand,
//! we run the handshake (or reuse a cached peer-token if still valid) and
//! issue HTTP calls (and later WS upgrades) against the peer.
//!
//! Per-peer state lives in the `Registry`; cached peer-tokens carry a ~5-min
//! TTL.

use crate::peer::identity::PeerIdentity;
use crate::peer::outbound::{PeerEntry, PeersConfig};
use crate::peer::pinned_client;
use crate::sessions::SessionInfo;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const TOKEN_TTL: Duration = Duration::from_secs(270); // just under server's 300s

#[derive(Debug, Clone, Serialize)]
pub enum FetchResult {
    Ok(Vec<SessionInfo>),
    Unreachable(String),
}

#[derive(Clone)]
pub struct FederationClient {
    inner: Arc<Inner>,
}

struct Inner {
    identity: PeerIdentity,
    registry: RwLock<Vec<PeerEntry>>,
    tokens: RwLock<HashMap<String, (String, Instant)>>,
}

impl FederationClient {
    pub fn new(identity: PeerIdentity, registry: PeersConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                identity,
                registry: RwLock::new(registry.peers),
                tokens: RwLock::new(HashMap::new()),
            }),
        }
    }

    pub async fn peers(&self) -> Vec<PeerEntry> {
        self.inner.registry.read().await.clone()
    }

    pub async fn replace_registry(&self, peers: Vec<PeerEntry>) {
        *self.inner.registry.write().await = peers;
        self.inner.tokens.write().await.clear();
    }

    async fn cached_token(&self, friendly_name: &str) -> Option<String> {
        let g = self.inner.tokens.read().await;
        let (token, exp) = g.get(friendly_name)?;
        if Instant::now() > *exp {
            return None;
        }
        Some(token.clone())
    }

    async fn store_token(&self, friendly_name: &str, token: String) {
        self.inner.tokens.write().await.insert(
            friendly_name.to_string(),
            (token, Instant::now() + TOKEN_TTL),
        );
    }

    async fn evict_token(&self, friendly_name: &str) {
        self.inner.tokens.write().await.remove(friendly_name);
    }

    pub async fn peer_by_name(&self, friendly_name: &str) -> Option<PeerEntry> {
        self.inner
            .registry
            .read()
            .await
            .iter()
            .find(|p| p.friendly_name == friendly_name)
            .cloned()
    }

    async fn handshake(&self, peer: &PeerEntry) -> Result<String, FetchError> {
        let client = pinned_client::build_client(&peer.peer_pubkey, &peer.tls_cert_fp);
        let base = peer.url.trim_end_matches('/');
        let me_pub = self.inner.identity.pub_b64().to_string();

        let chal: ChallengeResp = client
            .post(format!("{base}/peer/challenge"))
            .json(&ChallengeReq { pubkey_b64: me_pub.clone() })
            .send()
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| FetchError::Status(e.to_string()))?
            .json()
            .await
            .map_err(|e| FetchError::Decode(e.to_string()))?;
        let challenge = B64URL
            .decode(&chal.challenge_b64)
            .map_err(|e| FetchError::Decode(e.to_string()))?;

        let sig = self.inner.identity.sign(&challenge);
        let sig_b64 = B64URL.encode(sig.to_bytes());

        let auth: AuthResp = client
            .post(format!("{base}/peer/auth"))
            .json(&AuthReq {
                pubkey_b64: me_pub,
                signature_b64: sig_b64,
            })
            .send()
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| FetchError::Status(e.to_string()))?
            .json()
            .await
            .map_err(|e| FetchError::Decode(e.to_string()))?;
        Ok(auth.peer_token)
    }

    async fn token_for(&self, peer: &PeerEntry) -> Result<String, FetchError> {
        if let Some(t) = self.cached_token(&peer.friendly_name).await {
            return Ok(t);
        }
        let t = self.handshake(peer).await?;
        self.store_token(&peer.friendly_name, t.clone()).await;
        Ok(t)
    }

    pub async fn fetch_sessions(&self, friendly_name: &str) -> Result<Vec<SessionInfo>, FetchError> {
        let peer = self
            .peer_by_name(friendly_name)
            .await
            .ok_or_else(|| FetchError::UnknownPeer(friendly_name.to_string()))?;
        match self.fetch_sessions_once(&peer).await {
            Err(FetchError::Status(s)) if s.contains("401") => {
                self.evict_token(friendly_name).await;
                self.fetch_sessions_once(&peer).await
            }
            other => other,
        }
    }

    async fn fetch_sessions_once(&self, peer: &PeerEntry) -> Result<Vec<SessionInfo>, FetchError> {
        let token = self.token_for(peer).await?;
        let client = pinned_client::build_client(&peer.peer_pubkey, &peer.tls_cert_fp);
        let base = peer.url.trim_end_matches('/');
        let resp: ListResp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", format!("PeerToken {token}"))
            .send()
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| FetchError::Status(e.to_string()))?
            .json()
            .await
            .map_err(|e| FetchError::Decode(e.to_string()))?;
        Ok(resp.sessions)
    }

    pub async fn fetch_all(&self) -> Vec<(String, FetchResult)> {
        let peers = self.peers().await;
        let futs = peers.into_iter().map(|p| {
            let me = self.clone();
            async move {
                let res = match me.fetch_sessions(&p.friendly_name).await {
                    Ok(v) => FetchResult::Ok(v),
                    Err(e) => FetchResult::Unreachable(e.to_string()),
                };
                (p.friendly_name, res)
            }
        });
        futures_util::future::join_all(futs).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("unknown peer: {0}")]
    UnknownPeer(String),
    #[error("network: {0}")]
    Network(String),
    #[error("status: {0}")]
    Status(String),
    #[error("decode: {0}")]
    Decode(String),
}

#[derive(Serialize, Deserialize)]
struct ChallengeReq {
    pubkey_b64: String,
}
#[derive(Serialize, Deserialize)]
struct ChallengeResp {
    challenge_b64: String,
}
#[derive(Serialize, Deserialize)]
struct AuthReq {
    pubkey_b64: String,
    signature_b64: String,
}
#[derive(Serialize, Deserialize)]
struct AuthResp {
    peer_token: String,
}
#[derive(Serialize, Deserialize)]
struct ListResp {
    sessions: Vec<SessionInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_registry_fetches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let id = PeerIdentity::ensure(dir.path()).unwrap();
        let fc = FederationClient::new(id, PeersConfig::default());
        let all = fc.fetch_all().await;
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn unknown_peer_name_errors() {
        let dir = tempfile::tempdir().unwrap();
        let id = PeerIdentity::ensure(dir.path()).unwrap();
        let fc = FederationClient::new(id, PeersConfig::default());
        let err = fc.fetch_sessions("nope").await.unwrap_err();
        assert!(matches!(err, FetchError::UnknownPeer(_)));
    }

    #[tokio::test]
    async fn replace_registry_clears_cached_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let id = PeerIdentity::ensure(dir.path()).unwrap();
        let fc = FederationClient::new(id, PeersConfig::default());
        fc.store_token("p1", "tok-1".into()).await;
        assert!(fc.cached_token("p1").await.is_some());
        fc.replace_registry(vec![]).await;
        assert!(fc.cached_token("p1").await.is_none());
    }
}
