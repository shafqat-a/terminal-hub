//! Peer-to-peer auth handshake.
//!
//! Two endpoints, both under `/peer/*` (cookie-middleware-exempt):
//!
//! 1. `POST /peer/challenge { pubkey_b64 }` → `{ challenge_b64 }`
//!    Returns 32 random bytes (URL_SAFE_NO_PAD) to be signed with the peer's
//!    ed25519 private key. Stored in-memory keyed by pubkey, 5-min TTL.
//!    Refuses unknown pubkeys with 401 (cheap pre-flight).
//!
//! 2. `POST /peer/auth { pubkey_b64, signature_b64 }` → `{ peer_token }`
//!    Verifies the signature on the prior challenge; on success returns a
//!    random 32-byte hex token with 5-min TTL.
//!
//! Subsequent peer calls present the token as `Authorization: PeerToken <hex>`.
//! The `require_peer_token` middleware validates it and stashes
//! `PeerCaller(friendly_name)` into the request extensions.

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::peer::identity::PeerIdentity;
use crate::peer::inbound::AuthorizedPeers;
use crate::AppState;

const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const TOKEN_TTL: Duration = Duration::from_secs(300);

type ChallengeMap = HashMap<String, (Vec<u8>, Instant)>;
type TokenMap = HashMap<String, (String, Instant)>;

/// Per-instance handshake state. Cloneable (cheap — all Arc/Mutex inside).
#[derive(Clone)]
pub struct PeerHandshakeState {
    pub authorized: Arc<AuthorizedPeers>,
    challenges: Arc<Mutex<ChallengeMap>>,
    tokens: Arc<Mutex<TokenMap>>,
}

impl PeerHandshakeState {
    pub fn new(authorized: AuthorizedPeers) -> Self {
        Self {
            authorized: Arc::new(authorized),
            challenges: Arc::new(Mutex::new(HashMap::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn mint_challenge(&self, pubkey_b64: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let mut g = self.challenges.lock().unwrap();
        g.insert(
            pubkey_b64.to_string(),
            (buf.clone(), Instant::now() + CHALLENGE_TTL),
        );
        buf
    }

    fn take_challenge(&self, pubkey_b64: &str) -> Option<Vec<u8>> {
        let mut g = self.challenges.lock().unwrap();
        let (bytes, exp) = g.remove(pubkey_b64)?;
        if Instant::now() > exp {
            return None;
        }
        Some(bytes)
    }

    fn mint_token(&self, friendly_name: &str) -> String {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let hex = buf.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut g = self.tokens.lock().unwrap();
        g.insert(
            hex.clone(),
            (friendly_name.to_string(), Instant::now() + TOKEN_TTL),
        );
        hex
    }

    fn lookup_token(&self, token: &str) -> Option<String> {
        let g = self.tokens.lock().unwrap();
        let (name, exp) = g.get(token)?;
        if Instant::now() > *exp {
            return None;
        }
        Some(name.clone())
    }
}

#[derive(Clone, Debug)]
pub struct PeerCaller(pub String);

#[derive(Deserialize)]
pub struct ChallengeReq {
    pub pubkey_b64: String,
}

#[derive(Serialize)]
pub struct ChallengeResp {
    pub challenge_b64: String,
}

#[derive(Deserialize)]
pub struct AuthReq {
    pub pubkey_b64: String,
    pub signature_b64: String,
}

#[derive(Serialize)]
pub struct AuthResp {
    pub peer_token: String,
}

pub async fn post_challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeReq>,
) -> Result<Json<ChallengeResp>, (StatusCode, &'static str)> {
    let hs = &state.peer_handshake;
    if !hs.authorized.contains_key(&req.pubkey_b64) {
        return Err((StatusCode::UNAUTHORIZED, "unknown peer pubkey"));
    }
    let buf = hs.mint_challenge(&req.pubkey_b64);
    Ok(Json(ChallengeResp {
        challenge_b64: B64URL.encode(buf),
    }))
}

pub async fn post_auth(
    State(state): State<AppState>,
    Json(req): Json<AuthReq>,
) -> Result<Json<AuthResp>, (StatusCode, &'static str)> {
    let hs = &state.peer_handshake;
    let peer = hs
        .authorized
        .get(&req.pubkey_b64)
        .ok_or((StatusCode::UNAUTHORIZED, "unknown peer pubkey"))?;
    let challenge = hs
        .take_challenge(&req.pubkey_b64)
        .ok_or((StatusCode::UNAUTHORIZED, "no active challenge"))?;
    let pubkey_bytes = B64URL
        .decode(&req.pubkey_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&req.pubkey_b64))
        .map_err(|_| (StatusCode::BAD_REQUEST, "pubkey not valid base64"))?;
    let sig_bytes = B64URL
        .decode(&req.signature_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&req.signature_b64))
        .map_err(|_| (StatusCode::BAD_REQUEST, "signature not valid base64"))?;
    PeerIdentity::verify(&pubkey_bytes, &challenge, &sig_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "signature failed verification"))?;
    let token = hs.mint_token(&peer.friendly_name);
    Ok(Json(AuthResp { peer_token: token }))
}

pub async fn require_peer_token(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let header_val = match req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v,
        None => return (StatusCode::UNAUTHORIZED, "missing Authorization header").into_response(),
    };
    let token = match header_val.strip_prefix("PeerToken ") {
        Some(t) => t.trim(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "Authorization must be `PeerToken <hex>`",
            )
                .into_response()
        }
    };
    let name = match state.peer_handshake.lookup_token(token) {
        Some(n) => n,
        None => return (StatusCode::UNAUTHORIZED, "invalid or expired peer token").into_response(),
    };
    req.extensions_mut().insert(PeerCaller(name));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::inbound::AuthorizedPeer;

    fn one_peer(id: &PeerIdentity) -> AuthorizedPeers {
        let mut m = AuthorizedPeers::new();
        m.insert(
            id.pub_b64().to_string(),
            AuthorizedPeer {
                pubkey_b64: id.pub_b64().to_string(),
                friendly_name: "test-peer".into(),
                tls_cert_fp: "aaaa:bbbb:cccc".into(),
            },
        );
        m
    }

    #[test]
    fn challenge_then_verify_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let id = PeerIdentity::ensure(dir.path()).unwrap();
        let hs = PeerHandshakeState::new(one_peer(&id));

        let challenge = hs.mint_challenge(id.pub_b64());
        let sig = id.sign(&challenge);
        let consumed = hs.take_challenge(id.pub_b64()).unwrap();
        assert_eq!(consumed, challenge);
        assert!(PeerIdentity::verify(&id.pub_bytes(), &challenge, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn unknown_peer_pubkey_not_in_authorized() {
        let dir_known = tempfile::tempdir().unwrap();
        let dir_unknown = tempfile::tempdir().unwrap();
        let known = PeerIdentity::ensure(dir_known.path()).unwrap();
        let unknown = PeerIdentity::ensure(dir_unknown.path()).unwrap();
        let hs = PeerHandshakeState::new(one_peer(&known));
        assert!(!hs.authorized.contains_key(unknown.pub_b64()));
    }

    #[test]
    fn token_lookup_returns_friendly_name() {
        let dir = tempfile::tempdir().unwrap();
        let id = PeerIdentity::ensure(dir.path()).unwrap();
        let hs = PeerHandshakeState::new(one_peer(&id));
        let token = hs.mint_token("prod-box");
        assert_eq!(hs.lookup_token(&token).as_deref(), Some("prod-box"));
        assert!(hs.lookup_token("bogus").is_none());
    }

    #[test]
    fn expired_challenge_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let id = PeerIdentity::ensure(dir.path()).unwrap();
        let hs = PeerHandshakeState::new(one_peer(&id));
        hs.challenges.lock().unwrap().insert(
            id.pub_b64().to_string(),
            (vec![0; 32], Instant::now() - Duration::from_secs(1)),
        );
        assert!(hs.take_challenge(id.pub_b64()).is_none());
    }
}
