use crate::auth::{bootstrap, challenge::ChallengeStore, passkey::PasskeySvc, sha256};
use crate::db::Store;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

pub const COOKIE_NAME: &str = "th_session";
const COOKIE_TTL_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Clone)]
pub struct AuthState {
    pub store: Store,
    pub challenge: ChallengeStore,
    pub passkey: Arc<PasskeySvc>,
    pub public_url: String,
}

// ---------- /auth/challenge ----------

#[derive(Deserialize)]
pub struct ChallengeReq {
    pub email: String,
}

#[derive(Serialize)]
pub struct ChallengeResp {
    pub challenge: String,
}

pub async fn post_challenge(
    State(s): State<AuthState>,
    Json(b): Json<ChallengeReq>,
) -> Result<Json<ChallengeResp>, (StatusCode, String)> {
    // Deliberate: don't leak whether the user exists. Still issue a challenge,
    // it just won't verify later.
    let _ = s.store.get_user(&b.email).await.map_err(e500)?;
    let (_raw, b64) = s.challenge.issue(&b.email).await;
    Ok(Json(ChallengeResp { challenge: b64 }))
}

// ---------- /auth/enroll/initiate ----------

#[derive(Deserialize)]
pub struct InitiateReq {
    pub email: String,
    /// b64-URL-no-pad of the 32-byte challenge.
    pub challenge: String,
    /// b64-URL-no-pad of the raw ed25519 signature bytes.
    pub signature: String,
}

#[derive(Serialize)]
pub struct InitiateResp {
    pub bootstrap_url: String,
    pub token: String,
}

pub async fn post_enroll_initiate(
    State(s): State<AuthState>,
    Json(b): Json<InitiateReq>,
) -> Result<Json<InitiateResp>, (StatusCode, String)> {
    let claimed_email = s
        .challenge
        .consume(&b.challenge)
        .await
        .ok_or((StatusCode::UNAUTHORIZED, "unknown or expired challenge".into()))?;
    if claimed_email != b.email {
        return Err((StatusCode::UNAUTHORIZED, "email mismatch".into()));
    }
    let user = s
        .store
        .get_user(&b.email)
        .await
        .map_err(e500)?
        .ok_or((StatusCode::UNAUTHORIZED, "no such user".into()))?;
    let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b.challenge.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b.signature.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    auth_core::verify(&user.pubkey_openssh, &challenge_bytes, &sig)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "signature verification failed".into()))?;

    let token = bootstrap::mint(&s.store, &b.email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = s.store.audit(Some(&b.email), "enroll-initiate", None).await;
    let mut url = s.public_url.trim_end_matches('/').to_string();
    url.push_str("/enroll.html?t=");
    url.push_str(&token);
    Ok(Json(InitiateResp {
        bootstrap_url: url,
        token,
    }))
}

// ---------- /auth/passkey/register/start ----------

#[derive(Deserialize)]
pub struct StartRegQuery {
    pub t: String,
}

#[derive(Serialize)]
pub struct StartRegResp {
    pub registration_id: Uuid,
    pub ccr: serde_json::Value,
}

pub async fn get_passkey_register_start(
    State(s): State<AuthState>,
    Query(q): Query<StartRegQuery>,
) -> Result<Json<StartRegResp>, (StatusCode, String)> {
    let email = bootstrap::redeem(&s.store, &q.t)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid bootstrap token".into()))?;
    let (id, ccr) = s
        .passkey
        .start_registration(&s.store, &email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(StartRegResp {
        registration_id: id,
        ccr: serde_json::to_value(ccr).unwrap(),
    }))
}

// ---------- /auth/passkey/register/finish ----------

#[derive(Deserialize)]
pub struct FinishRegReq {
    pub registration_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

pub async fn post_passkey_register_finish(
    State(s): State<AuthState>,
    Json(b): Json<FinishRegReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    s.passkey
        .finish_registration(&s.store, b.registration_id, &b.credential)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- /auth/passkey/login/start ----------

#[derive(Deserialize)]
pub struct StartLoginReq {
    pub email: String,
}

#[derive(Serialize)]
pub struct StartLoginResp {
    pub auth_id: Uuid,
    pub rcr: serde_json::Value,
}

pub async fn post_passkey_login_start(
    State(s): State<AuthState>,
    Json(b): Json<StartLoginReq>,
) -> Result<Json<StartLoginResp>, (StatusCode, String)> {
    let (id, rcr) = s
        .passkey
        .start_authentication(&s.store, &b.email)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok(Json(StartLoginResp {
        auth_id: id,
        rcr: serde_json::to_value(rcr).unwrap(),
    }))
}

// ---------- /auth/passkey/login/finish ----------

#[derive(Deserialize)]
pub struct FinishLoginReq {
    pub auth_id: Uuid,
    pub credential: PublicKeyCredential,
}

pub async fn post_passkey_login_finish(
    State(s): State<AuthState>,
    cookies: Cookies,
    Json(b): Json<FinishLoginReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let email = s
        .passkey
        .finish_authentication(&s.store, b.auth_id, &b.credential)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let cookie_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    s.store
        .insert_session(&sha256(cookie_value.as_bytes()), &email, COOKIE_TTL_SECS)
        .await
        .map_err(e500)?;
    let mut c = Cookie::new(COOKIE_NAME, cookie_value);
    c.set_http_only(true);
    c.set_secure(true);
    c.set_same_site(cookie::SameSite::Lax);
    c.set_path("/");
    c.set_max_age(cookie::time::Duration::seconds(COOKIE_TTL_SECS));
    cookies.add(c);
    // Spec §7: log every successful login via the unified M4 audit helper so
    // peer_id / session_id columns stay populated (NULL here, but consistent
    // shape with attach/create/kill rows).
    crate::audit::log(&s.store, &email, "login", None, None, None).await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- /auth/logout ----------

pub async fn post_logout(
    State(s): State<AuthState>,
    cookies: Cookies,
) -> Result<StatusCode, (StatusCode, String)> {
    if let Some(c) = cookies.get(COOKIE_NAME) {
        let _ = s.store.delete_session(&sha256(c.value().as_bytes())).await;
        let mut clear = Cookie::new(COOKIE_NAME, "");
        clear.set_path("/");
        clear.set_max_age(cookie::time::Duration::seconds(0));
        cookies.add(clear);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn e500<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
