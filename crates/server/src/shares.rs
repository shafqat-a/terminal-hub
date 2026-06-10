//! Share link handlers: mint, list, revoke.
//!
//! Go parity notes:
//!
//! **Mint** (`POST /api/sessions/:id/share`):
//!   Go's `HandleMintShare` checks only `mgr.Get(id)` (live sessions in memory).
//!   If the session is not currently running it returns 404 "session not running".
//!   A session that exists only in the store (detached/dead) is rejected.
//!   We match this: `state.manager.get(id).await` -- live only.
//!
//! **Revoke** (`DELETE /api/shares/:id`):
//!   Go's `HandleRevokeShare` calls `st.RevokeShare(id)` which executes
//!   `UPDATE share_links SET revoked=1 WHERE id=?` and does NOT check
//!   rows_affected -- it always returns nil/200 even for unknown ids.
//!   We match this: call `store.revoke_share(id)` and return 200 regardless of
//!   the bool result.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::app::SharedState;
use crate::handlers::json_error;

/// Maximum share TTL regardless of what the caller requests (30 days).
const MAX_SHARE_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

fn share_unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_secs() as i64
}

fn random_hex(n: usize) -> Option<String> {
    let mut buf = vec![0u8; n];
    if rand::thread_rng().try_fill_bytes(&mut buf).is_err() {
        return None;
    }
    Some(hex::encode(buf))
}

fn token_hash(raw_token: &str) -> Vec<u8> {
    Sha256::digest(raw_token.as_bytes()).to_vec()
}

/// POST /api/sessions/:id/share
///
/// Body (optional): `{"ttlSeconds": <u64>}`
/// Response (201): `{id, sessionId, mode, token, path, url, expiresAt}`
///
/// Go parity: session must be live (`mgr.Get` succeeds).  If not found: 404
/// "session not running".  TTL capped at 30 days.
pub async fn mint_share(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    body: Bytes,
) -> Response {
    // Must be a live session (Go checks mgr.Get only -- not store rows).
    if state.manager.get(&session_id).await.is_none() {
        return json_error(StatusCode::NOT_FOUND, "session not running");
    }

    #[derive(serde::Deserialize, Default)]
    struct MintReq {
        #[serde(default, rename = "ttlSeconds")]
        ttl_seconds: u64,
    }
    let req: MintReq = serde_json::from_slice(&body).unwrap_or_default();

    let mut ttl = if req.ttl_seconds > 0 {
        Duration::from_secs(req.ttl_seconds)
    } else {
        state.cfg.share_ttl
    };
    if ttl > MAX_SHARE_TTL {
        ttl = MAX_SHARE_TTL;
    }

    // share id = hex(8 rand bytes) = 16 chars
    // token    = hex(32 rand bytes) = 64 chars
    let Some(share_id) = random_hex(8) else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "token generation failed");
    };
    let Some(raw_token) = random_hex(32) else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "token generation failed");
    };

    let now = share_unix_now();
    let expires_at = now + ttl.as_secs() as i64;
    let hash = token_hash(&raw_token);

    if let Err(e) = state
        .store
        .insert_share(&share_id, &hash, &session_id, "read", now, expires_at)
    {
        tracing::error!("store: insert_share failed: {e}");
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not create share link",
        );
    }

    let path = format!("/s/{raw_token}");
    let url = if state.cfg.public_url.is_empty() {
        path.clone()
    } else {
        format!("{}{path}", state.cfg.public_url)
    };

    (
        StatusCode::CREATED,
        Json(json!({
            "id":        share_id,
            "sessionId": session_id,
            "mode":      "read",
            "token":     raw_token,
            "path":      path,
            "url":       url,
            "expiresAt": expires_at,
        })),
    )
        .into_response()
}

/// GET /api/sessions/:id/shares
///
/// Returns array of share link metadata (token never included).
/// Fields: {id, sessionId, mode, createdAt, expiresAt, revoked}
pub async fn list_shares(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
) -> Response {
    match state.store.list_shares(&session_id) {
        Ok(rows) => {
            let arr: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id":        r.id,
                        "sessionId": r.session_id,
                        "mode":      r.mode,
                        "createdAt": r.created_at,
                        "expiresAt": r.expires_at,
                        "revoked":   r.revoked,
                    })
                })
                .collect();
            (StatusCode::OK, Json(Value::Array(arr))).into_response()
        }
        Err(e) => {
            tracing::error!("store: list_shares failed: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "could not list shares")
        }
    }
}

/// DELETE /api/shares/:id
///
/// Go parity: `RevokeShare` does NOT check rows_affected -- always returns
/// nil (200 success) even for unknown ids. We match this.
pub async fn revoke_share(
    State(state): State<SharedState>,
    Path(share_id): Path<String>,
) -> Response {
    match state.store.revoke_share(&share_id) {
        Ok(_found) => {
            // Go always returns 200 {"success":true} regardless of whether the
            // id existed, matching the fact that Go's RevokeShare ignores rows_affected.
            (StatusCode::OK, Json(json!({"success": true}))).into_response()
        }
        Err(e) => {
            tracing::error!("store: revoke_share failed: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "could not revoke share")
        }
    }
}

/// GET /s/:token — Public share viewer page (no auth required).
///
/// Redeems the token: valid → 200 share.html; invalid/expired/revoked → 404 share_invalid.html.
/// No detail leakage: both states return an HTML page (not JSON), and the
/// 404 page does not reveal whether the token ever existed.
pub async fn share_page(State(state): State<SharedState>, Path(token): Path<String>) -> Response {
    let hash = token_hash(&token);
    let now = share_unix_now();

    if state
        .store
        .redeem_share(&hash, now)
        .unwrap_or(None)
        .is_some()
    {
        crate::assets::serve_substituted("templates/share.html", "", axum::http::StatusCode::OK)
    } else {
        crate::assets::serve_substituted(
            "templates/share_invalid.html",
            "",
            axum::http::StatusCode::NOT_FOUND,
        )
    }
}
