use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::app::SharedState;
use crate::auth;

pub async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

/// Go parity: first X-Forwarded-For element, else peer address host.
///
/// SECURITY: X-Forwarded-For is client-controlled. Rate limiting keyed on it
/// assumes deployment behind a trusted reverse proxy that overwrites the
/// header. Exposed directly, an attacker can rotate XFF values to evade
/// per-IP throttling (same posture as the Go implementation).
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        let first = xff.split(",").next().unwrap_or("").trim();
        if !first.is_empty() {
            return first.to_string();
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_default()
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_secs() as i64
}

pub async fn login(
    State(state): State<SharedState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_ip(&headers, peer.map(|c| c.0));

    let (allowed, retry_after) = state.limiter.allowed(&ip);
    if !allowed {
        let secs = retry_after.as_secs() + 1;
        tracing::warn!("auth: login throttled, ip={ip} retry_after={secs}s");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, secs.to_string())],
            Json(json!({"error": "too many attempts, try again later"})),
        )
            .into_response();
    }

    #[derive(serde::Deserialize)]
    struct LoginRequest {
        #[serde(default)]
        password: String,
    }
    let Ok(req) = serde_json::from_slice::<LoginRequest>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid request");
    };

    if !state.auth.verify_password_async(&req.password).await {
        state.limiter.record_failure(&ip);
        tracing::warn!("auth: failed login attempt, ip={ip}");
        return json_error(StatusCode::UNAUTHORIZED, "invalid password");
    }

    state.limiter.reset(&ip);

    let token = auth::generate_session_token();
    let expires_at = unix_now() + state.cfg.session_timeout.as_secs() as i64;
    if let Err(e) = state.store.add_auth_session(&token, expires_at) {
        tracing::error!("store: failed to persist auth session: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        auth::COOKIE_NAME,
        token,
        state.cfg.session_timeout.as_secs()
    );
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(json!({"success": true, "token": token})),
    )
        .into_response()
}
