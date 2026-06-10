use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
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

pub(crate) fn json_error(status: StatusCode, message: &str) -> Response {
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

    // Cookie path is base_path + "/" so the cookie is scoped to the mount
    // point when the app is served under a reverse-proxy subpath (Go parity).
    let cookie = format!(
        "{}={}; Path={}/; HttpOnly; SameSite=Strict; Max-Age={}",
        auth::COOKIE_NAME,
        token,
        state.cfg.base_path,
        state.cfg.session_timeout.as_secs()
    );
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(json!({"success": true, "token": token})),
    )
        .into_response()
}

// ---- Session CRUD handlers --------------------------------------------------

/// GET /api/sessions → 200 [{id, name, createdAt, status, lastActivityAt,
///                           lastClientDisconnectAt, cols, rows}, ...]
pub async fn sessions_list(State(state): State<SharedState>) -> Response {
    let list = state.manager.list().await;
    (StatusCode::OK, Json(list)).into_response()
}

/// POST /api/sessions → 201 {id, name}
/// Body is optional; decode errors are silently ignored (Go parity).
pub async fn sessions_create(State(state): State<SharedState>, body: Bytes) -> Response {
    #[derive(serde::Deserialize, Default)]
    struct CreateRequest {
        #[serde(default)]
        name: Option<String>,
    }
    let req: CreateRequest = serde_json::from_slice(&body).unwrap_or_default();
    let name = req.name.filter(|n| !n.is_empty());

    match state.manager.create(name).await {
        Ok(sess) => {
            let id = sess.id.clone();
            let name = sess.name.lock().unwrap_or_else(|e| e.into_inner()).clone();
            (StatusCode::CREATED, Json(json!({"id": id, "name": name}))).into_response()
        }
        Err(crate::session::CreateError::SessionLimit) => {
            json_error(StatusCode::TOO_MANY_REQUESTS, "session limit reached")
        }
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// PUT /api/sessions/:id → 200 {success:true} / 400 / 404
pub async fn sessions_rename(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    #[derive(serde::Deserialize)]
    struct RenameRequest {
        #[serde(default)]
        name: String,
    }
    let req: RenameRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "name required"),
    };
    if req.name.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "name required");
    }
    match state.manager.rename(&id, &req.name).await {
        Ok(()) => (StatusCode::OK, Json(json!({"success": true}))).into_response(),
        Err(_) => json_error(StatusCode::NOT_FOUND, &format!("session {id} not found")),
    }
}

/// DELETE /api/sessions/:id → 200 {success:true} / 404
pub async fn sessions_delete(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    match state.manager.delete(&id).await {
        Ok(()) => (StatusCode::OK, Json(json!({"success": true}))).into_response(),
        Err(_) => json_error(StatusCode::NOT_FOUND, &format!("session {id} not found")),
    }
}
