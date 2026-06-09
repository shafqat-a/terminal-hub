//! Session-token gate. Token lookup order (Go parity):
//! X-Session-Token header -> ?token= query param -> cookie.

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};

use super::COOKIE_NAME;
use crate::app::SharedState;

fn token_from_request(req: &Request) -> Option<String> {
    if let Some(h) = req
        .headers()
        .get("X-Session-Token")
        .and_then(|v| v.to_str().ok())
    {
        if !h.is_empty() {
            return Some(h.to_string());
        }
    }
    // NOTE: query values are used raw, not percent-decoded. Tokens are 64
    // lowercase hex chars (no reserved characters); revisit if the format
    // ever changes.
    if let Some(query) = req.uri().query() {
        for pair in query.split("&") {
            if let Some(value) = pair.strip_prefix("token=") {
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    let cookies = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    let prefix = format!("{COOKIE_NAME}=");
    for cookie in cookies.split(';') {
        if let Some(value) = cookie.trim().strip_prefix(&prefix) {
            return Some(value.to_string());
        }
    }
    None
}

fn is_api_request(req: &Request) -> bool {
    let path = req.uri().path();
    path.starts_with("/api") || path.starts_with("/ws")
}

pub async fn require_auth(State(state): State<SharedState>, req: Request, next: Next) -> Response {
    let now = crate::handlers::unix_now();
    let valid = token_from_request(&req)
        .map(|t| state.store.validate_auth_session(&t, now).unwrap_or(false))
        .unwrap_or(false);

    if !valid {
        return if is_api_request(&req) {
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "unauthorized"})),
            )
                .into_response()
        } else {
            Redirect::to("/").into_response()
        };
    }
    next.run(req).await
}
