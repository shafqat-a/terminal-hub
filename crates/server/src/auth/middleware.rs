//! Cookie middleware. Public routes (login.html, enroll.html, /healthz, anything
//! under /auth/) are exempt; everything else returns 401 if there's no valid cookie.

use crate::auth::{routes::COOKIE_NAME, sha256};
use crate::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use tower_cookies::Cookies;

pub async fn require_session(
    State(state): State<AppState>,
    cookies: Cookies,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    if is_public(&path) {
        return next.run(req).await;
    }
    let Some(cookie) = cookies.get(COOKIE_NAME) else {
        return unauth(&path);
    };
    let hash = sha256(cookie.value().as_bytes());
    match state.auth.store.lookup_session(&hash).await {
        Ok(Some(_)) => next.run(req).await,
        _ => unauth(&path),
    }
}

fn is_public(path: &str) -> bool {
    path == "/healthz"
        || path == "/login.html"
        || path == "/enroll.html"
        || path == "/app.css"
        || path == "/auth.css"
        || path == "/login.js"
        || path == "/enroll.js"
        || path.starts_with("/auth/")
}

fn unauth(path: &str) -> Response {
    // For HTML page requests, redirect to login. For API / WS, return 401.
    if path.starts_with("/api/") || path.starts_with("/ws/") {
        (StatusCode::UNAUTHORIZED, "auth required").into_response()
    } else {
        Redirect::to("/login.html").into_response()
    }
}
