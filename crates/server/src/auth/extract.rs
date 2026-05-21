//! Request-extractor types layered on top of the cookie middleware.
//!
//! The middleware in `auth::middleware::require_session` validates the
//! `th_session` cookie and stashes an `AuthUser` in request extensions.
//! Handlers pull it out via these axum extractors:
//!
//! - `AuthUser` — the authenticated email (any role).
//! - `RequirePrimary` — same, but 403s if the user's role is `secondary`.

use crate::permissions::{lookup_role, Role};
use crate::AppState;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub email: String,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "not authenticated"))
    }
}

/// Wraps `AuthUser` and rejects with 403 if the user is not the primary.
pub struct RequirePrimary(pub String);

#[axum::async_trait]
impl FromRequestParts<AppState> for RequirePrimary {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser { email } = AuthUser::from_request_parts(parts, state).await?;
        match lookup_role(&state.auth.store, &email).await {
            Ok(Role::Primary) => Ok(RequirePrimary(email)),
            Ok(Role::Secondary) => Err((StatusCode::FORBIDDEN, "primary only")),
            Err(_) => Err((StatusCode::UNAUTHORIZED, "unknown user")),
        }
    }
}
