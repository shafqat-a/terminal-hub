//! Session CRUD endpoints. All gated by the cookie middleware; per-handler
//! ACL checks layer on top.

use crate::audit;
use crate::auth::extract::AuthUser;
use crate::permissions::{
    self, effective_caps, peer_create_allowed, visible_sessions, Capabilities,
};
use crate::session_id::SessionId;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::collections::HashSet;

pub(crate) const LOCAL: &str = "local";

#[derive(Deserialize)]
pub struct CreateBody {
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct RenameBody {
    pub display_name: String,
}

pub async fn list(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let all = s.mgr.list().await.map_err(e500)?;
    let filtered = match visible_sessions(&s.auth.store, &email, LOCAL)
        .await
        .map_err(perm500)?
    {
        None => all, // primary
        Some(ids) => {
            let allowed: HashSet<SessionId> = ids.into_iter().collect();
            all.into_iter()
                .filter(|si| allowed.contains(&si.id))
                .collect()
        }
    };
    Ok(Json(serde_json::json!({ "sessions": filtered })))
}

pub async fn create(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
    Json(b): Json<CreateBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !peer_create_allowed(&s.auth.store, &email, LOCAL)
        .await
        .map_err(perm500)?
    {
        return Err((
            StatusCode::FORBIDDEN,
            "create not allowed on this peer".into(),
        ));
    }
    let info = s.mgr.create(&b.display_name, &email).await.map_err(e500)?;

    // Auto-grant the creator and (if creator is secondary) the primary.
    permissions::grant(
        &s.auth.store,
        &email,
        LOCAL,
        &info.id,
        Capabilities::all_for_owner(),
        &email,
    )
    .await
    .map_err(perm500)?;
    if let Some(primary) = s.auth.store.primary_email().await.map_err(anyhow500)? {
        if primary != email {
            permissions::grant(
                &s.auth.store,
                &primary,
                LOCAL,
                &info.id,
                Capabilities::all_for_owner(),
                &email,
            )
            .await
            .map_err(perm500)?;
        }
    }

    audit::log(
        &s.auth.store,
        &email,
        "create",
        Some(LOCAL),
        Some(&info.id.to_string()),
        Some(serde_json::json!({ "display_name": b.display_name })),
    )
    .await;
    Ok(Json(serde_json::json!({ "session": info })))
}

pub async fn rename(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<RenameBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = parse_id(&id)?;
    require_cap(&s, &email, &id, Capabilities::MANAGE).await?;
    s.mgr.rename(&id, &b.display_name).await.map_err(e500)?;
    audit::log(
        &s.auth.store,
        &email,
        "rename",
        Some(LOCAL),
        Some(&id.to_string()),
        Some(serde_json::json!({ "display_name": b.display_name })),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn kill(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = parse_id(&id)?;
    require_cap(&s, &email, &id, Capabilities::MANAGE).await?;
    s.mgr.kill(&id).await.map_err(e500)?;
    permissions::cascade_session_delete(&s.auth.store, LOCAL, &id)
        .await
        .map_err(perm500)?;
    audit::log(
        &s.auth.store,
        &email,
        "kill",
        Some(LOCAL),
        Some(&id.to_string()),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn require_cap(
    s: &AppState,
    email: &str,
    id: &SessionId,
    cap: Capabilities,
) -> Result<(), (StatusCode, String)> {
    let caps = effective_caps(&s.auth.store, email, LOCAL, id)
        .await
        .map_err(perm500)?;
    if caps.has(cap) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            format!("missing capability {cap:?}"),
        ))
    }
}

pub(crate) fn parse_id(s: &str) -> Result<SessionId, (StatusCode, String)> {
    uuid::Uuid::parse_str(s)
        .map(SessionId)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

fn e500(e: crate::sessions::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub(crate) fn perm500(e: crate::permissions::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub(crate) fn anyhow500(e: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
