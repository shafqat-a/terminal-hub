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

// ---------------- M4 user/permission admin endpoints ----------------

use crate::auth::extract::RequirePrimary;
use crate::permissions::{
    list_grants, revoke as perm_revoke, set_peer_create_allowed, GrantRow,
};
use crate::users;

pub async fn users_list(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let role = permissions::lookup_role(&s.auth.store, &email)
        .await
        .map_err(perm500)?;
    let all = users::list(&s.auth.store).await.map_err(users500)?;
    let filtered: Vec<_> = match role {
        permissions::Role::Primary => all,
        permissions::Role::Secondary => all.into_iter().filter(|u| u.email == email).collect(),
    };
    Ok(Json(serde_json::json!({ "users": filtered })))
}

pub async fn users_add(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Json(body): Json<users::AddUserBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let row = users::add_secondary(&s.auth.store, &body.email, &body.pubkey)
        .await
        .map_err(users500)?;
    audit::log(
        &s.auth.store,
        &actor,
        "add-user",
        None,
        None,
        Some(serde_json::json!({ "added": body.email })),
    )
    .await;
    Ok(Json(serde_json::json!({ "user": row })))
}

pub async fn users_remove(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Path(email): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    users::remove(&s.auth.store, &email)
        .await
        .map_err(users500)?;
    audit::log(
        &s.auth.store,
        &actor,
        "remove-user",
        None,
        None,
        Some(serde_json::json!({ "removed": email })),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn perm_list(
    RequirePrimary(_): RequirePrimary,
    State(s): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let id = parse_id(&session_id)?;
    let grants: Vec<GrantRow> = list_grants(&s.auth.store, LOCAL, &id)
        .await
        .map_err(perm500)?;
    Ok(Json(serde_json::json!({ "grants": grants })))
}

#[derive(Deserialize)]
pub struct GrantBody {
    pub user_email: String,
    pub capabilities: u32,
}

pub async fn perm_grant(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Path(session_id): Path<String>,
    Json(body): Json<GrantBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = parse_id(&session_id)?;
    permissions::grant(
        &s.auth.store,
        &body.user_email,
        LOCAL,
        &id,
        Capabilities(body.capabilities),
        &actor,
    )
    .await
    .map_err(perm500)?;
    audit::log(
        &s.auth.store,
        &actor,
        "grant",
        Some(LOCAL),
        Some(&id.to_string()),
        Some(serde_json::json!({
            "user_email": body.user_email,
            "capabilities": body.capabilities,
        })),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn perm_revoke_handler(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Path((session_id, user_email)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let id = parse_id(&session_id)?;
    perm_revoke(&s.auth.store, &user_email, LOCAL, &id)
        .await
        .map_err(perm500)?;
    audit::log(
        &s.auth.store,
        &actor,
        "revoke",
        Some(LOCAL),
        Some(&id.to_string()),
        Some(serde_json::json!({ "user_email": user_email })),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PeerCreateBody {
    pub user_email: String,
    pub peer_id: String,
    pub allow: bool,
}

pub async fn peer_create_toggle(
    RequirePrimary(actor): RequirePrimary,
    State(s): State<AppState>,
    Json(body): Json<PeerCreateBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    if body.peer_id != "local" {
        // M4 is local-only; federation in M5.
        return Err((
            StatusCode::BAD_REQUEST,
            "only peer_id=local supported in M4".into(),
        ));
    }
    set_peer_create_allowed(
        &s.auth.store,
        &body.user_email,
        &body.peer_id,
        body.allow,
        &actor,
    )
    .await
    .map_err(perm500)?;
    audit::log(
        &s.auth.store,
        &actor,
        "peer-create-toggle",
        Some(&body.peer_id),
        None,
        Some(serde_json::json!({
            "user_email": body.user_email,
            "allow": body.allow,
        })),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

fn users500(e: users::Error) -> (StatusCode, String) {
    let code = match &e {
        users::Error::AlreadyExists(_) => StatusCode::CONFLICT,
        users::Error::NoPrimary => StatusCode::PRECONDITION_FAILED,
        users::Error::RemovingPrimary => StatusCode::FORBIDDEN,
        users::Error::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, e.to_string())
}

/// `GET /api/me` — return the calling user's email and role. The frontend uses
/// this to decide whether to render the share / admin affordances; the server
/// still enforces every action via `RequirePrimary` regardless.
pub async fn me(
    AuthUser { email }: AuthUser,
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let role = match permissions::lookup_role(&s.auth.store, &email).await {
        Ok(permissions::Role::Primary) => "primary",
        Ok(permissions::Role::Secondary) => "secondary",
        Err(e) => return Err(perm500(e)),
    };
    Ok(Json(serde_json::json!({ "email": email, "role": role })))
}
