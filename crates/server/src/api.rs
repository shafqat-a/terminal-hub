use crate::session_id::SessionId;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

#[derive(Deserialize)] pub struct CreateBody { pub display_name: String }
#[derive(Deserialize)] pub struct RenameBody { pub display_name: String }

pub async fn list(State(s): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let v = s.mgr.list().await.map_err(e500)?;
    Ok(Json(serde_json::json!({ "sessions": v })))
}
pub async fn create(State(s): State<AppState>, Json(b): Json<CreateBody>)
    -> Result<Json<serde_json::Value>, (StatusCode, String)>
{
    let v = s.mgr.create(&b.display_name, "local").await.map_err(e500)?;
    Ok(Json(serde_json::json!({ "session": v })))
}
pub async fn rename(State(s): State<AppState>, Path(id): Path<String>, Json(b): Json<RenameBody>)
    -> Result<StatusCode, (StatusCode, String)>
{
    let id = parse_id(&id)?;
    s.mgr.rename(&id, &b.display_name).await.map_err(e500)?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn kill(State(s): State<AppState>, Path(id): Path<String>)
    -> Result<StatusCode, (StatusCode, String)>
{
    let id = parse_id(&id)?;
    s.mgr.kill(&id).await.map_err(e500)?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_id(s: &str) -> Result<SessionId, (StatusCode, String)> {
    uuid::Uuid::parse_str(s).map(SessionId).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}
fn e500(e: crate::sessions::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
