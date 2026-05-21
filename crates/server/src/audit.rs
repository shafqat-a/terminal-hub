//! Audit log writes. Best-effort by design — never fail the request on a write
//! error, just log it and continue. The spec promises the log is *written*, not
//! consulted; a viewer ships post-MVP.

use crate::db::Store;
use serde_json::Value;

pub async fn log(
    store: &Store,
    user_email: &str,
    action: &str,
    peer_id: Option<&str>,
    session_id: Option<&str>,
    details: Option<Value>,
) {
    let detail_str = details.as_ref().map(|v| v.to_string());
    let res = store
        .audit_full(
            Some(user_email),
            action,
            peer_id,
            session_id,
            detail_str.as_deref(),
        )
        .await;
    if let Err(e) = res {
        tracing::warn!(?e, %action, %user_email, "audit log write failed");
    }
}
