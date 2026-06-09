use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use crate::auth::ratelimit::RateLimiter;
use crate::auth::AuthService;
use crate::config::Config;
use crate::handlers;

pub struct AppState {
    pub cfg: Config,
    pub auth: AuthService,
    pub limiter: RateLimiter,
    pub store: store::Store,
}

pub type SharedState = Arc<AppState>;

pub fn build_state(cfg: Config) -> SharedState {
    let auth = AuthService::new(&cfg.password);
    let limiter = RateLimiter::new(cfg.login_max_attempts, cfg.login_window, cfg.login_lockout);
    let db_path = cfg.data_dir.join("conductor.db");
    let store = store::Store::open(&db_path).expect("cannot open store");
    Arc::new(AppState {
        cfg,
        auth,
        limiter,
        store,
    })
}

pub fn build_app(state: SharedState) -> Router {
    Router::new()
        .route("/api/health", get(handlers::health))
        .with_state(state)
}

#[cfg(test)]
pub mod test_support {
    use super::*;

    /// App over a throwaway temp data dir; returns the dir to keep it alive.
    pub fn test_app() -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::from_lookup(|key| match key {
            "AI_CONDUCTOR_DATA_DIR" => Some(dir.path().display().to_string()),
            "AI_CONDUCTOR_PASSWORD" => Some("testpass".into()),
            _ => None,
        })
        .unwrap();
        (build_app(build_state(cfg)), dir)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::test_app;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok_json() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"status": "ok"}));
    }
}
