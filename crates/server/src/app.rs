use std::sync::Arc;

use axum::routing::{get, post};
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
    let store = store::Store::open(&db_path)
        .unwrap_or_else(|e| panic!("cannot open store at {}: {e}", db_path.display()));
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
        .route("/api/login", post(handlers::login))
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

    use axum::http::header;

    async fn login(
        app: axum::Router,
        body: &str,
        xff: Option<&str>,
    ) -> axum::http::Response<axum::body::Body> {
        let mut req = Request::post("/api/login").header(header::CONTENT_TYPE, "application/json");
        if let Some(ip) = xff {
            req = req.header("X-Forwarded-For", ip);
        }
        app.oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn login_success_returns_token_and_cookie() {
        let (app, _dir) = test_app();
        let res = login(app, r#"{"password":"testpass"}"#, None).await;
        assert_eq!(res.status(), StatusCode::OK);
        let cookie = res
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.starts_with("ai_conductor_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["success"], true);
        assert_eq!(v["token"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn login_wrong_password_is_401() {
        let (app, _dir) = test_app();
        let res = login(app, r#"{"password":"nope"}"#, None).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "invalid password"}));
    }

    #[tokio::test]
    async fn login_malformed_json_is_400() {
        let (app, _dir) = test_app();
        let res = login(app, "{not json", None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "invalid request"}));
    }

    #[tokio::test]
    async fn login_throttles_after_max_attempts_with_retry_after() {
        let (app, _dir) = test_app(); // default max_attempts = 5
        for _ in 0..5 {
            let res = login(app.clone(), r#"{"password":"nope"}"#, Some("10.1.1.7")).await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
        let res = login(app.clone(), r#"{"password":"testpass"}"#, Some("10.1.1.7")).await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = res
            .headers()
            .get("Retry-After")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(retry >= 1);
        // Different IP is unaffected.
        let res = login(app, r#"{"password":"testpass"}"#, Some("10.9.9.9")).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}
