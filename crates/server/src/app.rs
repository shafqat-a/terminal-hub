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
    tracing::debug!(shell = %cfg.shell, "session shell configured");
    Arc::new(AppState {
        cfg,
        auth,
        limiter,
        store,
    })
}

pub fn build_app(state: SharedState) -> Router {
    let protected = Router::new()
        .route("/terminal", get(|| async { "terminal placeholder (M2)" }))
        .route(
            "/api/sessions",
            get(|| async { axum::Json(serde_json::json!([])) }),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::middleware::require_auth,
        ));

    Router::new()
        .route("/", get(crate::assets::login_page))
        .route("/static/*path", get(crate::assets::static_file))
        .route("/api/health", get(handlers::health))
        .route("/api/login", post(handlers::login))
        .merge(protected)
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

    async fn obtain_token(app: &axum::Router) -> String {
        let res = login(app.clone(), r#"{"password":"testpass"}"#, None).await;
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        v["token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn terminal_without_token_redirects_to_login() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/terminal").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER); // axum Redirect::to = 303
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/");
    }

    #[tokio::test]
    async fn api_without_token_gets_401_json() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/api/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "unauthorized"}));
    }

    #[tokio::test]
    async fn header_token_grants_access() {
        let (app, _dir) = test_app();
        let token = obtain_token(&app).await;
        let res = app
            .oneshot(
                Request::get("/terminal")
                    .header("X-Session-Token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn query_token_grants_access() {
        let (app, _dir) = test_app();
        let token = obtain_token(&app).await;
        let res = app
            .oneshot(
                Request::get(format!("/terminal?token={token}").as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cookie_token_grants_access() {
        let (app, _dir) = test_app();
        let token = obtain_token(&app).await;
        let res = app
            .oneshot(
                Request::get("/terminal")
                    .header(header::COOKIE, format!("ai_conductor_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn garbage_token_is_rejected() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(
                Request::get("/terminal")
                    .header("X-Session-Token", "deadbeef")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn expired_token_is_rejected_by_middleware() {
        let (app, dir) = test_app();
        // Plant an already-expired session directly in the same DB file.
        let db = store::Store::open(&dir.path().join("conductor.db")).unwrap();
        db.add_auth_session("expiredtoken", 1).unwrap(); // expired long ago
        let res = app
            .oneshot(
                Request::get("/terminal")
                    .header("X-Session-Token", "expiredtoken")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn root_serves_login_page() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.starts_with("text/html"));
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("/api/login"),
            "login page must reference the login API"
        );
        assert!(
            html.contains("/terminal"),
            "login page must navigate to /terminal on success"
        );
        assert!(
            !html.contains("{{"),
            "no Go template directives may survive the port"
        );
        assert!(
            !html.contains("BASE_PATH"),
            "no dangling BASE_PATH references"
        );
    }

    #[tokio::test]
    async fn static_css_is_served_with_mime() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(
                Request::get("/static/css/style.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.starts_with("text/css"));
    }

    #[tokio::test]
    async fn unknown_static_path_is_404() {
        let (app, _dir) = test_app();
        let res = app
            .oneshot(Request::get("/static/nope.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
