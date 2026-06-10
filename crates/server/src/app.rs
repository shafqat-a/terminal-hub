use std::sync::Arc;
use std::time::Duration;

use axum::routing::{delete, get, post, put};
use axum::Router;

use crate::auth::ratelimit::RateLimiter;
use crate::auth::AuthService;
use crate::config::Config;
use crate::handlers;
use crate::session;
use crate::shares;

pub struct AppState {
    pub cfg: Config,
    pub auth: AuthService,
    pub limiter: RateLimiter,
    pub store: Arc<store::Store>,
    pub manager: session::Manager,
    /// Resolved API key (either from config or auto-generated at startup).
    pub api_key: String,
}

pub type SharedState = Arc<AppState>;

pub async fn build_state(cfg: Config) -> SharedState {
    let auth = AuthService::new(&cfg.password);
    let limiter = RateLimiter::new(cfg.login_max_attempts, cfg.login_window, cfg.login_lockout);
    let db_path = cfg.data_dir.join("conductor.db");
    let store = Arc::new(
        store::Store::open(&db_path)
            .unwrap_or_else(|e| panic!("cannot open store at {}: {e}", db_path.display())),
    );
    let manager = session::Manager::new(
        cfg.data_dir.clone(),
        cfg.shell.clone(),
        Arc::clone(&store),
        cfg.idle_timeout,
        cfg.max_sessions,
        Duration::from_secs(15),
    );

    let api_key = match &cfg.api_key {
        Some(k) => k.clone(),
        None => {
            let key = crate::auth::generate_session_token();
            tracing::info!("API key: {key}");
            key
        }
    };

    let state = Arc::new(AppState {
        cfg,
        auth,
        limiter,
        store,
        manager,
        api_key,
    });

    state.manager.init().await;

    state
}

pub fn build_app(state: SharedState) -> Router {
    let base_path = state.cfg.base_path.clone();
    let protected = Router::new()
        .route("/terminal", get(crate::assets::terminal_page))
        .route(
            "/api/sessions",
            get(handlers::sessions_list).post(handlers::sessions_create),
        )
        .route(
            "/api/sessions/:id",
            put(handlers::sessions_rename).delete(handlers::sessions_delete),
        )
        .route(
            "/api/sessions/:id/exec",
            axum::routing::post(crate::exec_history::sessions_exec),
        )
        .route(
            "/api/sessions/:id/history",
            get(crate::exec_history::sessions_history),
        )
        // Share link routes (M4-U1)
        .route("/api/sessions/:id/share", post(shares::mint_share))
        .route("/api/sessions/:id/shares", get(shares::list_shares))
        .route("/api/shares/:id", delete(shares::revoke_share))
        .route("/ws/:id", get(crate::ws::ws_session))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::middleware::require_auth,
        ));

    let app = Router::new()
        .route("/", get(crate::assets::login_page))
        .route("/static/*path", get(crate::assets::static_file))
        .route("/api/health", get(handlers::health))
        .route("/api/login", post(handlers::login))
        // Public share viewer routes (no auth required — registered outside protected router).
        .route("/s/:token", get(shares::share_page))
        .route("/ws/share/:token", get(crate::ws::ws_share))
        .merge(protected)
        .with_state(state);

    if base_path.is_empty() {
        return app;
    }

    // Mount the entire app under the base path (Go parity: r.Route(BasePath, ...)).
    // Nesting at "{base_path}/" maps the inner "/" route to "{base_path}/"
    // exactly; the bare prefix gets an explicit 301 to the login page (Go
    // parity: http.StatusMovedPermanently — axum's Redirect::permanent is 308,
    // so the response is built by hand), and anything outside the prefix
    // falls through to the default 404.
    let target = format!("{base_path}/");
    let redirect_target = target.clone();
    Router::new()
        .route(
            &base_path,
            get(move || {
                let target = redirect_target.clone();
                async move {
                    use axum::http::{header, StatusCode};
                    use axum::response::IntoResponse;
                    (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, target)]).into_response()
                }
            }),
        )
        .nest(&target, app)
}

#[cfg(test)]
pub mod test_support {
    use super::*;

    /// App over a throwaway temp data dir; returns the dir to keep it alive.
    pub async fn test_app() -> (Router, tempfile::TempDir) {
        test_app_with(|_| None).await
    }

    /// App with additional config overrides layered on top of the defaults.
    /// `extra` is called after the standard lookup; return `Some(value)` to
    /// override a key, `None` to fall through to the standard defaults.
    pub async fn test_app_with(
        extra: impl Fn(&str) -> Option<String> + 'static,
    ) -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().display().to_string();
        let cfg = Config::from_lookup(|key| {
            // extra overrides come first.
            if let Some(v) = extra(key) {
                return Some(v);
            }
            match key {
                "AI_CONDUCTOR_DATA_DIR" => Some(data_dir.clone()),
                "AI_CONDUCTOR_PASSWORD" => Some("testpass".into()),
                "AI_CONDUCTOR_API_KEY" => Some("testapikey".into()),
                _ => None,
            }
        })
        .unwrap();
        (build_app(build_state(cfg).await), dir)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{test_app, test_app_with};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok_json() {
        let (app, _dir) = test_app().await;
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
        let (app, _dir) = test_app().await;
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
        let (app, _dir) = test_app().await;
        let res = login(app, r#"{"password":"nope"}"#, None).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "invalid password"}));
    }

    #[tokio::test]
    async fn login_malformed_json_is_400() {
        let (app, _dir) = test_app().await;
        let res = login(app, "{not json", None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "invalid request"}));
    }

    #[tokio::test]
    async fn login_throttles_after_max_attempts_with_retry_after() {
        let (app, _dir) = test_app().await; // default max_attempts = 5
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
        let (app, _dir) = test_app().await;
        let res = app
            .oneshot(Request::get("/terminal").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/");
    }

    #[tokio::test]
    async fn api_without_token_gets_401_json() {
        let (app, _dir) = test_app().await;
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
        let (app, _dir) = test_app().await;
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
        let (app, _dir) = test_app().await;
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
        let (app, _dir) = test_app().await;
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
        let (app, _dir) = test_app().await;
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
        let (app, dir) = test_app().await;
        let db = store::Store::open(&dir.path().join("conductor.db")).unwrap();
        db.add_auth_session("expiredtoken", 1).unwrap();
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
        let (app, _dir) = test_app().await;
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
            !html.contains("__BASE_PATH__"),
            "no unsubstituted __BASE_PATH__ placeholders"
        );
        assert!(
            html.contains(r#"window.BASE_PATH = "";"#),
            "base_path must substitute to empty string at root"
        );
    }

    #[tokio::test]
    async fn static_css_is_served_with_mime() {
        let (app, _dir) = test_app().await;
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
        let (app, _dir) = test_app().await;
        let res = app
            .oneshot(Request::get("/static/nope.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    // ---- Session CRUD tests -----------------------------------------------

    async fn authed_request(
        app: &axum::Router,
        token: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> axum::http::Response<axum::body::Body> {
        let mut builder = match method {
            "GET" => Request::get(path),
            "POST" => Request::post(path),
            "PUT" => Request::put(path),
            "DELETE" => Request::delete(path),
            other => panic!("unsupported method: {other}"),
        };
        builder = builder.header("X-Session-Token", token);
        if let Some(b) = body {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            app.clone()
                .oneshot(builder.body(Body::from(b.to_string())).unwrap())
                .await
                .unwrap()
        } else {
            app.clone()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap()
        }
    }

    async fn body_json(res: axum::http::Response<axum::body::Body>) -> serde_json::Value {
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn create_session_returns_201_with_8_char_id() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let res = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let v = body_json(res).await;
        let id = v["id"].as_str().expect("id field");
        assert_eq!(id.len(), 8, "id must be 8 chars");
        assert_eq!(v["name"].as_str().unwrap(), id, "name defaults to id");
        // cleanup
        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    #[tokio::test]
    async fn create_with_name() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let res = authed_request(
            &app,
            &token,
            "POST",
            "/api/sessions",
            Some(r#"{"name":"workbench"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let v = body_json(res).await;
        let id = v["id"].as_str().expect("id field");
        assert_eq!(v["name"].as_str().unwrap(), "workbench");
        // cleanup
        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    #[tokio::test]
    async fn list_sessions_has_exact_wire_fields() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let create_res = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let created = body_json(create_res).await;
        let id = created["id"].as_str().unwrap().to_string();

        let list_res = authed_request(&app, &token, "GET", "/api/sessions", None).await;
        assert_eq!(list_res.status(), StatusCode::OK);
        let arr = body_json(list_res).await;
        let arr = arr.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        let obj = arr[0].as_object().expect("object");

        assert_eq!(
            obj.len(),
            8,
            "expected exactly 8 keys, got: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("createdAt"));
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("lastActivityAt"));
        assert!(obj.contains_key("lastClientDisconnectAt"));
        assert!(obj.contains_key("cols"));
        assert!(obj.contains_key("rows"));

        let ca = obj["createdAt"].as_str().unwrap();
        assert_eq!(ca.len(), 19, "createdAt len: {ca}");
        let ca_chars: Vec<char> = ca.chars().collect();
        assert_eq!(ca_chars[4], '-');
        assert_eq!(ca_chars[7], '-');
        assert_eq!(ca_chars[13], ':');
        assert_eq!(ca_chars[16], ':');

        assert_eq!(obj["status"].as_str().unwrap(), "running");
        assert_eq!(obj["cols"].as_u64().unwrap(), 80);
        assert_eq!(obj["rows"].as_u64().unwrap(), 24);

        // cleanup
        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    #[tokio::test]
    async fn rename_session_roundtrip() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let create_res = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        let created = body_json(create_res).await;
        let id = created["id"].as_str().unwrap().to_string();

        let rename_res = authed_request(
            &app,
            &token,
            "PUT",
            &format!("/api/sessions/{id}"),
            Some(r#"{"name":"renamed"}"#),
        )
        .await;
        assert_eq!(rename_res.status(), StatusCode::OK);
        let v = body_json(rename_res).await;
        assert_eq!(v, serde_json::json!({"success": true}));

        let list_res = authed_request(&app, &token, "GET", "/api/sessions", None).await;
        let arr = body_json(list_res).await;
        let arr = arr.as_array().unwrap();
        assert_eq!(arr[0]["name"].as_str().unwrap(), "renamed");

        // cleanup
        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    #[tokio::test]
    async fn rename_empty_name_is_400() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let create_res = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        let created = body_json(create_res).await;
        let id = created["id"].as_str().unwrap().to_string();

        let res = authed_request(
            &app,
            &token,
            "PUT",
            &format!("/api/sessions/{id}"),
            Some(r#"{"name":""}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let v = body_json(res).await;
        assert_eq!(v, serde_json::json!({"error": "name required"}));

        // cleanup
        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    #[tokio::test]
    async fn rename_unknown_is_404() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let res = authed_request(
            &app,
            &token,
            "PUT",
            "/api/sessions/zzzzzzzz",
            Some(r#"{"name":"anything"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let v = body_json(res).await;
        assert_eq!(
            v,
            serde_json::json!({"error": "session zzzzzzzz not found"})
        );
    }

    #[tokio::test]
    async fn delete_session_kills_tmux() {
        let (app, dir) = test_app().await;
        let token = obtain_token(&app).await;
        let create_res = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let created = body_json(create_res).await;
        let id = created["id"].as_str().unwrap().to_string();

        let del_res =
            authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
        assert_eq!(del_res.status(), StatusCode::OK);
        let v = body_json(del_res).await;
        assert_eq!(v, serde_json::json!({"success": true}));

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let tmux_name = tmux::session_name(&id);
        assert!(
            !tmux::has_session(dir.path(), &tmux_name).await,
            "tmux session should be gone after delete"
        );
    }

    #[tokio::test]
    async fn delete_unknown_is_404() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let res = authed_request(&app, &token, "DELETE", "/api/sessions/zzzzzzzz", None).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let v = body_json(res).await;
        assert_eq!(
            v,
            serde_json::json!({"error": "session zzzzzzzz not found"})
        );
    }

    #[tokio::test]
    async fn terminal_serves_ported_ui() {
        let (app, _dir) = test_app().await;
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
        let ct = res
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            ct.starts_with("text/html"),
            "content-type must be text/html, got: {ct}"
        );
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("xterm"), "terminal page must reference xterm");
        assert!(
            html.contains("/static/js/app.js"),
            "terminal page must reference app.js (which contains the /ws/ WebSocket logic)"
        );
        assert!(
            !html.contains("{{"),
            "no Go template directives may survive the port"
        );
        assert!(
            !html.contains("__BASE_PATH__"),
            "no unsubstituted __BASE_PATH__ placeholders"
        );
        assert!(
            html.contains(r#"window.BASE_PATH = "";"#),
            "base_path must substitute to empty string at root"
        );
    }

    // ---- X-API-Key auth tests --------------------------------------------

    #[tokio::test]
    async fn api_key_grants_api_access() {
        let (app, _dir) = test_app().await;
        // "testapikey" is set in test_app config lookup
        let res = app
            .oneshot(
                Request::get("/api/sessions")
                    .header("X-API-Key", "testapikey")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_key_grants_terminal() {
        let (app, _dir) = test_app().await;
        let res = app
            .oneshot(
                Request::get("/terminal")
                    .header("X-API-Key", "testapikey")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_api_key_falls_through() {
        let (app, _dir) = test_app().await;
        // Wrong key, no session token -> falls through to token path -> rejected
        let res_api = app
            .clone()
            .oneshot(
                Request::get("/api/sessions")
                    .header("X-API-Key", "wrongkey")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_api.status(), StatusCode::UNAUTHORIZED);
        let body = res_api.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, serde_json::json!({"error": "unauthorized"}));

        let res_term = app
            .oneshot(
                Request::get("/terminal")
                    .header("X-API-Key", "wrongkey")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res_term.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn cookie_still_works_without_api_key_header() {
        // Confirm that existing cookie-based auth is unaffected.
        let (app, _dir) = test_app().await;
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
    async fn wrong_length_api_key_is_rejected() {
        // Checks that a key of different length is not length-leaked
        // (note: subtle ct_eq short-circuits on length mismatch -- a length oracle.
        // Harmless for fixed-64-hex keys; M5 may hash both sides. Assert rejected.)
        let (app, _dir) = test_app().await;
        let res = app
            .oneshot(
                Request::get("/api/sessions")
                    .header("X-API-Key", "short")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- U3: max-session cap test -----------------------------------------

    /// POST /api/sessions with max_sessions=1: first → 201, second → 429 body-exact,
    /// delete first → third → 201.
    #[tokio::test]
    async fn cap_returns_429() {
        let (app, _dir) =
            test_app_with(|key| (key == "AI_CONDUCTOR_MAX_SESSIONS").then(|| "1".into())).await;
        let token = obtain_token(&app).await;

        // First create: must succeed.
        let res1 = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(
            res1.status(),
            StatusCode::CREATED,
            "first create must be 201"
        );
        let v1 = body_json(res1).await;
        let id1 = v1["id"].as_str().unwrap().to_string();

        // Second create: must be 429 with exact body.
        let res2 = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(
            res2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second create must be 429"
        );
        let v2 = body_json(res2).await;
        assert_eq!(
            v2,
            serde_json::json!({"error": "session limit reached"}),
            "429 body must be wire-exact"
        );

        // Delete first session.
        let del = authed_request(
            &app,
            &token,
            "DELETE",
            &format!("/api/sessions/{id1}"),
            None,
        )
        .await;
        assert_eq!(del.status(), StatusCode::OK);

        // Third create: must succeed now that slot freed.
        let res3 = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(
            res3.status(),
            StatusCode::CREATED,
            "third create must succeed after delete"
        );
        let v3 = body_json(res3).await;
        let id3 = v3["id"].as_str().unwrap().to_string();

        // Cleanup.
        authed_request(
            &app,
            &token,
            "DELETE",
            &format!("/api/sessions/{id3}"),
            None,
        )
        .await;
    }

    // ---- U4: exec + history integration tests --------------------------------

    /// exec round-trip: create session, exec `echo EXEC_PROOF_$((2+3))`,
    /// verify output contains "EXEC_PROOF_5", timeout==false, truncated_bytes==0.
    #[tokio::test]
    async fn exec_round_trip() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        // Create session.
        let create = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(create.status(), StatusCode::CREATED);
        let created = body_json(create).await;
        let id = created["id"].as_str().unwrap().to_string();

        // Give tmux a moment to initialise.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Exec command.
        let exec_res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{id}/exec"),
            Some(r#"{"command":"echo EXEC_PROOF_$((2+3))"}"#),
        )
        .await;
        assert_eq!(exec_res.status(), StatusCode::OK, "exec must return 200");
        let v = body_json(exec_res).await;
        let output = v["output"].as_str().unwrap_or("");
        assert!(
            output.contains("EXEC_PROOF_5"),
            "output must contain EXEC_PROOF_5, got: {output:?}"
        );
        assert_eq!(v["timeout"], false, "timeout must be false");
        assert_eq!(v["truncated_bytes"], 0, "truncated_bytes must be 0");

        // Cleanup.
        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    /// exec timeout: exec `sleep 5` with timeout=1 → 200, timeout==true, finishes quickly.
    #[tokio::test]
    async fn exec_timeout() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        let create = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(create.status(), StatusCode::CREATED);
        let created = body_json(create).await;
        let id = created["id"].as_str().unwrap().to_string();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let start = std::time::Instant::now();
        let exec_res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{id}/exec"),
            Some(r#"{"command":"sleep 5","timeout":1}"#),
        )
        .await;
        let elapsed = start.elapsed();

        assert_eq!(exec_res.status(), StatusCode::OK, "exec must return 200");
        let v = body_json(exec_res).await;
        assert_eq!(v["timeout"], true, "timeout must be true");
        // Should complete within ~2s wall (1s timeout + 1s slack).
        assert!(
            elapsed.as_secs() < 4,
            "exec with timeout=1 must return within ~4s wall, took: {elapsed:?}"
        );

        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    /// exec unknown session → 404 with wire-exact body.
    #[tokio::test]
    async fn exec_unknown_session_404() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        let res = authed_request(
            &app,
            &token,
            "POST",
            "/api/sessions/zzzzzzzz/exec",
            Some(r#"{"command":"echo hi"}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let v = body_json(res).await;
        assert_eq!(
            v,
            serde_json::json!({"error": "session not running"}),
            "404 body must be wire-exact"
        );
    }

    /// exec empty command → 400.
    #[tokio::test]
    async fn exec_empty_command_400() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        // Need a real session so the 400 is about the command, not 404.
        let create = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(create.status(), StatusCode::CREATED);
        let created = body_json(create).await;
        let id = created["id"].as_str().unwrap().to_string();

        let res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{id}/exec"),
            Some(r#"{"command":""}"#),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let v = body_json(res).await;
        assert_eq!(v, serde_json::json!({"error": "invalid request"}));

        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    /// history returns output: create session, exec an echo, GET history → 200.
    #[tokio::test]
    async fn history_returns_output() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        let create = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(create.status(), StatusCode::CREATED);
        let created = body_json(create).await;
        let id = created["id"].as_str().unwrap().to_string();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Exec an echo to leave a known string in the pane.
        authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{id}/exec"),
            Some(r#"{"command":"echo HISTORY_PROBE_XYZ"}"#),
        )
        .await;

        // GET history.
        let hist_res = authed_request(
            &app,
            &token,
            "GET",
            &format!("/api/sessions/{id}/history"),
            None,
        )
        .await;
        assert_eq!(hist_res.status(), StatusCode::OK, "history must return 200");
        let v = body_json(hist_res).await;
        assert_eq!(
            v["session_id"].as_str().unwrap(),
            id,
            "session_id must match"
        );
        let output = v["output"].as_str().unwrap_or("");
        assert!(
            output.contains("HISTORY_PROBE_XYZ"),
            "history output must contain HISTORY_PROBE_XYZ, got: {output:?}"
        );

        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    /// history tail clamps: tail=10 → output bytes ≤ 10.
    #[tokio::test]
    async fn history_tail_clamps() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        let create = authed_request(&app, &token, "POST", "/api/sessions", None).await;
        assert_eq!(create.status(), StatusCode::CREATED);
        let created = body_json(create).await;
        let id = created["id"].as_str().unwrap().to_string();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let hist_res = authed_request(
            &app,
            &token,
            "GET",
            &format!("/api/sessions/{id}/history?tail=10"),
            None,
        )
        .await;
        assert_eq!(hist_res.status(), StatusCode::OK);
        let v = body_json(hist_res).await;
        let output = v["output"].as_str().unwrap_or("");
        // The output bytes must be ≤ 10. CRLF expansion can only add bytes, so
        // the boundary-safe tail must yield ≤ 10 bytes.
        assert!(
            output.len() <= 10,
            "tail=10 must yield ≤ 10 bytes, got {} bytes: {output:?}",
            output.len()
        );

        authed_request(&app, &token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    /// history unknown session → 404 with wire-exact body.
    #[tokio::test]
    async fn history_unknown_404() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        let res = authed_request(&app, &token, "GET", "/api/sessions/zzzzzzzz/history", None).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let v = body_json(res).await;
        assert_eq!(
            v,
            serde_json::json!({"error": "session not found"}),
            "404 body must be wire-exact"
        );
    }
    // ---- U1: Share link integration tests -----------------------------------

    /// Helper: create a session and return its id.
    async fn create_session(app: &axum::Router, token: &str) -> String {
        let res = authed_request(app, token, "POST", "/api/sessions", None).await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let v = body_json(res).await;
        v["id"].as_str().unwrap().to_string()
    }

    /// Helper: delete a session (best-effort cleanup).
    async fn delete_session(app: &axum::Router, token: &str, id: &str) {
        authed_request(app, token, "DELETE", &format!("/api/sessions/{id}"), None).await;
    }

    #[tokio::test]
    async fn mint_share_201_shape() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let sess_id = create_session(&app, &token).await;

        let res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{sess_id}/share"),
            None,
        )
        .await;
        assert_eq!(res.status(), StatusCode::CREATED, "mint must return 201");
        let v = body_json(res).await;

        let id = v["id"].as_str().expect("id field");
        assert_eq!(id.len(), 16, "share id must be 16 hex chars");

        let share_token = v["token"].as_str().expect("token field");
        assert_eq!(share_token.len(), 64, "token must be 64 hex chars");

        assert_eq!(v["mode"].as_str().unwrap(), "read");
        assert_eq!(v["sessionId"].as_str().unwrap(), sess_id);

        let path = v["path"].as_str().expect("path field");
        assert_eq!(
            path,
            &format!("/s/{share_token}"),
            "path must be /s/<token>"
        );

        let url = v["url"].as_str().expect("url field");
        assert_eq!(url, path, "url must equal path when public_url is empty");

        assert!(v["expiresAt"].is_number(), "expiresAt must be a number");

        delete_session(&app, &token, &sess_id).await;
    }

    #[tokio::test]
    async fn mint_share_with_public_url() {
        let (app, _dir) = test_app_with(|k| {
            (k == "AI_CONDUCTOR_PUBLIC_URL").then(|| "https://example.com".into())
        })
        .await;
        let token = obtain_token(&app).await;
        let sess_id = create_session(&app, &token).await;

        let res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{sess_id}/share"),
            None,
        )
        .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let v = body_json(res).await;

        let path = v["path"].as_str().unwrap();
        let url = v["url"].as_str().unwrap();
        assert_eq!(
            url,
            &format!("https://example.com{path}"),
            "url must prepend public_url"
        );

        delete_session(&app, &token, &sess_id).await;
    }

    #[tokio::test]
    async fn mint_share_ttl_honored() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let sess_id = create_session(&app, &token).await;

        let body = r#"{"ttlSeconds":3600}"#;
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{sess_id}/share"),
            Some(body),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let v = body_json(res).await;

        let expires_at = v["expiresAt"].as_i64().unwrap();
        let expected = before + 3600;
        assert!(
            (expected..=expected + 5).contains(&expires_at),
            "expiresAt must be ~now+3600, got {expires_at}, expected ~{expected}"
        );

        delete_session(&app, &token, &sess_id).await;
    }

    #[tokio::test]
    async fn mint_share_ttl_capped_at_30d() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let sess_id = create_session(&app, &token).await;

        let body = r#"{"ttlSeconds":8640000}"#;
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{sess_id}/share"),
            Some(body),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let v = body_json(res).await;

        let expires_at = v["expiresAt"].as_i64().unwrap();
        let max_30d = before + 30 * 24 * 3600;
        assert!(
            expires_at <= max_30d + 5,
            "expiresAt must be capped at 30d, got {expires_at}, max ~{max_30d}"
        );
        assert!(
            expires_at >= max_30d - 5,
            "expiresAt must be ~30d when capped, got {expires_at}"
        );

        delete_session(&app, &token, &sess_id).await;
    }

    #[tokio::test]
    async fn list_shares_ordered_desc_no_token() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;
        let sess_id = create_session(&app, &token).await;

        authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{sess_id}/share"),
            None,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{sess_id}/share"),
            None,
        )
        .await;

        let list_res = authed_request(
            &app,
            &token,
            "GET",
            &format!("/api/sessions/{sess_id}/shares"),
            None,
        )
        .await;
        assert_eq!(list_res.status(), StatusCode::OK);
        let arr = body_json(list_res).await;
        let arr = arr.as_array().expect("must be array");
        assert_eq!(arr.len(), 2, "must have 2 shares");

        let ca0 = arr[0]["createdAt"].as_i64().unwrap();
        let ca1 = arr[1]["createdAt"].as_i64().unwrap();
        assert!(ca0 >= ca1, "list must be DESC by createdAt: {ca0} >= {ca1}");

        let obj = arr[0].as_object().unwrap();
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "id",
            "sessionId",
            "mode",
            "createdAt",
            "expiresAt",
            "revoked",
        ]
        .iter()
        .cloned()
        .collect();
        assert_eq!(
            keys, expected,
            "list fields must be exactly {{id,sessionId,mode,createdAt,expiresAt,revoked}}"
        );
        assert!(!obj.contains_key("token"), "token must NOT appear in list");

        delete_session(&app, &token, &sess_id).await;
    }

    #[tokio::test]
    async fn revoke_then_store_redeem_none() {
        let (app, dir) = test_app().await;
        let token = obtain_token(&app).await;
        let sess_id = create_session(&app, &token).await;

        let mint_res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/api/sessions/{sess_id}/share"),
            None,
        )
        .await;
        assert_eq!(mint_res.status(), StatusCode::CREATED);
        let mint_v = body_json(mint_res).await;
        let share_id = mint_v["id"].as_str().unwrap().to_string();
        let raw_token = mint_v["token"].as_str().unwrap().to_string();

        let revoke_res = authed_request(
            &app,
            &token,
            "DELETE",
            &format!("/api/shares/{share_id}"),
            None,
        )
        .await;
        assert_eq!(revoke_res.status(), StatusCode::OK);
        let rv = body_json(revoke_res).await;
        assert_eq!(rv, serde_json::json!({"success": true}));

        let db = store::Store::open(&dir.path().join("conductor.db")).unwrap();
        let hash: Vec<u8> = {
            use sha2::{Digest, Sha256};
            Sha256::digest(raw_token.as_bytes()).to_vec()
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let result = db.redeem_share(&hash, now).unwrap();
        assert!(result.is_none(), "revoked share must not be redeemable");

        delete_session(&app, &token, &sess_id).await;
    }

    #[tokio::test]
    async fn revoke_unknown_share_id_returns_200() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        let res =
            authed_request(&app, &token, "DELETE", "/api/shares/doesnotexist1234", None).await;
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "revoke of unknown id must be 200 (Go parity: rows_affected not checked)"
        );
        let v = body_json(res).await;
        assert_eq!(v, serde_json::json!({"success": true}));
    }

    #[tokio::test]
    async fn mint_for_unknown_session_is_404() {
        let (app, _dir) = test_app().await;
        let token = obtain_token(&app).await;

        let res = authed_request(&app, &token, "POST", "/api/sessions/zzzzzzzz/share", None).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let v = body_json(res).await;
        assert_eq!(
            v,
            serde_json::json!({"error": "session not running"}),
            "404 body must be wire-exact (Go: 'session not running')"
        );
    }

    // ---- U4: base-path mounting tests -----------------------------------------

    /// App mounted under "/app".
    async fn test_app_based() -> (axum::Router, tempfile::TempDir) {
        test_app_with(|key| (key == "AI_CONDUCTOR_BASE_PATH").then(|| "/app".into())).await
    }

    /// Login under the "/app" prefix and return the session token.
    async fn obtain_token_based(app: &axum::Router) -> String {
        let res = app
            .clone()
            .oneshot(
                Request::post("/app/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"password":"testpass"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "login under /app must be 200");
        let v = body_json(res).await;
        v["token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn base_path_health_under_prefix_only() {
        let (app, _dir) = test_app_based().await;

        let res = app
            .clone()
            .oneshot(Request::get("/app/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "/app/api/health must be 200");
        let v = body_json(res).await;
        assert_eq!(v, serde_json::json!({"status": "ok"}));

        let res = app
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "requests outside the prefix must 404 (Go parity)"
        );
    }

    #[tokio::test]
    async fn base_path_cookie_scoped_to_prefix() {
        let (app, _dir) = test_app_based().await;
        let res = app
            .oneshot(
                Request::post("/app/api/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"password":"testpass"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let cookie = res
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            cookie.contains("Path=/app/"),
            "session cookie must be scoped to Path=/app/, got: {cookie}"
        );
    }

    #[tokio::test]
    async fn base_path_terminal_html_substituted() {
        let (app, _dir) = test_app_based().await;
        let token = obtain_token_based(&app).await;
        let res = app
            .oneshot(
                Request::get("/app/terminal")
                    .header("X-Session-Token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains(r#"window.BASE_PATH = "/app""#),
            "terminal HTML must carry the substituted base path"
        );
        assert!(
            !html.contains("__BASE_PATH__"),
            "terminal HTML must have zero literal __BASE_PATH__ placeholders"
        );
    }

    #[tokio::test]
    async fn base_path_unauth_terminal_redirects_under_prefix() {
        let (app, _dir) = test_app_based().await;
        let res = app
            .oneshot(Request::get("/app/terminal").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            res.headers().get(header::LOCATION).unwrap(),
            "/app/",
            "unauthenticated browser redirect must target the prefixed login page"
        );
    }

    #[tokio::test]
    async fn base_path_bare_prefix_301_to_slash() {
        let (app, _dir) = test_app_based().await;
        let res = app
            .oneshot(Request::get("/app").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::MOVED_PERMANENTLY,
            "GET /app must 301 (Go parity)"
        );
        assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/app/");
    }

    #[tokio::test]
    async fn base_path_share_mint_path_prefixed() {
        let (app, _dir) = test_app_based().await;
        let token = obtain_token_based(&app).await;

        let create = authed_request(&app, &token, "POST", "/app/api/sessions", None).await;
        assert_eq!(create.status(), StatusCode::CREATED);
        let created = body_json(create).await;
        let sess_id = created["id"].as_str().unwrap().to_string();

        let res = authed_request(
            &app,
            &token,
            "POST",
            &format!("/app/api/sessions/{sess_id}/share"),
            None,
        )
        .await;
        assert_eq!(res.status(), StatusCode::CREATED);
        let v = body_json(res).await;
        let path = v["path"].as_str().unwrap();
        assert!(
            path.starts_with("/app/s/"),
            "share mint path must start with /app/s/, got: {path}"
        );
        let url = v["url"].as_str().unwrap();
        assert_eq!(url, path, "url must equal path when public_url is empty");

        authed_request(
            &app,
            &token,
            "DELETE",
            &format!("/app/api/sessions/{sess_id}"),
            None,
        )
        .await;
    }
}
