use axum::routing::{any, get, post};
use axum::Router;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

pub mod api;
pub mod attach;
pub mod audit;
pub mod auth;
pub mod db;
pub mod hub;
pub mod paths;
pub mod permissions;
pub mod session_id;
pub mod sessions;
pub mod tls;
pub mod users;

#[derive(Clone)]
pub struct Config {
    pub tmux_socket: String,
    pub tmux_session: String,
    pub bind: String,
    pub public_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tmux_socket: std::env::var("TERMINAL_HUB_TMUX_SOCKET")
                .unwrap_or_else(|_| "terminal-hub".into()),
            tmux_session: std::env::var("TERMINAL_HUB_TMUX_SESSION")
                .unwrap_or_else(|_| "_boot".into()),
            bind: std::env::var("TERMINAL_HUB_BIND").unwrap_or_else(|_| "127.0.0.1:5999".into()),
            public_url: std::env::var("TERMINAL_HUB_PUBLIC_URL")
                .unwrap_or_else(|_| "https://localhost:5999/".into()),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub mgr: Arc<sessions::Manager>,
    pub cfg: Arc<Config>,
    pub hub: hub::Hub,
    pub auth: auth::routes::AuthState,
}

impl axum::extract::FromRef<AppState> for auth::routes::AuthState {
    fn from_ref(s: &AppState) -> Self {
        s.auth.clone()
    }
}

pub async fn router() -> anyhow::Result<Router> {
    let store = db::Store::in_memory()?;
    router_with(Config::default(), store).await
}

pub async fn router_with(cfg: Config, store: db::Store) -> anyhow::Result<Router> {
    // PasskeySvc::from_env reads TERMINAL_HUB_PUBLIC_URL. Reflect cfg into env
    // so direct test invocations of router_with don't have to set it twice.
    std::env::set_var("TERMINAL_HUB_PUBLIC_URL", &cfg.public_url);
    let mgr = Arc::new(sessions::Manager::connect(&cfg.tmux_socket, &cfg.tmux_session).await?);
    let hub = hub::Hub::new(cfg.tmux_socket.clone());
    let passkey = Arc::new(auth::passkey::PasskeySvc::from_env()?);
    let auth_state = auth::routes::AuthState {
        store: store.clone(),
        challenge: auth::challenge::ChallengeStore::new(),
        passkey,
        public_url: cfg.public_url.clone(),
    };
    let state = AppState {
        mgr,
        cfg: Arc::new(cfg),
        hub,
        auth: auth_state,
    };

    let auth_routes = Router::new()
        .route("/auth/challenge", post(auth::routes::post_challenge))
        .route(
            "/auth/enroll/initiate",
            post(auth::routes::post_enroll_initiate),
        )
        .route(
            "/auth/passkey/register/start",
            get(auth::routes::get_passkey_register_start),
        )
        .route(
            "/auth/passkey/register/finish",
            post(auth::routes::post_passkey_register_finish),
        )
        .route(
            "/auth/passkey/login/start",
            post(auth::routes::post_passkey_login_start),
        )
        .route(
            "/auth/passkey/login/finish",
            post(auth::routes::post_passkey_login_finish),
        )
        .route("/auth/logout", post(auth::routes::post_logout));

    Ok(Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/sessions", get(api::list).post(api::create))
        .route(
            "/api/sessions/:id",
            axum::routing::patch(api::rename).delete(api::kill),
        )
        .route("/ws/attach/:id", any(attach::ws_attach))
        .route("/api/me", get(api::me))
        .route("/api/users", get(api::users_list).post(api::users_add))
        .route(
            "/api/users/:email",
            axum::routing::delete(api::users_remove),
        )
        .route(
            "/api/permissions/session/:session_id",
            get(api::perm_list).post(api::perm_grant),
        )
        .route(
            "/api/permissions/session/:session_id/:user_email",
            axum::routing::delete(api::perm_revoke_handler),
        )
        .route(
            "/api/permissions/peer-create",
            post(api::peer_create_toggle),
        )
        .merge(auth_routes)
        .fallback_service(ServeDir::new(static_dir()))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::middleware::require_session,
        ))
        .layer(CookieManagerLayer::new())
        .with_state(state))
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("static");
    p
}
