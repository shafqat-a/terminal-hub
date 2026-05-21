use axum::routing::{any, get};
use axum::Router;
use std::sync::Arc;
use tower_http::services::ServeDir;

pub mod api;
pub mod attach;
pub mod db;
pub mod hub;
pub mod paths;
pub mod session_id;
pub mod sessions;
pub mod tls;

pub struct Config {
    pub tmux_socket: String,
    pub tmux_session: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            tmux_socket: std::env::var("TERMINAL_HUB_TMUX_SOCKET").unwrap_or_else(|_| "terminal-hub".into()),
            tmux_session: std::env::var("TERMINAL_HUB_TMUX_SESSION").unwrap_or_else(|_| "_boot".into()),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub mgr: Arc<sessions::Manager>,
    pub cfg: Arc<Config>,
    pub hub: hub::Hub,
}

pub async fn router() -> anyhow::Result<Router> { router_with(Config::default()).await }
pub async fn router_with(cfg: Config) -> anyhow::Result<Router> {
    let mgr = Arc::new(sessions::Manager::connect(&cfg.tmux_socket, &cfg.tmux_session).await?);
    let hub = hub::Hub::new(cfg.tmux_socket.clone());
    let state = AppState { mgr, cfg: Arc::new(cfg), hub };
    Ok(Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/sessions", get(api::list).post(api::create))
        .route("/api/sessions/:id", axum::routing::patch(api::rename).delete(api::kill))
        .route("/ws/attach/:id", any(attach::ws_attach))
        .fallback_service(ServeDir::new(static_dir()))
        .with_state(state))
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")); p.push("static"); p
}
