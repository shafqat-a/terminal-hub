use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;
use std::sync::Arc;
use tower_http::services::ServeDir;

mod attach;

pub struct Config {
    pub tmux_socket: String,
    pub tmux_session: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tmux_socket: std::env::var("TERMINAL_HUB_TMUX_SOCKET")
                .unwrap_or_else(|_| "terminal-hub".into()),
            tmux_session: std::env::var("TERMINAL_HUB_TMUX_SESSION")
                .unwrap_or_else(|_| "scratch".into()),
        }
    }
}

pub fn router() -> Router { router_with(Config::default()) }

pub fn router_with(cfg: Config) -> Router {
    let state = Arc::new(cfg);
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws/echo", any(ws_echo))
        .route("/ws/attach", any(attach::ws_attach))
        .fallback_service(ServeDir::new(static_dir()))
        .with_state(state)
}

async fn ws_echo(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_echo)
}
async fn handle_echo(mut s: WebSocket) {
    while let Some(Ok(m)) = s.recv().await {
        if let Message::Text(t) = m {
            if s.send(Message::Text(t)).await.is_err() { return; }
        }
    }
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("static");
    p
}
