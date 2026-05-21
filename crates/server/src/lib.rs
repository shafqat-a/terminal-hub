use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;
use tower_http::services::ServeDir;

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws/echo", any(ws_echo))
        .fallback_service(ServeDir::new(static_dir()))
}

async fn ws_echo(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_echo)
}

async fn handle_echo(mut socket: WebSocket) {
    while let Some(Ok(msg)) = socket.recv().await {
        if let Message::Text(t) = msg {
            if socket.send(Message::Text(t)).await.is_err() {
                return;
            }
        }
    }
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("static");
    p
}
