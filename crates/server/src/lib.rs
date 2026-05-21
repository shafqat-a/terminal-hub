use axum::{routing::get, Router};
use tower_http::services::ServeDir;

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .fallback_service(ServeDir::new(static_dir()))
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("static");
    p
}
