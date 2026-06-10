mod app;
mod assets;
mod auth;
mod config;
mod handlers;
pub mod session;
mod ws;

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::Config::from_env().expect("invalid configuration");

    if let Some(pid_file) = &cfg.pid_file {
        std::fs::write(pid_file, std::process::id().to_string()).expect("cannot write pid file");
    }
    let pid_file = cfg.pid_file.clone();
    let addr = cfg.addr.clone();

    let state = app::build_state(cfg).await;
    let router = app::build_app(state).into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("cannot bind");
    tracing::info!("ai-dev-conductor listening on {addr}");

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("shutdown signal received");
        })
        .await
        .expect("server error");

    if let Some(pid_file) = pid_file {
        std::fs::remove_file(pid_file).ok();
    }
}
