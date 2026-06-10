mod app;
mod assets;
mod auth;
mod config;
mod exec_history;
mod files;
mod handlers;
pub mod session;
mod shares;
mod util;
mod ws;

use std::net::SocketAddr;
use std::time::Duration;

/// How long in-flight connections get to drain after the shutdown signal
/// before the process exits anyway (Go parity: 15s Shutdown context).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// Resolves on SIGTERM or SIGINT (Go parity: signal.Notify(SIGINT, SIGTERM)).
async fn shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("cannot install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}

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

    // Graceful shutdown (Go parity, spec §6): SIGTERM/SIGINT → stop accepting,
    // let in-flight requests finish, then exit 0. Nothing in this path kills
    // tmux sessions — they deliberately stay RUNNING so a restarted server
    // re-adopts them (M3 machinery). The store closes via Drop when the last
    // Arc<AppState> goes away. Long-lived connections (WebSockets) keep the
    // serve future alive, so the drain is bounded by SHUTDOWN_GRACE, after
    // which remaining connections are dropped (Go: 15s Shutdown context).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutting down");
        shutdown_tx.send_replace(true);
    });

    let graceful = {
        let mut rx = shutdown_rx.clone();
        async move {
            // Ends on signal; also ends (defensively) if the sender vanishes.
            while !*rx.borrow_and_update() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    };
    let grace_elapsed = {
        let mut rx = shutdown_rx;
        async move {
            while !*rx.borrow_and_update() {
                if rx.changed().await.is_err() {
                    // Sender gone without a signal: never force-exit.
                    std::future::pending::<()>().await;
                }
            }
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        }
    };

    tokio::select! {
        res = axum::serve(listener, router).with_graceful_shutdown(graceful) => {
            res.expect("server error");
        }
        _ = grace_elapsed => {
            tracing::warn!("shutdown grace period elapsed; dropping remaining connections");
        }
    }

    if let Some(pid_file) = pid_file {
        std::fs::remove_file(pid_file).ok();
    }
}
