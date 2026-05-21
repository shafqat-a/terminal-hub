use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let bind = std::env::var("TERMINAL_HUB_BIND").unwrap_or_else(|_| "127.0.0.1:5999".into());
    let app = terminal_hub_server::router().await?;
    tracing::info!(%bind, "terminal-hub listening");
    let listener = TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
