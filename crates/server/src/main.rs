use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use terminal_hub_server::{db, paths, tls, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::default();
    let paths = paths::Paths::resolve()?;
    paths.ensure()?;

    let store = db::Store::open(&paths.db())?;

    let host = url::Url::parse(&cfg.public_url)?
        .host_str()
        .unwrap_or("localhost")
        .to_string();
    let tls_files = tls::ensure(
        &paths.tls_crt(),
        &paths.tls_key(),
        &[host.clone(), "127.0.0.1".into()],
    )?;

    let cfg_for_router = cfg.clone();
    let app = terminal_hub_server::router_with(cfg_for_router, store).await?;

    let tls_conf = RustlsConfig::from_pem(
        tls_files.cert_pem.into_bytes(),
        tls_files.key_pem.into_bytes(),
    )
    .await?;

    let addr: SocketAddr = cfg.bind.parse()?;
    tracing::info!(%addr, public_url=%cfg.public_url, "terminal-hub listening (TLS)");
    axum_server::bind_rustls(addr, tls_conf)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
