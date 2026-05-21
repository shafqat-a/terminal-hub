use std::net::SocketAddr;
use std::process::Command;
use tokio::net::TcpListener;

const SOCKET: &str = "terminal-hub-test-m2-http";
const BOOT: &str = "_boot";

fn ensure() { let _ = Command::new("tmux").args(["-L", SOCKET, "new-session", "-d", "-s", BOOT]).status(); }
fn kill() { let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status(); }

async fn spawn_app() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: SOCKET.into(),
        tmux_session: BOOT.into(),
        bind: addr.to_string(),
        // webauthn-rs requires https:// or http://localhost for the origin.
        public_url: format!("http://localhost:{}/", addr.port()),
    };
    let store = terminal_hub_server::db::Store::in_memory().unwrap();
    let app = terminal_hub_server::router_with(cfg, store).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn health_returns_ok() {
    ensure();
    let addr = spawn_app().await;
    let body = reqwest::get(format!("http://{addr}/healthz"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "ok");
    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn root_redirects_to_login_when_unauthed() {
    // M3: auth middleware now intercepts `/` for unauthenticated clients and
    // redirects to /login.html. The actual xterm index is gated behind the
    // session cookie.
    ensure();
    let addr = spawn_app().await;
    let resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(format!("http://{addr}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/login.html")
    );
    kill();
}
