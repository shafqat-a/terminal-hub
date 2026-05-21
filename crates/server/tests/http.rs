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
    let cfg = terminal_hub_server::Config { tmux_socket: SOCKET.into(), tmux_session: BOOT.into() };
    let app = terminal_hub_server::router_with(cfg).await.unwrap();
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
async fn root_serves_index_html() {
    ensure();
    let addr = spawn_app().await;
    let body = reqwest::get(format!("http://{addr}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<title>terminal-hub</title>"), "got: {body}");
    assert!(body.contains("xterm"), "should reference xterm.js");
    kill();
}
