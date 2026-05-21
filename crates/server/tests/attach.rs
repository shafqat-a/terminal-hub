use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const SOCKET: &str = "terminal-hub-test-m1-attach";
const SESSION: &str = "scratch";

fn ensure_server() {
    let _ = Command::new("tmux")
        .args(["-L", SOCKET, "new-session", "-d", "-s", SESSION])
        .status();
}

fn kill_server() {
    let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status();
}

async fn spawn_app() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: SOCKET.into(),
        tmux_session: SESSION.into(),
    };
    let app = terminal_hub_server::router_with(cfg);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_echoes_typed_chars() {
    ensure_server();
    let addr = spawn_app().await;
    let url = format!("ws://{addr}/ws/attach");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

    ws.send(Message::Text("echo ping\r".into())).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut saw_ping = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) if std::str::from_utf8(&b).map(|s| s.contains("ping")).unwrap_or(false) => {
                saw_ping = true;
                break;
            }
            _ => {}
        }
    }

    kill_server();
    assert!(saw_ping, "expected to see 'ping' echoed back from the shell");
}
