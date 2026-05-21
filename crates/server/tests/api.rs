use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

// Each test gets its own tmux socket so parallel tests don't kill each other's sessions.
const BOOT: &str = "_boot";

fn ensure(socket: &str) {
    let _ = Command::new("tmux")
        .args(["-L", socket, "new-session", "-d", "-s", BOOT])
        .status();
}
fn kill(socket: &str) {
    let _ = Command::new("tmux").args(["-L", socket, "kill-server"]).status();
}

async fn spawn(socket: &str) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: socket.into(),
        tmux_session: BOOT.into(),
    };
    let app = terminal_hub_server::router_with(cfg).await.unwrap();
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn crud_round_trip() {
    let socket = "terminal-hub-test-m2-api-crud";
    ensure(socket);
    let addr = spawn(socket).await;
    let c = reqwest::Client::new();
    let created: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .json(&serde_json::json!({ "display_name": "build" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["session"]["id"].as_str().unwrap().to_string();
    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(listed["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["id"] == id));
    let st = c
        .delete(format!("http://{addr}/api/sessions/{id}"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 204);
    kill(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_tabs_mirror_same_session() {
    let socket = "terminal-hub-test-m2-api-mirror";
    ensure(socket);
    let addr = spawn(socket).await;
    let c = reqwest::Client::new();
    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .json(&serde_json::json!({ "display_name": "mirror" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();
    let url = format!("ws://{addr}/ws/attach/{id}");
    let (mut a, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut b, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    a.send(Message::Text("echo mirror-test\r".into())).await.unwrap();
    let (mut sa, mut sb) = (false, false);
    let dl = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < dl && !(sa && sb) {
        tokio::select! {
            r = tokio::time::timeout(Duration::from_millis(200), a.next()) => {
                if let Ok(Some(Ok(Message::Binary(by)))) = r {
                    if std::str::from_utf8(&by).map(|s| s.contains("mirror-test")).unwrap_or(false) { sa = true; }
                }
            }
            r = tokio::time::timeout(Duration::from_millis(200), b.next()) => {
                if let Ok(Some(Ok(Message::Binary(by)))) = r {
                    if std::str::from_utf8(&by).map(|s| s.contains("mirror-test")).unwrap_or(false) { sb = true; }
                }
            }
        }
    }
    let _ = c.delete(format!("http://{addr}/api/sessions/{id}")).send().await;
    kill(socket);
    assert!(sa && sb, "both subscribers should see the output");
}

#[tokio::test(flavor = "multi_thread")]
async fn reattach_replays_scrollback() {
    let socket = "terminal-hub-test-m2-api-scroll";
    ensure(socket);
    let addr = spawn(socket).await;
    let c = reqwest::Client::new();
    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .json(&serde_json::json!({ "display_name": "scroll" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();
    let url = format!("ws://{addr}/ws/attach/{id}");
    {
        let (mut w, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        w.send(Message::Text("echo scrollback-marker\r".into())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        let _ = w.close(None).await;
    }
    let (mut w2, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let mut saw = false;
    let dl = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < dl && !saw {
        if let Ok(Some(Ok(Message::Binary(by)))) = tokio::time::timeout(Duration::from_millis(200), w2.next()).await {
            if std::str::from_utf8(&by).map(|s| s.contains("scrollback-marker")).unwrap_or(false) { saw = true; }
        }
    }
    let _ = c.delete(format!("http://{addr}/api/sessions/{id}")).send().await;
    kill(socket);
    assert!(saw, "second attach should replay 'scrollback-marker' from tmux buffer");
}
