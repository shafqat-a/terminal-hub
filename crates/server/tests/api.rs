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

/// Returns (addr, session_cookie_value). The caller is responsible for
/// attaching the cookie as `th_session=<value>` on every protected request.
async fn spawn(socket: &str) -> (SocketAddr, String) {
    use base64::Engine;
    use rand::RngCore;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: socket.into(),
        tmux_session: BOOT.into(),
        bind: addr.to_string(),
        // webauthn-rs only accepts http://localhost (or https://) as the
        // origin; raw 127.0.0.1 over plain http is rejected as insecure.
        public_url: format!("http://localhost:{}/", addr.port()),
    };
    let store = terminal_hub_server::db::Store::in_memory().unwrap();
    // Seed a user + a valid session cookie so the auth middleware lets us
    // through to the M2 routes under test.
    store
        .upsert_user("test@example.com", "ssh-ed25519 AAA", "primary")
        .await
        .unwrap();
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let cookie_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let hash = terminal_hub_server::auth::sha256(cookie_value.as_bytes());
    store
        .insert_session(&hash, "test@example.com", 3600)
        .await
        .unwrap();

    let app = terminal_hub_server::router_with(cfg, store)
        .await
        .unwrap();
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });
    (addr, cookie_value)
}

fn cookie_header(value: &str) -> String {
    format!("th_session={}", value)
}

#[tokio::test(flavor = "multi_thread")]
async fn crud_round_trip() {
    let socket = "terminal-hub-test-m2-api-crud";
    ensure(socket);
    let (addr, cookie) = spawn(socket).await;
    let cookie_h = cookie_header(&cookie);
    let c = reqwest::Client::new();
    let created: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", &cookie_h)
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
        .header("cookie", &cookie_h)
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
        .header("cookie", &cookie_h)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 204);
    kill(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_tabs_mirror_same_session() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let socket = "terminal-hub-test-m2-api-mirror";
    ensure(socket);
    let (addr, cookie) = spawn(socket).await;
    let cookie_h = cookie_header(&cookie);
    let c = reqwest::Client::new();
    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", &cookie_h)
        .json(&serde_json::json!({ "display_name": "mirror" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();
    let url = format!("ws://{addr}/ws/attach/{id}");
    let mut req_a = url.as_str().into_client_request().unwrap();
    req_a
        .headers_mut()
        .insert("cookie", cookie_h.parse().unwrap());
    let mut req_b = url.as_str().into_client_request().unwrap();
    req_b
        .headers_mut()
        .insert("cookie", cookie_h.parse().unwrap());
    let (mut a, _) = tokio_tungstenite::connect_async(req_a).await.unwrap();
    let (mut b, _) = tokio_tungstenite::connect_async(req_b).await.unwrap();
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
    let _ = c
        .delete(format!("http://{addr}/api/sessions/{id}"))
        .header("cookie", &cookie_h)
        .send()
        .await;
    kill(socket);
    assert!(sa && sb, "both subscribers should see the output");
}

#[tokio::test(flavor = "multi_thread")]
async fn me_returns_email_and_role() {
    let socket = "terminal-hub-test-m4-api-me";
    ensure(socket);
    let (addr, cookie) = spawn(socket).await;
    let ch = cookie_header(&cookie);
    let c = reqwest::Client::new();
    let resp: serde_json::Value = c
        .get(format!("http://{addr}/api/me"))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["email"], "test@example.com");
    assert_eq!(resp["role"], "primary");
    kill(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn reattach_replays_scrollback() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let socket = "terminal-hub-test-m2-api-scroll";
    ensure(socket);
    let (addr, cookie) = spawn(socket).await;
    let cookie_h = cookie_header(&cookie);
    let c = reqwest::Client::new();
    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", &cookie_h)
        .json(&serde_json::json!({ "display_name": "scroll" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();
    let url = format!("ws://{addr}/ws/attach/{id}");
    let build_req = || {
        let mut r = url.as_str().into_client_request().unwrap();
        r.headers_mut().insert("cookie", cookie_h.parse().unwrap());
        r
    };
    {
        let (mut w, _) = tokio_tungstenite::connect_async(build_req()).await.unwrap();
        w.send(Message::Text("echo scrollback-marker\r".into())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        let _ = w.close(None).await;
    }
    let (mut w2, _) = tokio_tungstenite::connect_async(build_req()).await.unwrap();
    let mut saw = false;
    let dl = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < dl && !saw {
        if let Ok(Some(Ok(Message::Binary(by)))) = tokio::time::timeout(Duration::from_millis(200), w2.next()).await {
            if std::str::from_utf8(&by).map(|s| s.contains("scrollback-marker")).unwrap_or(false) { saw = true; }
        }
    }
    let _ = c
        .delete(format!("http://{addr}/api/sessions/{id}"))
        .header("cookie", &cookie_h)
        .send()
        .await;
    kill(socket);
    assert!(saw, "second attach should replay 'scrollback-marker' from tmux buffer");
}
