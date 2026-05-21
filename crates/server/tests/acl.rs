//! End-to-end ACL enforcement matrix for M4.
//!
//! Walks every interesting (role, capability) combination through the real
//! HTTP API and WebSocket attach path:
//!
//!   * primary sees all sessions; secondary with no grants sees nothing.
//!   * secondary with ATTACH only can attach but their typed input is
//!     silently dropped (output still flows).
//!   * secondary with MANAGE can rename/kill.
//!   * secondary without `peer_create_allowed` gets 403 on POST /api/sessions.
//!   * secondary with `peer_create_allowed` can create AND is auto-granted
//!     on the new session (and so is the primary).
//!
//! Cookies are seeded directly into the Store via `insert_session`, bypassing
//! the WebAuthn ceremony — same pattern as `tests/api.rs` and `tests/users.rs`.

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use terminal_hub_server::db::Store;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

const BOOT: &str = "_boot";

fn ensure(socket: &str) {
    let _ = Command::new("tmux")
        .args(["-L", socket, "new-session", "-d", "-s", BOOT])
        .status();
}
fn kill_tmux(socket: &str) {
    let _ = Command::new("tmux")
        .args(["-L", socket, "kill-server"])
        .status();
}

async fn seed_cookie(store: &Store, email: &str) -> String {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let hash = terminal_hub_server::auth::sha256(value.as_bytes());
    store.insert_session(&hash, email, 3600).await.unwrap();
    value
}

async fn spawn(socket: &str, store: Store) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: socket.into(),
        tmux_session: BOOT.into(),
        bind: addr.to_string(),
        public_url: format!("http://localhost:{}/", addr.port()),
    };
    let app = terminal_hub_server::router_with(cfg, store).await.unwrap();
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });
    addr
}

fn cookie_header(value: &str) -> String {
    format!("th_session={value}")
}

/// Seed a (primary, secondary) pair and return (store, addr, p_cookie, s_cookie).
async fn fixture(socket: &str) -> (Store, SocketAddr, String, String) {
    ensure(socket);
    let store = Store::in_memory().unwrap();
    store
        .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
        .await
        .unwrap();
    store
        .upsert_user("s@x", "ssh-ed25519 BBB", "secondary")
        .await
        .unwrap();
    let p = seed_cookie(&store, "p@x").await;
    let s = seed_cookie(&store, "s@x").await;
    let addr = spawn(socket, store.clone()).await;
    (store, addr, p, s)
}

#[tokio::test(flavor = "multi_thread")]
async fn primary_sees_all_sessions_secondary_sees_none_by_default() {
    let socket = "terminal-hub-test-m4-acl-list";
    let (_store, addr, p_cookie, s_cookie) = fixture(socket).await;
    let c = reqwest::Client::new();

    // Primary creates two sessions.
    for name in &["alpha", "beta"] {
        let r = c
            .post(format!("http://{addr}/api/sessions"))
            .header("cookie", cookie_header(&p_cookie))
            .json(&serde_json::json!({ "display_name": name }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "primary create {name}");
    }

    // Primary list — sees both.
    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&p_cookie))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["sessions"].as_array().unwrap().len(),
        2,
        "primary should see both sessions"
    );

    // Secondary list — empty, no grants.
    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&s_cookie))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listed["sessions"].as_array().unwrap().is_empty(),
        "secondary should see nothing without grants, got {listed}"
    );

    kill_tmux(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_with_attach_only_sees_session_but_cannot_write() {
    let socket = "terminal-hub-test-m4-acl-attach";
    let (_store, addr, p_cookie, s_cookie) = fixture(socket).await;
    let c = reqwest::Client::new();

    // Primary creates a session.
    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&p_cookie))
        .json(&serde_json::json!({ "display_name": "shared" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();

    // Grant secondary ATTACH only (no WRITE).
    let st = c
        .post(format!("http://{addr}/api/permissions/session/{id}"))
        .header("cookie", cookie_header(&p_cookie))
        .json(&serde_json::json!({ "user_email": "s@x", "capabilities": 1u32 }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 204);

    // Secondary list — sees just the granted session.
    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&s_cookie))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = listed["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![id.as_str()]);

    // Secondary attaches, types something, no output produced (input dropped).
    let url = format!("ws://{addr}/ws/attach/{id}");
    let mut req = url.as_str().into_client_request().unwrap();
    req.headers_mut()
        .insert("cookie", cookie_header(&s_cookie).parse().unwrap());
    let (mut ws_s, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    // Drain initial scrollback frame if any.
    let _ = tokio::time::timeout(Duration::from_millis(200), ws_s.next()).await;
    ws_s.send(Message::Text(
        "echo SHOULD-NOT-APPEAR-FROM-SECONDARY\r".into(),
    ))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Primary also attaches; output should not contain the dropped marker,
    // and primary's own write must echo back to both sockets.
    let mut req = url.as_str().into_client_request().unwrap();
    req.headers_mut()
        .insert("cookie", cookie_header(&p_cookie).parse().unwrap());
    let (mut ws_p, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    ws_p.send(Message::Text("echo PRIMARY-WROTE-THIS\r".into()))
        .await
        .unwrap();

    let mut saw_dropped = false;
    let mut saw_primary = false;
    let mut secondary_saw_primary = false;
    let dl = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < dl && !(saw_primary && secondary_saw_primary) {
        tokio::select! {
            r = tokio::time::timeout(Duration::from_millis(200), ws_p.next()) => {
                if let Ok(Some(Ok(Message::Binary(by)))) = r {
                    let s = String::from_utf8_lossy(&by);
                    if s.contains("SHOULD-NOT-APPEAR-FROM-SECONDARY") { saw_dropped = true; }
                    if s.contains("PRIMARY-WROTE-THIS") { saw_primary = true; }
                }
            }
            r = tokio::time::timeout(Duration::from_millis(200), ws_s.next()) => {
                if let Ok(Some(Ok(Message::Binary(by)))) = r {
                    let s = String::from_utf8_lossy(&by);
                    if s.contains("SHOULD-NOT-APPEAR-FROM-SECONDARY") { saw_dropped = true; }
                    if s.contains("PRIMARY-WROTE-THIS") { secondary_saw_primary = true; }
                }
            }
        }
    }
    assert!(
        !saw_dropped,
        "secondary input without WRITE must be silently dropped"
    );
    assert!(saw_primary, "primary's own write should be echoed back");
    assert!(
        secondary_saw_primary,
        "secondary with ATTACH should still receive output"
    );

    kill_tmux(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_without_manage_cannot_rename_or_kill() {
    let socket = "terminal-hub-test-m4-acl-manage";
    let (_store, addr, p_cookie, s_cookie) = fixture(socket).await;
    let c = reqwest::Client::new();

    // Primary creates, grants secondary ATTACH only.
    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&p_cookie))
        .json(&serde_json::json!({ "display_name": "noluck" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();
    let st = c
        .post(format!("http://{addr}/api/permissions/session/{id}"))
        .header("cookie", cookie_header(&p_cookie))
        .json(&serde_json::json!({ "user_email": "s@x", "capabilities": 1u32 }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 204);

    let rn = c
        .patch(format!("http://{addr}/api/sessions/{id}"))
        .header("cookie", cookie_header(&s_cookie))
        .json(&serde_json::json!({ "display_name": "stolen" }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(rn, 403);

    let rm = c
        .delete(format!("http://{addr}/api/sessions/{id}"))
        .header("cookie", cookie_header(&s_cookie))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(rm, 403);

    // Now grant MANAGE — same secondary CAN rename and kill.
    let st = c
        .post(format!("http://{addr}/api/permissions/session/{id}"))
        .header("cookie", cookie_header(&p_cookie))
        .json(&serde_json::json!({
            "user_email": "s@x",
            "capabilities": 1u32 | 4u32, // ATTACH + MANAGE
        }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 204);

    let rn = c
        .patch(format!("http://{addr}/api/sessions/{id}"))
        .header("cookie", cookie_header(&s_cookie))
        .json(&serde_json::json!({ "display_name": "now-mine" }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(rn, 204, "secondary with MANAGE may rename");

    let rm = c
        .delete(format!("http://{addr}/api/sessions/{id}"))
        .header("cookie", cookie_header(&s_cookie))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(rm, 204, "secondary with MANAGE may kill");

    kill_tmux(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_attach_to_ungranted_session_is_forbidden() {
    let socket = "terminal-hub-test-m4-acl-ungranted";
    let (_store, addr, p_cookie, s_cookie) = fixture(socket).await;
    let c = reqwest::Client::new();

    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&p_cookie))
        .json(&serde_json::json!({ "display_name": "private" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();

    // Secondary attempts WS attach with no permission row — handshake should fail.
    let url = format!("ws://{addr}/ws/attach/{id}");
    let mut req = url.as_str().into_client_request().unwrap();
    req.headers_mut()
        .insert("cookie", cookie_header(&s_cookie).parse().unwrap());
    let res = tokio_tungstenite::connect_async(req).await;
    assert!(
        res.is_err(),
        "ungranted secondary must not be able to attach"
    );

    kill_tmux(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_create_requires_peer_create_allowed_and_auto_grants() {
    let socket = "terminal-hub-test-m4-acl-create";
    let (store, addr, p_cookie, s_cookie) = fixture(socket).await;
    let c = reqwest::Client::new();

    // Without the flag, secondary's create is forbidden.
    let st = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&s_cookie))
        .json(&serde_json::json!({ "display_name": "denied" }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 403, "create without peer_create_allowed must 403");

    // Primary flips the flag.
    let st = c
        .post(format!("http://{addr}/api/permissions/peer-create"))
        .header("cookie", cookie_header(&p_cookie))
        .json(&serde_json::json!({
            "user_email": "s@x",
            "peer_id": "local",
            "allow": true,
        }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 204);

    // Now the secondary creates a session.
    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&s_cookie))
        .json(&serde_json::json!({ "display_name": "mine" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();

    // The creator is auto-granted full capabilities, and so is the primary.
    let caps_s = store
        .get_permission_caps("s@x", "local", &id)
        .await
        .unwrap();
    assert_eq!(caps_s, Some(7), "creator (secondary) auto-granted all caps");
    let caps_p = store
        .get_permission_caps("p@x", "local", &id)
        .await
        .unwrap();
    assert_eq!(caps_p, Some(7), "primary also auto-granted on the new session");

    // Secondary sees their own session immediately in /api/sessions.
    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&s_cookie))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = listed["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![id.as_str()]);

    kill_tmux(socket);
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_cannot_call_primary_only_grant_endpoints() {
    let socket = "terminal-hub-test-m4-acl-gate";
    let (_store, addr, p_cookie, s_cookie) = fixture(socket).await;
    let c = reqwest::Client::new();

    // Primary creates a session so we have a real id to point at.
    let cr: serde_json::Value = c
        .post(format!("http://{addr}/api/sessions"))
        .header("cookie", cookie_header(&p_cookie))
        .json(&serde_json::json!({ "display_name": "gate" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();

    // Secondary cannot list grants.
    let st = c
        .get(format!("http://{addr}/api/permissions/session/{id}"))
        .header("cookie", cookie_header(&s_cookie))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 403);

    // Secondary cannot grant.
    let st = c
        .post(format!("http://{addr}/api/permissions/session/{id}"))
        .header("cookie", cookie_header(&s_cookie))
        .json(&serde_json::json!({ "user_email": "s@x", "capabilities": 7u32 }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 403);

    // Secondary cannot revoke.
    let st = c
        .delete(format!("http://{addr}/api/permissions/session/{id}/s@x"))
        .header("cookie", cookie_header(&s_cookie))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 403);

    kill_tmux(socket);
}
