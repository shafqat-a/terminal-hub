//! Integration tests for the M4 users + permissions admin endpoints.
//!
//! Each test seeds users + cookies directly into the Store, then drives the
//! HTTP API over a random localhost port. Tmux is used only as a side-effect
//! of constructing the server (Manager::connect requires a live socket).

use base64::Engine;
use rand::RngCore;
use std::net::SocketAddr;
use std::process::Command;
use terminal_hub_server::db::Store;
use tokio::net::TcpListener;

const SOCKET: &str = "terminal-hub-test-m4-users";
const BOOT: &str = "_boot";

fn ensure() {
    let _ = Command::new("tmux")
        .args(["-L", SOCKET, "new-session", "-d", "-s", BOOT])
        .status();
}
fn kill() {
    let _ = Command::new("tmux")
        .args(["-L", SOCKET, "kill-server"])
        .status();
}

/// Seed a session cookie for `email` in `store`. Returns the raw cookie value
/// the caller should send as `th_session=<value>`.
async fn seed_cookie(store: &Store, email: &str) -> String {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let hash = terminal_hub_server::auth::sha256(value.as_bytes());
    store.insert_session(&hash, email, 3600).await.unwrap();
    value
}

async fn spawn(store: Store) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: SOCKET.into(),
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

#[tokio::test(flavor = "multi_thread")]
async fn primary_can_add_list_and_remove_secondary() {
    ensure();
    let store = Store::in_memory().unwrap();
    store
        .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
        .await
        .unwrap();
    let cookie = seed_cookie(&store, "p@x").await;
    let ch = cookie_header(&cookie);
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    // POST /api/users — add secondary.
    let resp = c
        .post(format!("http://{addr}/api/users"))
        .header("cookie", &ch)
        .json(&serde_json::json!({
            "email": "s@x",
            "pubkey": "ssh-ed25519 BBB",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "add: {}", resp.status());

    // GET /api/users — primary sees both.
    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/users"))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let users = listed["users"].as_array().unwrap();
    assert_eq!(users.len(), 2, "expected primary + secondary, got {users:?}");

    // DELETE /api/users/s@x — remove.
    let resp = c
        .delete(format!("http://{addr}/api/users/s@x"))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(store.get_user("s@x").await.unwrap().is_none());

    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_sees_only_own_user_row() {
    ensure();
    let store = Store::in_memory().unwrap();
    store
        .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
        .await
        .unwrap();
    store
        .upsert_user("s@x", "ssh-ed25519 BBB", "secondary")
        .await
        .unwrap();
    let cookie = seed_cookie(&store, "s@x").await;
    let ch = cookie_header(&cookie);
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/users"))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let users = listed["users"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["email"], "s@x");

    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn secondary_cannot_add_or_remove_users() {
    ensure();
    let store = Store::in_memory().unwrap();
    store
        .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
        .await
        .unwrap();
    store
        .upsert_user("s@x", "ssh-ed25519 BBB", "secondary")
        .await
        .unwrap();
    let cookie = seed_cookie(&store, "s@x").await;
    let ch = cookie_header(&cookie);
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    let resp = c
        .post(format!("http://{addr}/api/users"))
        .header("cookie", &ch)
        .json(&serde_json::json!({
            "email": "newbie@x",
            "pubkey": "ssh-ed25519 CCC",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "POST /api/users by secondary must 403");

    let resp = c
        .delete(format!("http://{addr}/api/users/p@x"))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn primary_grant_and_revoke_round_trip() {
    use terminal_hub_server::permissions::Capabilities;
    use terminal_hub_server::session_id::SessionId;
    ensure();
    let store = Store::in_memory().unwrap();
    store
        .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
        .await
        .unwrap();
    store
        .upsert_user("s@x", "ssh-ed25519 BBB", "secondary")
        .await
        .unwrap();
    let cookie = seed_cookie(&store, "p@x").await;
    let ch = cookie_header(&cookie);
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    let id = SessionId::new();

    // POST a grant for s@x on the synthetic session id.
    let resp = c
        .post(format!("http://{addr}/api/permissions/session/{id}"))
        .header("cookie", &ch)
        .json(&serde_json::json!({
            "user_email": "s@x",
            "capabilities": Capabilities::all_for_owner().0,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // GET grants for that session.
    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/permissions/session/{id}"))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grants = listed["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["user_email"], "s@x");
    assert_eq!(grants[0]["capabilities"], 7);
    assert_eq!(grants[0]["granted_by"], "p@x");

    // DELETE the grant.
    let resp = c
        .delete(format!(
            "http://{addr}/api/permissions/session/{id}/s@x"
        ))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let listed: serde_json::Value = c
        .get(format!("http://{addr}/api/permissions/session/{id}"))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(listed["grants"].as_array().unwrap().is_empty());

    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_create_toggle_primary_only() {
    ensure();
    let store = Store::in_memory().unwrap();
    store
        .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
        .await
        .unwrap();
    store
        .upsert_user("s@x", "ssh-ed25519 BBB", "secondary")
        .await
        .unwrap();
    let primary_cookie = seed_cookie(&store, "p@x").await;
    let secondary_cookie = seed_cookie(&store, "s@x").await;
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    // Secondary calling the toggle → 403.
    let resp = c
        .post(format!("http://{addr}/api/permissions/peer-create"))
        .header("cookie", cookie_header(&secondary_cookie))
        .json(&serde_json::json!({
            "user_email": "s@x",
            "peer_id": "local",
            "allow": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Primary granting peer-create to s@x.
    let resp = c
        .post(format!("http://{addr}/api/permissions/peer-create"))
        .header("cookie", cookie_header(&primary_cookie))
        .json(&serde_json::json!({
            "user_email": "s@x",
            "peer_id": "local",
            "allow": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(store.peer_create_allowed("s@x", "local").await.unwrap());

    // Revoke.
    let resp = c
        .post(format!("http://{addr}/api/permissions/peer-create"))
        .header("cookie", cookie_header(&primary_cookie))
        .json(&serde_json::json!({
            "user_email": "s@x",
            "peer_id": "local",
            "allow": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(!store.peer_create_allowed("s@x", "local").await.unwrap());

    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_remove_primary_via_api() {
    ensure();
    let store = Store::in_memory().unwrap();
    store
        .upsert_user("p@x", "ssh-ed25519 AAA", "primary")
        .await
        .unwrap();
    let cookie = seed_cookie(&store, "p@x").await;
    let ch = cookie_header(&cookie);
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    let resp = c
        .delete(format!("http://{addr}/api/users/p@x"))
        .header("cookie", &ch)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "removing primary must be rejected");

    kill();
}
