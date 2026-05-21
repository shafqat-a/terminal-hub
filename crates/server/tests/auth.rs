use base64::Engine;
use ed25519_dalek::Signer;
use rand::RngCore;
use std::net::SocketAddr;
use std::process::Command;
use terminal_hub_server::{db::Store, Config};
use tokio::net::TcpListener;

const SOCKET: &str = "terminal-hub-test-m3-auth";
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

fn make_user() -> (ed25519_dalek::SigningKey, String) {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
        sk.verifying_key().to_bytes(),
    ));
    (sk, pk.to_openssh().unwrap())
}

async fn spawn(store: Store) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    // webauthn-rs requires https:// or http://localhost as origin.
    let public_url = format!("http://localhost:{}/", addr.port());
    let cfg = Config {
        tmux_socket: SOCKET.into(),
        tmux_session: BOOT.into(),
        bind: addr.to_string(),
        public_url,
    };
    let app = terminal_hub_server::router_with(cfg, store).await.unwrap();
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_initiate_redeem_full_flow() {
    ensure();
    let store = Store::in_memory().unwrap();
    let (sk, pubkey_openssh) = make_user();
    store
        .upsert_user("alice@example.com", &pubkey_openssh, "primary")
        .await
        .unwrap();
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::builder().cookie_store(true).build().unwrap();

    // 1) Ask for a challenge.
    let ch: serde_json::Value = c
        .post(format!("http://{addr}/auth/challenge"))
        .json(&serde_json::json!({ "email": "alice@example.com" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge_b64 = ch["challenge"].as_str().unwrap().to_string();
    let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(challenge_b64.as_bytes())
        .unwrap();

    // 2) Sign and POST /auth/enroll/initiate.
    let sig = sk.sign(&auth_core::payload(&challenge_bytes));
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let init: serde_json::Value = c
        .post(format!("http://{addr}/auth/enroll/initiate"))
        .json(&serde_json::json!({
            "email": "alice@example.com",
            "challenge": &challenge_b64,
            "signature": sig_b64,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = init["token"].as_str().unwrap().to_string();
    assert!(init["bootstrap_url"]
        .as_str()
        .unwrap()
        .contains("/enroll.html?t="));

    // 3) Redeem the token via the passkey register-start endpoint.
    //    Real WebAuthn flow needs a browser; here we only assert that the token
    //    is accepted (HTTP 200) on first use and rejected (4xx) on second.
    let r1 = c
        .get(format!(
            "http://{addr}/auth/passkey/register/start?t={token}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200, "first redemption should succeed");
    let r2 = c
        .get(format!(
            "http://{addr}/auth/passkey/register/start?t={token}"
        ))
        .send()
        .await
        .unwrap();
    assert!(
        r2.status().is_client_error(),
        "second redemption must fail, got {}",
        r2.status()
    );
    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_signature_is_rejected() {
    ensure();
    let store = Store::in_memory().unwrap();
    let (_sk, pubkey_openssh) = make_user();
    store
        .upsert_user("eve@example.com", &pubkey_openssh, "primary")
        .await
        .unwrap();
    let addr = spawn(store).await;
    let c = reqwest::Client::new();
    let ch: serde_json::Value = c
        .post(format!("http://{addr}/auth/challenge"))
        .json(&serde_json::json!({ "email": "eve@example.com" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fake = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
    let resp = c
        .post(format!("http://{addr}/auth/enroll/initiate"))
        .json(&serde_json::json!({
            "email": "eve@example.com",
            "challenge": ch["challenge"],
            "signature": fake,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_route_requires_cookie() {
    ensure();
    let store = Store::in_memory().unwrap();
    let addr = spawn(store).await;
    let c = reqwest::Client::new();
    let r = c
        .get(format!("http://{addr}/api/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = c
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    kill();
}
