//! Interactive WebSocket session handler.
//!
//! Wire protocol (Go-compatible):
//! - Server→client: Text frames carrying JSON `{"type":"output","data":"..."}`.
//! - Client→server: Text JSON `{"type":"input"|"resize"|"paste-image",...}` or Binary (raw PTY bytes).
//! - On attach: capture-pane snapshot with LF→CRLF, sent as first output frame.
//! - Ping every 30s; 60s inbound silence = disconnect.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use axum::extract::ws::{Message, WebSocket};

use crate::app::SharedState;
use crate::handlers::json_error;
use crate::session::Session;

/// GET /ws/:id — WebSocket upgrade handler (auth-gated in the router).
pub async fn ws_session(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(sess) = state.manager.get(&id).await else {
        return json_error(StatusCode::NOT_FOUND, &format!("session {id} not found"));
    };
    let data_dir = state.cfg.data_dir.clone();
    ws.on_upgrade(move |socket| pump(socket, sess, data_dir, false))
}

/// GET /ws/share/:token — Public, read-only WebSocket for a share link.
///
/// No auth required. Token is validated via store.redeem_share before upgrade.
/// Go parity: invalid token → 404 text; session not live → 404 text; valid → upgrade read_only=true.
pub async fn ws_share(
    State(state): State<SharedState>,
    Path(token): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64;

    let redeemed = match state.store.redeem_share(&hash, now) {
        Ok(r) => r,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response();
        }
    };
    let Some((session_id, _mode)) = redeemed else {
        return (StatusCode::NOT_FOUND, "share link invalid or expired\n").into_response();
    };

    let Some(sess) = state.manager.get(&session_id).await else {
        return (StatusCode::NOT_FOUND, "session not running\n").into_response();
    };

    let data_dir = state.cfg.data_dir.clone();
    ws.on_upgrade(move |socket| pump(socket, sess, data_dir, true))
}

/// Message sent from client → server.
#[derive(Debug, Deserialize)]
struct ClientMsg {
    #[serde(rename = "type", default)]
    msg_type: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    rows: u16,
    #[serde(default)]
    cols: u16,
    #[serde(default)]
    mime: String,
}

/// Drive the WebSocket connection: snapshot repaint on attach, then fan-out
/// PTY output to client and write client input/resize back to the PTY.
///
/// `read_only`: when true, input/resize/paste-image text frames AND binary
/// frames are silently ignored (loop continues, last_inbound still updated).
/// All output forwarding, pings, and lifecycle signals are identical to a
/// normal (read_only=false) connection — share viewers count as viewers.
pub async fn pump(socket: WebSocket, sess: Arc<Session>, data_dir: PathBuf, read_only: bool) {
    sess.viewer_attached();

    // Subscribe BEFORE capture-pane so we cannot miss any output bytes that
    // arrive while the snapshot command is running (Go has the same order:
    // AddClient happens before Snapshot).
    // Flip side: bytes emitted during capture appear in both snapshot and live stream — transient double-paint, self-correcting.
    let mut rx = sess.pty.output.subscribe();

    let (mut sink, mut stream) = socket.split();

    // Snapshot: capture current pane contents, replace bare LF with CRLF
    // (byte-level, verbatim Go bytes.ReplaceAll), send as first output frame.
    let tmux_name = tmux::session_name(&sess.id);
    match tmux::capture_pane(&data_dir, &tmux_name, 2000).await {
        Ok(bytes) => {
            // Replace all bare \n with \r\n (byte-level) using the shared helper.
            let crlf_bytes = crate::exec_history::crlf(&bytes);
            let data = String::from_utf8_lossy(&crlf_bytes); // Lossy = Go parity; M5 adds UTF-8 boundary buffering (spec §4.1).
            let frame = serde_json::json!({"type": "output", "data": data}).to_string();
            // 10s write timeout for the snapshot frame.
            let send_result =
                tokio::time::timeout(Duration::from_secs(10), sink.send(Message::Text(frame)))
                    .await;
            if matches!(send_result, Err(_) | Ok(Err(_))) {
                sess.viewer_detached();
                return;
            }
        }
        Err(e) => {
            tracing::warn!("capture-pane failed for session {}: {e}", sess.id);
            // Continue without snapshot.
        }
    }

    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
    // Skip the immediate first tick so we do not send a ping right on connect.
    ping_interval.tick().await;
    let mut last_inbound = Instant::now();

    // Subscribe BEFORE loop; resolves when Manager::delete signals closure.
    let mut closed_rx = sess.closed.subscribe();

    loop {
        tokio::select! {
            // Manager::delete signalled — tell the client and stop.
            _ = closed_rx.changed() => {
                break;
            }

            // PTY output → client.
            out = rx.recv() => match out {
                Ok(bytes) => {
                    let data = String::from_utf8_lossy(&bytes); // Lossy = Go parity; M5 adds UTF-8 boundary buffering (spec §4.1).
                    let frame = serde_json::json!({"type": "output", "data": data}).to_string();
                    let send_result = tokio::time::timeout(
                        Duration::from_secs(10),
                        sink.send(Message::Text(frame)),
                    )
                    .await;
                    if matches!(send_result, Err(_) | Ok(Err(_))) {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },

            // Client → PTY input.
            frame = stream.next() => {
                last_inbound = Instant::now();
                match frame {
                    Some(Ok(Message::Text(t))) => {
                        if read_only {
                            // Silently ignore all text frames in read-only mode.
                            continue;
                        }
                        match serde_json::from_str::<ClientMsg>(&t) {
                            Ok(msg) => match msg.msg_type.as_str() {
                                "input" => {
                                    sess.pty.write(msg.data.as_bytes()).unwrap_or_else(|e| tracing::debug!("pty write failed: {e}"));
                                }
                                "resize" if msg.rows > 0 && msg.cols > 0 => {
                                    sess.pty.resize(msg.rows, msg.cols).ok();
                                    *sess.size.lock().unwrap_or_else(|e| e.into_inner()) =
                                        (msg.cols, msg.rows);
                                }
                                "paste-image" => {
                                    tracing::debug!(
                                        "paste-image deferred to M5 (mime={})",
                                        msg.mime
                                    );
                                }
                                _ => {
                                    // Unknown type — ignore.
                                }
                            },
                            Err(_) => {
                                // Parse failure — ignore per spec.
                            }
                        }
                    }
                    Some(Ok(Message::Binary(b))) => {
                        if read_only {
                            // Silently ignore binary frames in read-only mode.
                            continue;
                        }
                        sess.pty.write(&b).unwrap_or_else(|e| tracing::debug!("pty write failed: {e}"));
                    }
                    Some(Ok(_)) => {
                        // Ping/Pong/Close — axum auto-handles pings; nothing to do.
                    }
                    Some(Err(_)) | None => break,
                }
            },

            // Keepalive: ping every 30s; close if silent for 60s.
            _ = ping_interval.tick() => {
                if last_inbound.elapsed() > Duration::from_secs(60) {
                    break;
                }
                let send_result = tokio::time::timeout(
                    Duration::from_secs(10),
                    sink.send(Message::Ping(vec![])),
                )
                .await;
                if matches!(send_result, Err(_) | Ok(Err(_))) {
                    break;
                }
            }
        }
    }

    sess.viewer_detached();
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use sha2::{Digest, Sha256};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

    use crate::app::{build_app, build_state, SharedState};
    use crate::config::Config;

    /// Spawn a real TCP server for integration tests.
    /// Returns (addr, state, tempdir_guard).
    async fn spawn_server() -> (SocketAddr, SharedState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::from_lookup(|key| match key {
            "AI_CONDUCTOR_DATA_DIR" => Some(dir.path().display().to_string()),
            "AI_CONDUCTOR_PASSWORD" => Some("testpass".into()),
            _ => None,
        })
        .unwrap();
        let state = build_state(cfg).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_app(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr, state, dir)
    }

    /// Read text frames until we find one whose `data` field contains `needle`,
    /// within `budget`.
    async fn wait_for_output(
        stream: &mut futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
        needle: &str,
        budget: Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(Ok(TungsteniteMessage::Text(t)))) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                        if v["data"].as_str().unwrap_or("").contains(needle) {
                            return true;
                        }
                    }
                }
                Ok(Some(Ok(_))) => continue, // Ping/Pong/Binary
                Ok(Some(Err(_))) | Ok(None) | Err(_) => return false,
            }
        }
    }

    #[tokio::test]
    async fn ws_unknown_session_is_404() {
        let (addr, state, _dir) = spawn_server().await;
        let expires = crate::handlers::unix_now() + 3600;
        state.store.add_auth_session("wstoken404", expires).unwrap();

        let url = format!("ws://{addr}/ws/zzzzzzzz?token=wstoken404");
        let result = tokio_tungstenite::connect_async(&url).await;
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                assert_eq!(resp.status(), 404, "expected 404, got {}", resp.status());
            }
            other => panic!("expected HTTP 404 error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn ws_requires_auth() {
        let (addr, _state, _dir) = spawn_server().await;
        let url = format!("ws://{addr}/ws/anysession");
        let result = tokio_tungstenite::connect_async(&url).await;
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                assert_eq!(resp.status(), 401, "expected 401, got {}", resp.status());
            }
            other => panic!("expected HTTP 401 error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn ws_end_to_end() {
        let (addr, state, _dir) = spawn_server().await;

        // Create a real session.
        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();

        // Register a valid auth token.
        let expires = crate::handlers::unix_now() + 3600;
        state.store.add_auth_session("wse2etoken", expires).unwrap();

        // Connect via WebSocket.
        let url = format!("ws://{addr}/ws/{id}?token=wse2etoken");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect");
        let (mut sink, mut stream) = ws.split();

        // First message MUST be type=="output" (snapshot).
        let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timeout waiting for snapshot")
            .expect("stream ended")
            .expect("ws error");
        if let TungsteniteMessage::Text(t) = first {
            let v: serde_json::Value = serde_json::from_str(&t).expect("first frame JSON");
            assert_eq!(
                v["type"].as_str().unwrap(),
                "output",
                "first frame must be type=output, got: {v}"
            );
        } else {
            panic!("first frame was not Text: {first:?}");
        }

        // Send input: echo a unique string.
        let input = serde_json::json!({"type": "input", "data": "echo WSPROOF\n"}).to_string();
        sink.send(TungsteniteMessage::Text(input))
            .await
            .expect("send input");

        // Read until we see WSPROOF in output (10s budget).
        let found = wait_for_output(&mut stream, "WSPROOF", Duration::from_secs(10)).await;
        assert!(found, "expected WSPROOF in output frames within 10s");

        // Send resize.
        let resize = serde_json::json!({"type": "resize", "cols": 120, "rows": 40}).to_string();
        sink.send(TungsteniteMessage::Text(resize))
            .await
            .expect("send resize");

        // Connection should stay alive — send another echo.
        let input2 = serde_json::json!({"type": "input", "data": "echo WSPROOF2\n"}).to_string();
        sink.send(TungsteniteMessage::Text(input2))
            .await
            .expect("send input2");
        let found2 = wait_for_output(&mut stream, "WSPROOF2", Duration::from_secs(10)).await;
        assert!(found2, "expected WSPROOF2 in output frames after resize");

        // Send a Binary frame — raw CR.
        sink.send(TungsteniteMessage::Binary(b"\r".to_vec()))
            .await
            .expect("send binary");

        // Still alive: another echo.
        let input3 = serde_json::json!({"type": "input", "data": "echo ALIVE\n"}).to_string();
        sink.send(TungsteniteMessage::Text(input3))
            .await
            .expect("send input3");
        let found3 = wait_for_output(&mut stream, "ALIVE", Duration::from_secs(10)).await;
        assert!(found3, "connection should be alive after Binary frame");

        // Close.
        sink.send(TungsteniteMessage::Close(None)).await.ok();

        // Cleanup.
        state.manager.delete(&id).await.ok();
    }

    #[tokio::test]
    async fn resize_applies_to_tmux() {
        let (addr, state, dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();
        let tmux_name = tmux::session_name(&id);

        let expires = crate::handlers::unix_now() + 3600;
        state
            .store
            .add_auth_session("wsresizetoken", expires)
            .unwrap();

        // Connect.
        let url = format!("ws://{addr}/ws/{id}?token=wsresizetoken");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect");
        let (mut sink, mut stream) = ws.split();

        // Drain snapshot.
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .ok();

        // Send resize to 120 cols × 40 rows.
        let resize = serde_json::json!({"type": "resize", "cols": 120, "rows": 40}).to_string();
        sink.send(TungsteniteMessage::Text(resize))
            .await
            .expect("send resize");

        // Give the PTY ioctl a moment to propagate.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Poll tmux display-message for window_width up to 3s.
        let data_dir = dir.path().to_path_buf();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut width_ok = false;
        while std::time::Instant::now() < deadline {
            if let Ok(out) = tmux::run(
                &data_dir,
                &["display-message", "-p", "-t", &tmux_name, "#{window_width}"],
            )
            .await
            {
                if out.trim_ascii() == b"120" {
                    width_ok = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();

        assert!(
            width_ok,
            "tmux window_width should become 120 after resize message"
        );
    }

    #[tokio::test]
    async fn delete_disconnects_viewer() {
        let (addr, state, _dir) = spawn_server().await;

        // Create a real session.
        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();

        // Register a valid auth token.
        let expires = crate::handlers::unix_now() + 3600;
        state
            .store
            .add_auth_session("wsdeletedisconnect", expires)
            .unwrap();

        // Connect via WebSocket.
        let url = format!("ws://{addr}/ws/{id}?token=wsdeletedisconnect");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect");
        let (_sink, mut stream) = ws.split();

        // Drain the snapshot frame.
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;

        // Delete the session -- should signal all viewers to disconnect.
        state.manager.delete(&id).await.expect("delete");

        // Expect the WS stream to end (None, Err, or Close frame) within 5s.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                panic!("viewer socket did not close within 5s after session delete");
            }
            match tokio::time::timeout(remaining, stream.next()).await {
                Ok(None) | Err(_) => break, // stream ended -- pass
                Ok(Some(Ok(TungsteniteMessage::Close(_)))) => break, // server sent Close -- pass
                Ok(Some(Err(_))) => break,  // transport error -- pass
                Ok(Some(Ok(_))) => continue, // Ping/Pong/Text -- keep draining
            }
        }
    }

    // ---- Share viewer WebSocket tests ---------------------------------------

    /// Helper: insert a share row directly (bypassing HTTP) for testing.
    fn insert_share_direct(store: &store::Store, session_id: &str, raw_token: &str) -> i64 {
        let hash = Sha256::digest(raw_token.as_bytes()).to_vec();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now + 3600;
        store
            .insert_share(
                "sharetest01234567",
                &hash,
                session_id,
                "read",
                now,
                expires_at,
            )
            .unwrap();
        expires_at
    }

    #[tokio::test]
    async fn share_page_valid_200() {
        let (addr, state, _dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();
        let raw_token = "a".repeat(64);
        insert_share_direct(&state.store, &id, &raw_token);

        let url = format!("http://{addr}/s/{raw_token}");
        let resp = reqwest::get(&url).await.expect("GET /s/:token");
        assert_eq!(resp.status(), 200, "expected 200 for valid share token");
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/html"), "expected text/html, got: {ct}");
        let body = resp.text().await.unwrap();
        assert!(body.contains("VIEW ONLY"), "body must contain VIEW ONLY");
        assert!(
            !body.contains("__BASE_PATH__"),
            "body must not contain __BASE_PATH__"
        );
        assert!(!body.contains("{{"), "body must not contain {{");

        state.manager.delete(&id).await.ok();
    }

    #[tokio::test]
    async fn share_page_invalid_404() {
        let (addr, _state, _dir) = spawn_server().await;

        let url = format!("http://{addr}/s/garbagetoken0000");
        let resp = reqwest::get(&url).await.expect("GET /s/:bad");
        assert_eq!(resp.status(), 404, "expected 404 for bad share token");
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("isn't available"),
            "404 body must contain text from share_invalid.html (got: {body})"
        );
    }

    #[tokio::test]
    async fn ws_share_read_only() {
        let (addr, state, _dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();
        let raw_token = "b".repeat(64);
        insert_share_direct(&state.store, &id, &raw_token);

        // Connect WITHOUT auth.
        let url = format!("ws://{addr}/ws/share/{raw_token}");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS share connect");
        let (mut sink, mut stream) = ws.split();

        // First frame must be type=="output" (snapshot).
        let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timeout waiting for snapshot")
            .expect("stream ended")
            .expect("ws error");
        if let TungsteniteMessage::Text(t) = first {
            let v: serde_json::Value = serde_json::from_str(&t).expect("JSON");
            assert_eq!(v["type"].as_str().unwrap(), "output");
        } else {
            panic!("first frame not Text: {first:?}");
        }

        // Send input frame — must be silently dropped (not executed).
        let input =
            serde_json::json!({"type": "input", "data": "echo SHOULD_NOT_RUN\n"}).to_string();
        sink.send(TungsteniteMessage::Text(input))
            .await
            .expect("send input");
        // Also send a binary frame — must be silently dropped.
        sink.send(TungsteniteMessage::Binary(b"x".to_vec()))
            .await
            .expect("send binary");

        // Wait for the server to process the frames (they are silently dropped).
        tokio::time::sleep(Duration::from_millis(1200)).await;

        // Verify SHOULD_NOT_RUN did NOT appear via tmux capture-pane.
        let tmux_name = tmux::session_name(&id);
        let capture = tmux::capture_pane(_dir.path(), &tmux_name, 2000)
            .await
            .unwrap_or_default();
        let capture_str = String::from_utf8_lossy(&capture);
        assert!(
            !capture_str.contains("SHOULD_NOT_RUN"),
            "read-only: input must not be forwarded to pty (capture: {capture_str})"
        );

        // The connection should still be alive — write via sess.pty directly.
        sess.pty.write(b"echo VISIBLE\n").expect("pty write");

        // Read until VISIBLE appears in output stream.
        let found = wait_for_output(&mut stream, "VISIBLE", Duration::from_secs(10)).await;
        assert!(found, "VISIBLE echo must appear in share WS output stream");

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    #[tokio::test]
    async fn ws_share_revoked_404() {
        let (addr, state, _dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();
        let raw_token = "c".repeat(64);
        insert_share_direct(&state.store, &id, &raw_token);

        // Revoke by revoking the share id we inserted.
        state.store.revoke_share("sharetest01234567").unwrap();

        let url = format!("ws://{addr}/ws/share/{raw_token}");
        let result = tokio_tungstenite::connect_async(&url).await;
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                assert_eq!(resp.status(), 404, "expected 404 after revoke");
            }
            other => panic!("expected HTTP 404, got: {other:?}"),
        }

        state.manager.delete(&id).await.ok();
    }

    #[tokio::test]
    async fn ws_share_dead_session_404() {
        let (addr, state, _dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();
        let raw_token = "d".repeat(64);
        insert_share_direct(&state.store, &id, &raw_token);

        // Delete the session so it is no longer live.
        state.manager.delete(&id).await.expect("delete");

        let url = format!("ws://{addr}/ws/share/{raw_token}");
        let result = tokio_tungstenite::connect_async(&url).await;
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                assert_eq!(resp.status(), 404, "expected 404 for dead session");
            }
            other => panic!("expected HTTP 404, got: {other:?}"),
        }
    }
}
