//! Interactive WebSocket session handler.
//!
//! Wire protocol (Go-compatible):
//! - Server→client: Text frames carrying JSON `{"type":"output","data":"..."}`.
//! - Client→server: Text JSON `{"type":"input"|"resize"|"paste-image",...}` or Binary (raw PTY bytes).
//! - On attach: capture-pane snapshot with LF→CRLF, sent as first output frame,
//!   then a re-assert frame for any active DEC private modes (spec §4.3).
//! - Live output: per-client UTF-8 boundary carry (§4.1) + UAX #15 stream-safe
//!   transform (§4.6); on broadcast lag the client is re-synced with a fresh
//!   snapshot instead of a torn stream (§4.5).
//! - Ping every 30s; 60s inbound silence = disconnect.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use unicode_normalization::UnicodeNormalization;

use axum::extract::ws::{Message, WebSocket};

use crate::app::SharedState;
use crate::handlers::json_error;
use crate::session::Session;

// ---- Output framing helpers (spec §4.1, §4.6) -------------------------------

/// Per-client carry of an incomplete trailing UTF-8 sequence across broadcast
/// chunks (spec §4.1). PTY reads can split a multibyte character anywhere;
/// `feed` decodes what is complete, holds back 0–3 trailing bytes that form a
/// valid sequence prefix, and replaces truly invalid bytes with U+FFFD
/// (same replacement scheme as `String::from_utf8_lossy`).
struct Utf8Carry {
    rem: Vec<u8>,
}

impl Utf8Carry {
    fn new() -> Self {
        Utf8Carry { rem: Vec::new() }
    }

    /// Decode `chunk` (prefixed by any carried bytes) into complete UTF-8.
    fn feed(&mut self, chunk: &[u8]) -> String {
        // Hot path: no carry pending — decode the chunk slice in place.
        let joined;
        let mut input: &[u8] = if self.rem.is_empty() {
            chunk
        } else {
            joined = [self.rem.as_slice(), chunk].concat();
            self.rem.clear();
            &joined
        };

        let mut out = String::with_capacity(input.len());
        loop {
            match std::str::from_utf8(input) {
                Ok(s) => {
                    out.push_str(s);
                    return out;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    // Bytes up to `valid` are known-good UTF-8.
                    out.push_str(
                        std::str::from_utf8(&input[..valid]).expect("validated by valid_up_to"),
                    );
                    match e.error_len() {
                        // Invalid sequence of known length: replace, keep going
                        // at the next byte so valid trailing bytes survive.
                        Some(len) => {
                            out.push('\u{FFFD}');
                            input = &input[valid + len..];
                        }
                        // Incomplete trailing sequence: carry it (≤3 bytes by
                        // UTF-8 construction) into the next chunk.
                        None => {
                            self.rem.extend_from_slice(&input[valid..]);
                            return out;
                        }
                    }
                }
            }
        }
    }

    /// Drop any pending bytes. Used on lag-resync: the missed chunks make the
    /// carried prefix meaningless.
    fn clear(&mut self) {
        self.rem.clear();
    }
}

/// UAX #15 stream-safe transform (spec §4.6): caps pathological combining-mark
/// runs by inserting U+034F CGJ after 30 nonstarters, so hostile output cannot
/// blow up xterm.js cell rendering. ASCII (no nonstarters) passes through
/// without reallocation; everything else is unchanged unless a run overflows.
fn stream_safe(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        return Cow::Borrowed(text);
    }
    Cow::Owned(text.chars().stream_safe().collect())
}

/// Serialize one server→client output frame.
fn output_frame(data: &str) -> String {
    serde_json::json!({"type": "output", "data": data}).to_string()
}

/// Send `frame` with the standard 10s write timeout. False = connection dead.
async fn send_text(sink: &mut SplitSink<WebSocket, Message>, frame: String) -> bool {
    let send_result =
        tokio::time::timeout(Duration::from_secs(10), sink.send(Message::Text(frame))).await;
    !matches!(send_result, Err(_) | Ok(Err(_)))
}

/// Repaint a client from scratch: one frame re-asserting all active DEC
/// private modes (spec §4.3), then the capture-pane snapshot frame. Used on
/// attach and on lag-resync (§4.5). Returns false when the socket is dead.
///
/// Order matters: re-assert MUST precede the snapshot. tmux asserts alt
/// screen (?1049h) at attach, so the session scanner virtually always holds
/// it active; sending it after the snapshot would switch xterm.js to a
/// cleared alt buffer and wipe the snapshot just painted (blank screen until
/// the pane next emits output). Clear-then-paint is safe; paint-then-clear
/// is not.
async fn send_resync(
    sink: &mut SplitSink<WebSocket, Message>,
    sess: &Session,
    data_dir: &std::path::Path,
    tmux_name: &str,
) -> bool {
    // Mode re-assert frame: skipped entirely when no tracked mode is active.
    let reassert = sess
        .pty
        .modes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .reassert_sequence();
    if !reassert.is_empty() && !send_text(sink, output_frame(&reassert)).await {
        return false;
    }

    match tmux::capture_pane(data_dir, tmux_name, 2000).await {
        Ok(bytes) => {
            // Replace all bare \n with \r\n (byte-level) using the shared
            // helper. capture-pane output is complete, so lossy decode (no
            // carry) is safe here.
            let crlf_bytes = crate::exec_history::crlf(&bytes);
            let data = String::from_utf8_lossy(&crlf_bytes);
            if !send_text(sink, output_frame(&stream_safe(&data))).await {
                return false;
            }
        }
        Err(e) => {
            tracing::warn!("capture-pane failed for session {}: {e}", sess.id);
            // Continue without snapshot.
        }
    }
    true
}

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

    // Attach repaint: capture-pane snapshot (bare LF → CRLF, verbatim Go
    // bytes.ReplaceAll) followed by the active-mode re-assert frame.
    let tmux_name = tmux::session_name(&sess.id);
    if !send_resync(&mut sink, &sess, &data_dir, &tmux_name).await {
        sess.viewer_detached();
        return;
    }

    // Live-stream UTF-8 carry: broadcast chunks may split multibyte sequences.
    let mut carry = Utf8Carry::new();

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
                    let text = carry.feed(&bytes);
                    if text.is_empty() {
                        // Whole chunk was an incomplete sequence — held back.
                        continue;
                    }
                    if !send_text(&mut sink, output_frame(&stream_safe(&text))).await {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // The client missed `n` chunks; its view is corrupt.
                    // Re-sync with a fresh snapshot + mode re-asserts
                    // instead of streaming a torn tail (spec §4.5).
                    // Resubscribe FIRST: a lagged receiver repositions to the
                    // oldest retained chunk, which would replay up to the full
                    // buffer of stale pre-snapshot output on top of the fresh
                    // snapshot (and immediately re-lag under pressure).
                    // resubscribe() starts at the tail instead; bytes emitted
                    // during capture-pane double-paint and self-correct, same
                    // as the attach path.
                    tracing::debug!("session {}: client lagged {n} chunks, resyncing", sess.id);
                    rx = rx.resubscribe();
                    carry.clear();
                    if !send_resync(&mut sink, &sess, &data_dir, &tmux_name).await {
                        break;
                    }
                }
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
                                    // Go StdEncoding = standard alphabet, padded.
                                    // Errors never disconnect: log and keep pumping.
                                    match base64::Engine::decode(
                                        &base64::engine::general_purpose::STANDARD,
                                        &msg.data,
                                    ) {
                                        Ok(img) => {
                                            if let Err(e) =
                                                sess.paste_image(&img, &msg.mime, &data_dir).await
                                            {
                                                tracing::warn!(
                                                    "session {}: paste image failed: {e}",
                                                    sess.id
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "session {}: bad paste-image data: {e}",
                                                sess.id
                                            );
                                        }
                                    }
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

    use super::{stream_safe, Utf8Carry};

    // ---- Utf8Carry unit tests (spec §4.1) ------------------------------------

    /// Multibyte corpus: CJK, emoji ZWJ family, combining marks, mixed ASCII.
    const UTF8_CORPUS: &[&str] = &[
        "漢字かなカナ한글",
        "👨‍👩‍👧‍👦 family 👍🏽",
        "e\u{301}a\u{300}\u{316}o\u{302}\u{303}\u{304}",
        "plain ascii $ ls -la\r\n",
        "mix: 漢👀é\u{200d}🦺 end",
    ];

    /// Every 2-chunk split of every corpus entry reassembles losslessly.
    #[test]
    fn utf8_carry_lossless_at_every_split_point() {
        for text in UTF8_CORPUS {
            let bytes = text.as_bytes();
            for i in 0..=bytes.len() {
                let mut carry = Utf8Carry::new();
                let mut out = carry.feed(&bytes[..i]);
                out.push_str(&carry.feed(&bytes[i..]));
                assert_eq!(&out, *text, "split at byte {i} of {text:?}");
                assert!(carry.rem.is_empty(), "no leftover after full input");
            }
        }
    }

    /// Byte-by-byte feeding (worst-case splits) also reassembles losslessly.
    #[test]
    fn utf8_carry_lossless_byte_by_byte() {
        for text in UTF8_CORPUS {
            let mut carry = Utf8Carry::new();
            let mut out = String::new();
            for &b in text.as_bytes() {
                out.push_str(&carry.feed(&[b]));
            }
            assert_eq!(&out, *text);
        }
    }

    /// Three-chunk splits across a 4-byte scalar (every pair of cut points).
    #[test]
    fn utf8_carry_three_chunk_splits() {
        let text = "a😀b"; // 61 F0 9F 98 80 62
        let bytes = text.as_bytes();
        for i in 0..=bytes.len() {
            for j in i..=bytes.len() {
                let mut carry = Utf8Carry::new();
                let mut out = carry.feed(&bytes[..i]);
                out.push_str(&carry.feed(&bytes[i..j]));
                out.push_str(&carry.feed(&bytes[j..]));
                assert_eq!(&out, text, "splits at {i},{j}");
            }
        }
    }

    /// Truly invalid bytes become U+FFFD without eating valid following bytes.
    #[test]
    fn utf8_carry_invalid_bytes_replaced_without_loss() {
        let mut carry = Utf8Carry::new();
        // Lone continuation byte, then valid text.
        assert_eq!(carry.feed(b"\x80abc"), "\u{FFFD}abc");
        // Overlong/invalid lead followed by ASCII: FE is never valid.
        assert_eq!(carry.feed(b"a\xfeb"), "a\u{FFFD}b");
        // Truncated 3-byte sequence interrupted by ASCII (cannot continue).
        assert_eq!(carry.feed(b"\xe6\xbcZ"), "\u{FFFD}Z");
        assert!(carry.rem.is_empty());
    }

    /// An incomplete tail followed by NON-continuation bytes in the next chunk
    /// resolves to U+FFFD for the carried prefix, keeping the new bytes.
    #[test]
    fn utf8_carry_carried_prefix_invalidated_by_next_chunk() {
        let mut carry = Utf8Carry::new();
        assert_eq!(carry.feed(b"\xf0\x9f"), ""); // held: prefix of 4-byte seq
        assert_eq!(carry.feed(b"ok"), "\u{FFFD}ok");
        assert!(carry.rem.is_empty());
    }

    /// Matches String::from_utf8_lossy on whole (unsplit) inputs.
    #[test]
    fn utf8_carry_matches_lossy_on_complete_chunks() {
        let cases: &[&[u8]] = &[
            b"\xf0\x9f\x98\x80 ok",
            b"\xff\xfe\xfd",
            b"abc\xe6\xbc\xa2def",
            b"\xed\xa0\x80x", // UTF-16 surrogate — always invalid
        ];
        for &case in cases {
            let mut carry = Utf8Carry::new();
            let mut out = carry.feed(case);
            // Flush: a trailing incomplete sequence is U+FFFD under lossy.
            if !carry.rem.is_empty() {
                out.push('\u{FFFD}');
                carry.clear();
            }
            assert_eq!(out, String::from_utf8_lossy(case), "case {case:?}");
        }
    }

    // ---- stream_safe unit tests (spec §4.6) ----------------------------------

    /// 1000 combining marks on one base char get CGJ (U+034F) breaks inserted.
    #[test]
    fn stream_safe_caps_combining_mark_bomb() {
        let bomb: String = std::iter::once('a')
            .chain(std::iter::repeat_n('\u{0301}', 1000))
            .collect();
        let out = stream_safe(&bomb);
        assert!(out.contains('\u{034F}'), "CGJ must be inserted");
        // All original marks survive — only CGJ is added.
        assert_eq!(out.chars().filter(|&c| c == '\u{0301}').count(), 1000);
    }

    /// Ordinary ASCII and CJK pass through byte-identical (borrowed for ASCII).
    #[test]
    fn stream_safe_passes_ordinary_text_unchanged() {
        let ascii = "ls -la\r\n$ \x1b[1;31mred\x1b[0m";
        assert!(matches!(stream_safe(ascii), std::borrow::Cow::Borrowed(s) if s == ascii));

        for text in ["漢字テスト한글", "👨‍👩‍👧‍👦 emoji", "café e\u{301}"] {
            assert_eq!(stream_safe(text).as_ref(), text, "must be identical");
        }
    }

    /// Spawn a real TCP server for integration tests.
    /// Returns (addr, state, tempdir_guard).
    async fn spawn_server() -> (SocketAddr, SharedState, tempfile::TempDir) {
        spawn_server_with(|_| None).await
    }

    /// Like [`spawn_server`] but with additional config overrides layered on
    /// top of the defaults (mirrors `test_app_with`).
    async fn spawn_server_with(
        extra: impl Fn(&str) -> Option<String> + 'static,
    ) -> (SocketAddr, SharedState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::from_lookup(|key| {
            if let Some(v) = extra(key) {
                return Some(v);
            }
            match key {
                "AI_CONDUCTOR_DATA_DIR" => Some(dir.path().display().to_string()),
                "AI_CONDUCTOR_PASSWORD" => Some("testpass".into()),
                _ => None,
            }
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

    /// Read text frames until `needle` appears in accumulated `data`,
    /// returning everything accumulated so far. Empty return = budget blown.
    async fn collect_output_until(
        stream: &mut futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
        needle: &str,
        budget: Duration,
    ) -> String {
        let deadline = tokio::time::Instant::now() + budget;
        let mut acc = String::new();
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return String::new();
            }
            match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(Ok(TungsteniteMessage::Text(t)))) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                        acc.push_str(v["data"].as_str().unwrap_or(""));
                        if acc.contains(needle) {
                            return acc;
                        }
                    }
                }
                Ok(Some(Ok(_))) => continue, // Ping/Pong/Binary
                Ok(Some(Err(_))) | Ok(None) | Err(_) => return String::new(),
            }
        }
    }

    /// Create a session + authed WS connection; returns (sink, stream, id).
    /// The first (snapshot) frame is NOT consumed.
    async fn connect_session(
        addr: SocketAddr,
        state: &SharedState,
        token: &str,
    ) -> (
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            TungsteniteMessage,
        >,
        futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
        String,
    ) {
        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();
        let expires = crate::util::unix_now() + 3600;
        state.store.add_auth_session(token, expires).unwrap();
        let url = format!("ws://{addr}/ws/{id}?token={token}");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect");
        let (sink, stream) = ws.split();
        (sink, stream, id)
    }

    /// Send one input frame.
    async fn send_input(
        sink: &mut futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            TungsteniteMessage,
        >,
        data: &str,
    ) {
        let frame = serde_json::json!({"type": "input", "data": data}).to_string();
        sink.send(TungsteniteMessage::Text(frame))
            .await
            .expect("send input");
    }

    #[tokio::test]
    async fn ws_unknown_session_is_404() {
        let (addr, state, _dir) = spawn_server().await;
        let expires = crate::util::unix_now() + 3600;
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
        let expires = crate::util::unix_now() + 3600;
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

        let expires = crate::util::unix_now() + 3600;
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
        let expires = crate::util::unix_now() + 3600;
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

    // ---- U4: base-path WebSocket test --------------------------------------

    /// WS round-trip through the "/app" mount: connect to /app/ws/<id>?token=,
    /// receive the snapshot frame, send input, and observe its output.
    #[tokio::test]
    async fn ws_round_trip_under_base_path() {
        let (addr, state, _dir) =
            spawn_server_with(|key| (key == "AI_CONDUCTOR_BASE_PATH").then(|| "/app".into())).await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();

        let expires = crate::util::unix_now() + 3600;
        state
            .store
            .add_auth_session("wsbasetoken", expires)
            .unwrap();

        let url = format!("ws://{addr}/app/ws/{id}?token=wsbasetoken");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect under /app");
        let (mut sink, mut stream) = ws.split();

        // First frame must be the snapshot (type=="output").
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

        // Input round-trip.
        let input = serde_json::json!({"type": "input", "data": "echo BASEPATH_WS\n"}).to_string();
        sink.send(TungsteniteMessage::Text(input))
            .await
            .expect("send input");
        let found = wait_for_output(&mut stream, "BASEPATH_WS", Duration::from_secs(10)).await;
        assert!(found, "expected BASEPATH_WS in output frames within 10s");

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    // ---- M5/U1: spec §4 integration suite (real tmux) ------------------------

    /// §4.1: an emoji emitted in two halves with a delay between them (so PTY
    /// reads split the scalar) reaches the client as valid UTF-8 — no U+FFFD.
    #[tokio::test]
    async fn split_utf8_output_reaches_client_intact() {
        let (addr, state, _dir) = spawn_server().await;
        let (mut sink, mut stream, id) = connect_session(addr, &state, "wssplitutf8").await;

        // 😀 = F0 9F 98 80; octal escapes are portable across /bin/sh printfs.
        // The marker is quote-split so the echoed command line cannot match it.
        send_input(
            &mut sink,
            "printf '\\360\\237'; sleep 0.3; printf '\\230\\200'; echo; echo SPLIT_DON''E\n",
        )
        .await;

        let acc = collect_output_until(&mut stream, "SPLIT_DONE", Duration::from_secs(10)).await;
        assert!(acc.contains('😀'), "emoji must arrive reassembled: {acc:?}");
        assert!(
            !acc.contains('\u{FFFD}'),
            "no replacement char may appear: {acc:?}"
        );

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    /// §4.3: modes set by the pane (mouse, bracketed paste) propagate through
    /// tmux to the PTY stream; a NEW connection gets them re-asserted in an
    /// early frame right after the snapshot.
    #[tokio::test]
    async fn mode_replay_on_new_connection() {
        let (addr, state, _dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();

        // Let tmux attach settle, then enable mouse + bracketed paste in the pane.
        tokio::time::sleep(Duration::from_millis(500)).await;
        sess.pty
            .write(b"printf '\\033[?1000h\\033[?1006h\\033[?2004h'\n")
            .expect("pty write");

        // Wait for the session-level scanner to register the pane-driven modes.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let seq = sess
                .pty
                .modes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .reassert_sequence();
            if seq.contains("\x1b[?1006h") && seq.contains("\x1b[?2004h") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "scanner must register pane modes within 5s (got: {seq:?})"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // NEW connection: snapshot frame first, then the mode re-assert frame.
        let expires = crate::util::unix_now() + 3600;
        state
            .store
            .add_auth_session("wsmodereplay", expires)
            .unwrap();
        let url = format!("ws://{addr}/ws/{id}?token=wsmodereplay");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect");
        let (mut sink, mut stream) = ws.split();

        // The snapshot shows the echoed printf as literal backslash text; only
        // the re-assert frame carries raw ESC [ ? sequences. Find the frame
        // holding ALL expected re-asserts within the first frames.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut found = false;
        let mut seen = Vec::new();
        while !found {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "re-assert frame must arrive within 5s; frames seen: {seen:?}"
            );
            match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(Ok(TungsteniteMessage::Text(t)))) => {
                    let v: serde_json::Value = serde_json::from_str(&t).expect("frame JSON");
                    let data = v["data"].as_str().unwrap_or("").to_string();
                    found = data.contains("\x1b[?1000h")
                        && data.contains("\x1b[?1006h")
                        && data.contains("\x1b[?2004h");
                    seen.push(data);
                }
                Ok(Some(Ok(_))) => continue,
                other => panic!("stream ended before re-assert frame: {other:?}"),
            }
        }

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    /// §4 (alt screen): entering and leaving the alternate screen mid-stream
    /// repaints without killing the connection or corrupting the stream.
    #[tokio::test]
    async fn alt_screen_enter_exit_repaint() {
        let (addr, state, _dir) = spawn_server().await;
        let (mut sink, mut stream, id) = connect_session(addr, &state, "wsaltscreen").await;

        // Markers are quote-split so the echoed command line cannot match
        // them. The sleep keeps the alt screen up long enough for tmux to
        // redraw (an instant enter/exit would never be streamed).
        send_input(
            &mut sink,
            "printf '\\033[?1049h'; echo ALT_MAR''K; sleep 0.5; printf '\\033[?1049l'; echo MAIN_MAR''K\n",
        )
        .await;

        let acc = collect_output_until(&mut stream, "MAIN_MARK", Duration::from_secs(10)).await;
        assert!(acc.contains("ALT_MARK"), "alt-screen output must stream");
        assert!(!acc.contains('\u{FFFD}'), "stream must stay valid UTF-8");

        // Connection still healthy after the round trip.
        send_input(&mut sink, "echo STILL_ALIVE\n").await;
        let found = wait_for_output(&mut stream, "STILL_ALIVE", Duration::from_secs(10)).await;
        assert!(found, "connection must survive alt-screen enter/exit");

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    /// §4 (wide chars / grapheme clusters): a line of wide CJK exceeding the
    /// pane width plus an emoji ZWJ family at the wrap point reaches the
    /// client as valid UTF-8 with no panic and no replacement chars.
    #[tokio::test]
    async fn wide_chars_and_zwj_emoji_at_wrap_point() {
        let (addr, state, _dir) = spawn_server().await;
        let (mut sink, mut stream, id) = connect_session(addr, &state, "wswidewrap").await;

        // 50 double-width chars = 100 columns > default 80: forces a wrap,
        // with the ZWJ family emoji landing past the wrap boundary.
        let wide = "漢".repeat(50);
        send_input(
            &mut sink,
            &format!("printf '%s\\n' '{wide}👨‍👩‍👧‍👦'; echo WRAP_DON''E\n"),
        )
        .await;

        let acc = collect_output_until(&mut stream, "WRAP_DONE", Duration::from_secs(10)).await;
        assert!(acc.contains('漢'), "wide chars must arrive: {acc:?}");
        assert!(
            acc.contains('👨') && acc.contains('👦'),
            "ZWJ family members must arrive: {acc:?}"
        );
        assert!(!acc.contains('\u{FFFD}'), "no replacement chars: {acc:?}");

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    /// §4.6 (grapheme bomb): a long combining-mark run streams without
    /// corruption. tmux itself caps combining marks per cell below the UAX #15
    /// 30-nonstarter threshold, so the CGJ insertion is pinned at unit level
    /// (`stream_safe_caps_combining_mark_bomb`); here we pin end-to-end
    /// validity and liveness.
    #[tokio::test]
    async fn combining_mark_bomb_stream_stays_valid() {
        let (addr, state, _dir) = spawn_server().await;
        let (mut sink, mut stream, id) = connect_session(addr, &state, "wscombomb").await;

        // U+0301 = octal \314\201; 60 marks on one base char. The marker is
        // quote-split so the echoed command line cannot match it.
        send_input(
            &mut sink,
            "printf 'X'; i=0; while [ $i -lt 60 ]; do printf '\\314\\201'; i=$((i+1)); done; echo; echo BOMB_DON''E\n",
        )
        .await;

        let acc = collect_output_until(&mut stream, "BOMB_DONE", Duration::from_secs(10)).await;
        assert!(
            acc.contains('\u{0301}'),
            "combining marks must arrive: {acc:?}"
        );
        assert!(!acc.contains('\u{FFFD}'), "no replacement chars: {acc:?}");

        // Connection still healthy.
        send_input(&mut sink, "echo BOMB_ALIVE\n").await;
        let found = wait_for_output(&mut stream, "BOMB_ALIVE", Duration::from_secs(10)).await;
        assert!(found, "connection must survive the combining-mark bomb");

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    /// §4.4: 20 rapid resize frames are serialized per session; tmux ends at
    /// exactly the last requested size.
    #[tokio::test]
    async fn resize_storm_converges_on_final_size() {
        let (addr, state, dir) = spawn_server().await;
        let (mut sink, mut stream, id) = connect_session(addr, &state, "wsresizestorm").await;
        let tmux_name = tmux::session_name(&id);

        // Drain the snapshot frame.
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .ok();

        // 19 varied sizes back-to-back, then the final target 105x33.
        for i in 0..19u16 {
            let resize = serde_json::json!({
                "type": "resize",
                "cols": 81 + i,
                "rows": 25 + (i % 10),
            })
            .to_string();
            sink.send(TungsteniteMessage::Text(resize))
                .await
                .expect("send resize");
        }
        let last = serde_json::json!({"type": "resize", "cols": 105, "rows": 33}).to_string();
        sink.send(TungsteniteMessage::Text(last))
            .await
            .expect("send final resize");

        // Poll until tmux reports exactly the final size. The status line
        // occupies one client row, so a 105x33 client yields a 105x32 pane.
        let data_dir = dir.path().to_path_buf();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut last_seen = Vec::new();
        let mut size_ok = false;
        while std::time::Instant::now() < deadline {
            if let Ok(out) = tmux::run(
                &data_dir,
                &[
                    "display-message",
                    "-p",
                    "-t",
                    &tmux_name,
                    "#{pane_width}x#{pane_height}",
                ],
            )
            .await
            {
                last_seen = out.trim_ascii().to_vec();
                if last_seen == b"105x32" {
                    size_ok = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();

        assert!(
            size_ok,
            "tmux must end at the last requested size 105x32 (pane view of a \
             105x33 client), got: {}",
            String::from_utf8_lossy(&last_seen)
        );
    }

    /// §4.2 pin: a bracketed-paste wrapped payload (multi-line, tabs, raw ESC
    /// bytes) written as an input frame reaches the pane application verbatim.
    /// tmux consumes the 200~/201~ markers (the pane app did not enable mode
    /// 2004) and must deliver the inner bytes untouched — including `\n`.
    #[tokio::test]
    async fn bracketed_paste_input_passthrough_verbatim() {
        let (addr, state, dir) = spawn_server().await;
        let (mut sink, mut stream, id) = connect_session(addr, &state, "wspastepin").await;
        let tmux_name = tmux::session_name(&id);

        let out_path = dir.path().join("paste_out.bin");
        send_input(&mut sink, &format!("cat > {}\n", out_path.display())).await;

        // Wait until cat is running in the pane before pasting.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let cmd = tmux::run(
                dir.path(),
                &[
                    "display-message",
                    "-p",
                    "-t",
                    &tmux_name,
                    "#{pane_current_command}",
                ],
            )
            .await
            .unwrap_or_default();
            if cmd.trim_ascii() == b"cat" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "cat must start in the pane within 5s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let inner = "L1\nL2\tTAB\u{1b}ZESC";
        send_input(&mut sink, &format!("\u{1b}[200~{inner}\u{1b}[201~")).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        // First ^D flushes the unterminated last line; second ^D is EOF.
        send_input(&mut sink, "\u{4}\u{4}").await;

        // Poll the file for the exact inner bytes.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while std::time::Instant::now() < deadline {
            got = std::fs::read(&out_path).unwrap_or_default();
            if got == inner.as_bytes() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Drain anything pending so the close below is clean.
        let _ = wait_for_output(&mut stream, "\u{0}", Duration::from_millis(100)).await;
        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();

        assert_eq!(
            got,
            inner.as_bytes(),
            "paste payload must reach the pane byte-exact"
        );
    }

    /// §4.7 pin: an OSC 52 clipboard sequence emitted by the pane reaches the
    /// WS client intact. tmux only forwards OSC 52 when the client terminal
    /// advertises the Ms capability, so the test pre-starts the tmux server
    /// (dummy detached session) and sets the standard xterm Ms override before
    /// the session's client attaches; the pin is that OUR relay passes the
    /// forwarded sequence through unmangled.
    #[tokio::test]
    async fn osc52_output_reaches_client() {
        let (addr, state, dir) = spawn_server().await;

        tmux::run(
            dir.path(),
            &["new-session", "-d", "-s", "dummy", "--", "/bin/sh"],
        )
        .await
        .expect("dummy session");
        tmux::run(
            dir.path(),
            &[
                "set",
                "-g",
                "terminal-overrides",
                ",xterm*:Ms=\\E]52;%p1%s;%p2%s\\007",
            ],
        )
        .await
        .expect("set Ms override");
        tmux::run(dir.path(), &["set", "-g", "set-clipboard", "on"])
            .await
            .expect("set-clipboard on");

        let (mut sink, mut stream, id) = connect_session(addr, &state, "wsosc52").await;

        // "Zm9vYmFy" = base64("foobar"). The echoed command shows the literal
        // backslash text only; the raw ESC ] sequence proves passthrough.
        send_input(&mut sink, "printf '\\033]52;c;Zm9vYmFy\\007'\n").await;

        let acc =
            collect_output_until(&mut stream, "\u{1b}]52;c;Zm9vYmFy", Duration::from_secs(10))
                .await;
        assert!(
            acc.contains("\u{1b}]52;c;Zm9vYmFy"),
            "raw OSC 52 sequence must reach the client: {acc:?}"
        );

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
        tmux::kill_session(dir.path(), "dummy").await.ok();
    }

    /// §4.5: lapping the 1024-chunk broadcast buffer does not tear the stream
    /// or drop the connection — the client gets a re-sync (fresh snapshot +
    /// mode re-asserts) and keeps streaming.
    ///
    /// Lag is forced deterministically by injecting chunks straight into the
    /// session's broadcast sender far faster than the pump can drain them.
    #[tokio::test]
    async fn lagged_client_resyncs_with_snapshot_and_modes() {
        let (addr, state, _dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();

        // tmux asserts bracketed paste (?2004) on its client at attach; wait
        // for the scanner to hold it so the re-assert frame is non-empty and
        // detectable.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let seq = sess
                .pty
                .modes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .reassert_sequence();
            if seq.contains("\x1b[?2004h") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "scanner must see the tmux attach modes within 5s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let expires = crate::util::unix_now() + 3600;
        state
            .store
            .add_auth_session("wslagresync", expires)
            .unwrap();
        let url = format!("ws://{addr}/ws/{id}?token=wslagresync");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect");
        let (mut sink, mut stream) = ws.split();

        // Consume the attach-time re-assert frame so any re-assert seen later
        // can only come from a lag-resync.
        let attach_reassert =
            collect_output_until(&mut stream, "\x1b[?2004h", Duration::from_secs(5)).await;
        assert!(
            !attach_reassert.is_empty(),
            "attach re-assert frame must arrive"
        );

        // Inject 3x the channel capacity in a tight loop: the pump (one TCP
        // write per chunk) cannot keep up, so its receiver must lag.
        for _ in 0..3072 {
            sess.pty.output.send(b"FLOODCHUNK ".to_vec()).ok();
        }

        let resynced =
            collect_output_until(&mut stream, "\x1b[?2004h", Duration::from_secs(20)).await;
        assert!(
            !resynced.is_empty(),
            "lagged client must receive a resync re-assert frame"
        );

        // The connection survives and continues streaming after resync.
        send_input(&mut sink, "echo LAG_ALIVE\n").await;
        let found = wait_for_output(&mut stream, "LAG_ALIVE", Duration::from_secs(20)).await;
        assert!(found, "connection must stay alive after lag-resync");

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    // ---- M5 U2: image paste --------------------------------------------------

    /// The WS paste path reads the real process env; a desktop test host would
    /// take the clipboard branch, so drop the display vars to force the file
    /// fallback (pure reads — and thus a no-op — on headless CI).
    fn force_no_display() {
        for key in ["WAYLAND_DISPLAY", "DISPLAY"] {
            if std::env::var_os(key).is_some() {
                std::env::remove_var(key);
            }
        }
    }

    /// paste-image frame, no display available: file lands under
    /// `<data_dir>/<id>/pastes/`, bytes match the decoded payload, and the
    /// absolute path is typed into the pane.
    #[tokio::test]
    async fn ws_paste_image_falls_back_to_file() {
        force_no_display();
        let (addr, state, dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();

        let expires = crate::util::unix_now() + 3600;
        state
            .store
            .add_auth_session("wspastetoken", expires)
            .unwrap();

        let url = format!("ws://{addr}/ws/{id}?token=wspastetoken");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect");
        let (mut sink, mut stream) = ws.split();

        // Drain the snapshot frame; give the shell a moment to come up.
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .ok();
        tokio::time::sleep(Duration::from_millis(400)).await;

        let payload: &[u8] = b"\x89PNG\r\n\x1a\nws-paste-payload";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload);
        let frame = serde_json::json!({"type": "paste-image", "data": b64, "mime": "image/png"})
            .to_string();
        sink.send(TungsteniteMessage::Text(frame))
            .await
            .expect("send paste-image");

        // Poll until the fallback file appears.
        let pastes = dir.path().join(&id).join("pastes");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut saved: Option<std::path::PathBuf> = None;
        while std::time::Instant::now() < deadline {
            if let Ok(entries) = std::fs::read_dir(&pastes) {
                if let Some(entry) = entries.flatten().next() {
                    saved = Some(entry.path());
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let path = saved.expect("a file must appear under pastes/ within 10s");
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with(".png"),
            "image/png must map to .png: {path:?}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            payload,
            "saved bytes must equal the decoded payload"
        );

        // The absolute path was typed into the pty — visible via capture-pane.
        let needle = std::path::absolute(&path).unwrap().display().to_string();
        let tmux_name = tmux::session_name(&id);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut found = false;
        while std::time::Instant::now() < deadline {
            if let Ok(bytes) = tmux::capture_pane(dir.path(), &tmux_name, 50).await {
                if String::from_utf8_lossy(&bytes).contains(&needle) {
                    found = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(found, "pane must contain the typed absolute path {needle}");

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }

    /// Bad base64 in a paste-image frame must NOT disconnect: a later input
    /// frame still executes.
    #[tokio::test]
    async fn ws_paste_image_bad_base64_keeps_connection() {
        let (addr, state, _dir) = spawn_server().await;

        let sess = state.manager.create(None).await.expect("create session");
        let id = sess.id.clone();

        let expires = crate::util::unix_now() + 3600;
        state
            .store
            .add_auth_session("wspastebadtoken", expires)
            .unwrap();

        let url = format!("ws://{addr}/ws/{id}?token=wspastebadtoken");
        let (ws, _resp) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect");
        let (mut sink, mut stream) = ws.split();

        // Drain the snapshot frame.
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .ok();

        let frame = serde_json::json!({
            "type": "paste-image",
            "data": "!!!not-base64!!!",
            "mime": "image/png"
        })
        .to_string();
        sink.send(TungsteniteMessage::Text(frame))
            .await
            .expect("send bad paste-image");

        // Connection must still be alive: a valid input frame executes.
        let input = serde_json::json!({"type": "input", "data": "echo PASTE_ALIVE\n"}).to_string();
        sink.send(TungsteniteMessage::Text(input))
            .await
            .expect("send input after bad paste");
        let found = wait_for_output(&mut stream, "PASTE_ALIVE", Duration::from_secs(10)).await;
        assert!(
            found,
            "connection must survive a bad-base64 paste-image frame"
        );

        sink.send(TungsteniteMessage::Close(None)).await.ok();
        state.manager.delete(&id).await.ok();
    }
}
