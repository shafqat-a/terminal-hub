//! /ws/attach — proxies bytes between a browser WebSocket and a tmux session.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use std::sync::Arc;
use tmux_client::conn::Connection;
use tmux_client::protocol::Event;

use crate::Config;

pub async fn ws_attach(
    State(cfg): State<Arc<Config>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_attach(socket, cfg))
}

async fn handle_attach(mut socket: WebSocket, cfg: Arc<Config>) {
    let mut conn = match Connection::attach(&cfg.tmux_socket, &cfg.tmux_session).await {
        Ok(c) => c,
        Err(e) => {
            let _ = socket
                .send(Message::Text(format!("tmux attach error: {e}")))
                .await;
            return;
        }
    };

    loop {
        tokio::select! {
            ev = conn.recv() => {
                match ev {
                    Some(Event::PaneOutput { raw, .. }) => {
                        let decoded = unescape_octal(&raw);
                        if socket.send(Message::Binary(decoded)).await.is_err() {
                            return;
                        }
                    }
                    Some(_) => {} // ignore CommandOk/CommandErr/Unknown for now
                    None => return,
                }
            }
            msg = socket.recv() => {
                let Some(Ok(msg)) = msg else { return; };
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                    Message::Close(_) => return,
                    _ => continue,
                };
                let escaped = text.replace('\'', "'\\''");
                let cmd = format!("send-keys -t '{}' -l '{}'", cfg.tmux_session, escaped);
                if conn.send_command(&cmd).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// tmux escapes non-printable bytes in %output as `\NNN` (octal, 3 digits).
fn unescape_octal(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &bytes[i + 1..i + 4];
            if octal.iter().all(|b| (b'0'..=b'7').contains(b)) {
                let v = (octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0');
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_known_octals() {
        assert_eq!(unescape_octal("hi\\015"), b"hi\r");
        assert_eq!(unescape_octal("a\\033[31mb"), b"a\x1b[31mb");
        assert_eq!(unescape_octal("nothing-special"), b"nothing-special");
    }
}
