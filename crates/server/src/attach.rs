use crate::session_id::SessionId;
use crate::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tokio::sync::broadcast;

pub async fn ws_attach(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = match uuid::Uuid::parse_str(&id_str) {
        Ok(u) => SessionId(u),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    ws.on_upgrade(move |socket| handle(socket, state, id))
}

async fn handle(mut socket: WebSocket, state: AppState, id: SessionId) {
    let (mut rx, tx_in) = match state.hub.subscribe(&id).await {
        Ok(p) => p,
        Err(e) => { let _ = socket.send(Message::Text(format!("attach error: {e}"))).await; return; }
    };
    if let Ok(scroll) = state.hub.capture_scrollback(&id, 5000).await {
        if !scroll.is_empty() { let _ = socket.send(Message::Binary(scroll)).await; }
    }
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Ok(b) => { if socket.send(Message::Binary(b)).await.is_err() { return; } }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            },
            m = socket.recv() => {
                let Some(Ok(m)) = m else { return; };
                let text = match m {
                    Message::Text(t) => t,
                    Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    Message::Close(_) => return,
                    _ => continue,
                };
                if tx_in.send(text).await.is_err() { return; }
            }
        }
    }
}

pub fn unescape_octal(s: &str) -> Vec<u8> {
    let b = s.as_bytes(); let mut out = Vec::with_capacity(b.len()); let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let o = &b[i+1..i+4];
            if o.iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push((o[0]-b'0')*64 + (o[1]-b'0')*8 + (o[2]-b'0')); i += 4; continue;
            }
        }
        out.push(b[i]); i += 1;
    }
    out
}

#[cfg(test)]
mod tests { use super::*;
    #[test] fn unescapes() { assert_eq!(unescape_octal("hi\\015"), b"hi\r"); }
}
