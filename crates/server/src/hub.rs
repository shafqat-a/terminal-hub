use crate::session_id::SessionId;
use std::collections::HashMap;
use std::sync::Arc;
use tmux_client::conn::Connection;
use tmux_client::protocol::Event;
use tokio::sync::{broadcast, mpsc, Mutex};

#[derive(Clone)]
pub struct Hub {
    inner: Arc<Mutex<HashMap<SessionId, Channel>>>,
    socket: String,
}

struct Channel {
    tx_out: broadcast::Sender<Vec<u8>>,
    tx_in: mpsc::Sender<String>,
}

impl Hub {
    pub fn new(socket: String) -> Self { Self { inner: Default::default(), socket } }

    pub async fn subscribe(&self, id: &SessionId)
        -> anyhow::Result<(broadcast::Receiver<Vec<u8>>, mpsc::Sender<String>)>
    {
        let mut g = self.inner.lock().await;
        if let Some(ch) = g.get(id) { return Ok((ch.tx_out.subscribe(), ch.tx_in.clone())); }
        let conn = Connection::attach(&self.socket, &id.tmux_name()).await?;
        let (tx_out, _) = broadcast::channel::<Vec<u8>>(1024);
        let (tx_in, rx_in) = mpsc::channel::<String>(256);
        spawn_pump(conn, tx_out.clone(), rx_in, id.clone());
        let rx_out = tx_out.subscribe();
        g.insert(id.clone(), Channel { tx_out, tx_in: tx_in.clone() });
        Ok((rx_out, tx_in))
    }

    pub async fn capture_scrollback(&self, id: &SessionId, lines: usize) -> anyhow::Result<Vec<u8>> {
        let out = tokio::process::Command::new("tmux")
            .args(["-L", &self.socket, "capture-pane", "-p", "-e",
                   "-t", &id.tmux_name(), "-S", &format!("-{lines}")])
            .output().await?;
        if !out.status.success() {
            anyhow::bail!("capture-pane failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(out.stdout)
    }
}

fn spawn_pump(mut conn: Connection, tx_out: broadcast::Sender<Vec<u8>>,
              mut rx_in: mpsc::Receiver<String>, id: SessionId) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                ev = conn.recv() => match ev {
                    Some(Event::PaneOutput { raw, .. }) => {
                        let _ = tx_out.send(crate::attach::unescape_octal(&raw));
                    }
                    Some(_) => {}
                    None => break,
                },
                inp = rx_in.recv() => match inp {
                    Some(text) => {
                        let esc = text.replace('\'', "'\\''");
                        if conn.send_command(&format!("send-keys -t '{}' -l '{}'",
                                                      id.tmux_name(), esc)).await.is_err() { break; }
                    }
                    None => break,
                },
            }
        }
    });
}
