# M2 — Multi-Session Local Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Important:** Refresh this plan after M1 ships. Concrete struct field names and exact response shapes may need to adjust to what M1 ended up with.

**Goal:** A usable single-user terminal multiplexer in a browser. Sidebar lists every tmux session on the local instance; clicking one attaches the main pane. Create, kill, rename. Scrollback replays on attach. Multiple browser tabs can attach to the same session.

**Architecture:** Add a `sessions` module to the server crate that talks to `tmux_client::Connection` for control commands (list/new/kill/rename). The existing `/ws/attach` endpoint becomes `/ws/attach/:session_id`. A per-session `Hub` actor multiplexes pane bytes to multiple WebSocket subscribers. Sidebar UI is plain HTML + a tiny vanilla-JS module.

**Tech Stack:** Same as M1 + `uuid` (v7), `axum::extract::Path`, `serde_json`.

**Spec reference:** `docs/superpowers/specs/2026-05-21-terminal-hub-design.md` §8 (session model), §12 (sidebar UX).

---

## Task 1: SessionId with tmux-name round-trip

**Files:**
- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/session_id.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Add deps + module**

Add to `crates/server/Cargo.toml` `[dependencies]`:

```toml
uuid = { version = "1", features = ["v7", "serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

Create `crates/server/src/session_id.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub uuid::Uuid);

impl SessionId {
    pub fn new() -> Self { Self(uuid::Uuid::now_v7()) }
    pub fn tmux_name(&self) -> String { format!("th-{}", self.0) }
    pub fn from_tmux_name(name: &str) -> Option<Self> {
        uuid::Uuid::parse_str(name.strip_prefix("th-")?).ok().map(Self)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn round_trip() {
        let id = SessionId::new();
        assert_eq!(SessionId::from_tmux_name(&id.tmux_name()).unwrap(), id);
    }
    #[test] fn rejects_unprefixed() { assert!(SessionId::from_tmux_name("scratch").is_none()); }
}
```

Add `pub mod session_id;` to `crates/server/src/lib.rs`.

- [ ] **Step 2: Verify + commit**

Run: `cargo test -p terminal-hub-server session_id`
Expected: 2 pass.

```bash
git add crates/server/Cargo.toml crates/server/src/session_id.rs crates/server/src/lib.rs
git commit -m "feat(server): SessionId type with tmux-name round-trip"
```

---

## Task 2: Session manager driving tmux commands

**Files:**
- Create: `crates/server/src/sessions.rs`
- Create: `crates/server/tests/sessions.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Implement Manager**

Create `crates/server/src/sessions.rs`:

```rust
use crate::session_id::SessionId;
use serde::Serialize;
use std::sync::Arc;
use tmux_client::conn::Connection;
use tmux_client::protocol::Event;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub display_name: String,
    pub owner: String,
    pub created_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tmux: {0}")] Tmux(#[from] tmux_client::conn::Error),
    #[error("tmux cmd error: {0}")] Cmd(String),
}

pub struct Manager {
    ctl: Arc<Mutex<Connection>>,
}

impl Manager {
    pub async fn connect(socket: &str, boot_session: &str) -> Result<Self, Error> {
        Ok(Self { ctl: Arc::new(Mutex::new(Connection::attach(socket, boot_session).await?)) })
    }

    async fn run(&self, cmd: &str) -> Result<String, Error> {
        let mut c = self.ctl.lock().await;
        c.send_command(cmd).await?;
        loop {
            match c.recv().await {
                Some(Event::CommandOk { body }) => return Ok(body),
                Some(Event::CommandErr { body }) => return Err(Error::Cmd(body)),
                Some(_) => continue,
                None => return Err(Error::Cmd("connection closed".into())),
            }
        }
    }

    pub async fn list(&self) -> Result<Vec<SessionInfo>, Error> {
        let fmt = "#{session_name}|#{?@display-name,#{@display-name},(unnamed)}|\
                   #{?@owner-email,#{@owner-email},?}|#{?@created-at,#{@created-at},0}";
        let body = self.run(&format!("list-sessions -F '{fmt}'")).await?;
        Ok(body.lines().filter_map(|line| {
            let p: Vec<&str> = line.splitn(4, '|').collect();
            if p.len() != 4 { return None; }
            Some(SessionInfo {
                id: SessionId::from_tmux_name(p[0])?,
                display_name: p[1].into(),
                owner: p[2].into(),
                created_at: p[3].parse().unwrap_or(0),
            })
        }).collect())
    }

    pub async fn create(&self, display_name: &str, owner: &str) -> Result<SessionInfo, Error> {
        let id = SessionId::new();
        let name = id.tmux_name();
        let now = now_secs();
        self.run(&format!("new-session -d -s '{name}'")).await?;
        self.run(&format!("set-option -t '{name}' @display-name '{}'", esc(display_name))).await?;
        self.run(&format!("set-option -t '{name}' @owner-email '{}'", esc(owner))).await?;
        self.run(&format!("set-option -t '{name}' @created-at {now}")).await?;
        Ok(SessionInfo { id, display_name: display_name.into(), owner: owner.into(), created_at: now })
    }

    pub async fn rename(&self, id: &SessionId, new_display: &str) -> Result<(), Error> {
        self.run(&format!("set-option -t '{}' @display-name '{}'", id.tmux_name(), esc(new_display))).await?;
        Ok(())
    }

    pub async fn kill(&self, id: &SessionId) -> Result<(), Error> {
        self.run(&format!("kill-session -t '{}'", id.tmux_name())).await?;
        Ok(())
    }
}

fn esc(s: &str) -> String { s.replace('\'', "'\\''") }
fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
```

Add `pub mod sessions;` to `crates/server/src/lib.rs`.

- [ ] **Step 2: Test**

Create `crates/server/tests/sessions.rs`:

```rust
use std::process::Command;
use terminal_hub_server::sessions::Manager;

const SOCKET: &str = "terminal-hub-test-m2-sessions";
const BOOT: &str = "_boot";

fn ensure() { let _ = Command::new("tmux").args(["-L", SOCKET, "new-session", "-d", "-s", BOOT]).status(); }
fn kill() { let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status(); }

#[tokio::test(flavor = "multi_thread")]
async fn crud() {
    ensure();
    let m = Manager::connect(SOCKET, BOOT).await.unwrap();
    let info = m.create("build", "you@example.com").await.unwrap();
    assert!(m.list().await.unwrap().iter().any(|s| s.id == info.id));
    m.rename(&info.id, "renamed").await.unwrap();
    assert!(m.list().await.unwrap().iter().any(|s| s.display_name == "renamed"));
    m.kill(&info.id).await.unwrap();
    assert!(!m.list().await.unwrap().iter().any(|s| s.id == info.id));
    kill();
}
```

Run: `cargo test -p terminal-hub-server --test sessions -- --nocapture`
Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add crates/server/src/sessions.rs crates/server/src/lib.rs crates/server/tests/sessions.rs
git commit -m "feat(server): Manager — list/create/rename/kill tmux sessions"
```

---

## Task 3: REST API + per-session Hub + `/ws/attach/:id`

This task combines the API, the broadcast Hub, and the parametrized WebSocket route because they all depend on the same `AppState` shape; doing them in one task avoids a bunch of churn in `lib.rs`.

**Files:**
- Create: `crates/server/src/api.rs`
- Create: `crates/server/src/hub.rs`
- Modify: `crates/server/src/attach.rs`
- Modify: `crates/server/src/lib.rs`
- Modify: `crates/server/src/main.rs`
- Create: `crates/server/tests/api.rs`

- [ ] **Step 1: Per-session broadcast Hub**

Create `crates/server/src/hub.rs`:

```rust
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
```

- [ ] **Step 2: REST API**

Create `crates/server/src/api.rs`:

```rust
use crate::session_id::SessionId;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

#[derive(Deserialize)] pub struct CreateBody { pub display_name: String }
#[derive(Deserialize)] pub struct RenameBody { pub display_name: String }

pub async fn list(State(s): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let v = s.mgr.list().await.map_err(e500)?;
    Ok(Json(serde_json::json!({ "sessions": v })))
}
pub async fn create(State(s): State<AppState>, Json(b): Json<CreateBody>)
    -> Result<Json<serde_json::Value>, (StatusCode, String)>
{
    let v = s.mgr.create(&b.display_name, "local").await.map_err(e500)?;
    Ok(Json(serde_json::json!({ "session": v })))
}
pub async fn rename(State(s): State<AppState>, Path(id): Path<String>, Json(b): Json<RenameBody>)
    -> Result<StatusCode, (StatusCode, String)>
{
    let id = parse_id(&id)?;
    s.mgr.rename(&id, &b.display_name).await.map_err(e500)?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn kill(State(s): State<AppState>, Path(id): Path<String>)
    -> Result<StatusCode, (StatusCode, String)>
{
    let id = parse_id(&id)?;
    s.mgr.kill(&id).await.map_err(e500)?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_id(s: &str) -> Result<SessionId, (StatusCode, String)> {
    uuid::Uuid::parse_str(s).map(SessionId).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}
fn e500(e: crate::sessions::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
```

- [ ] **Step 3: Refactor `attach.rs`**

Replace `crates/server/src/attach.rs`:

```rust
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
```

- [ ] **Step 4: Update lib.rs + main.rs**

Replace `crates/server/src/lib.rs`:

```rust
use axum::routing::{any, get};
use axum::Router;
use std::sync::Arc;
use tower_http::services::ServeDir;

pub mod api;
pub mod attach;
pub mod hub;
pub mod session_id;
pub mod sessions;

pub struct Config {
    pub tmux_socket: String,
    pub tmux_session: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            tmux_socket: std::env::var("TERMINAL_HUB_TMUX_SOCKET").unwrap_or_else(|_| "terminal-hub".into()),
            tmux_session: std::env::var("TERMINAL_HUB_TMUX_SESSION").unwrap_or_else(|_| "_boot".into()),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub mgr: Arc<sessions::Manager>,
    pub cfg: Arc<Config>,
    pub hub: hub::Hub,
}

pub async fn router() -> anyhow::Result<Router> { router_with(Config::default()).await }
pub async fn router_with(cfg: Config) -> anyhow::Result<Router> {
    let mgr = Arc::new(sessions::Manager::connect(&cfg.tmux_socket, &cfg.tmux_session).await?);
    let hub = hub::Hub::new(cfg.tmux_socket.clone());
    let state = AppState { mgr, cfg: Arc::new(cfg), hub };
    Ok(Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/sessions", get(api::list).post(api::create))
        .route("/api/sessions/:id", axum::routing::patch(api::rename).delete(api::kill))
        .route("/ws/attach/:id", any(attach::ws_attach))
        .fallback_service(ServeDir::new(static_dir()))
        .with_state(state))
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")); p.push("static"); p
}
```

Replace `crates/server/src/main.rs`:

```rust
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let bind = std::env::var("TERMINAL_HUB_BIND").unwrap_or_else(|_| "127.0.0.1:5999".into());
    let app = terminal_hub_server::router().await?;
    tracing::info!(%bind, "terminal-hub listening");
    let listener = TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 5: End-to-end test (CRUD + mirroring + scrollback)**

Create `crates/server/tests/api.rs`:

```rust
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const SOCKET: &str = "terminal-hub-test-m2-api";
const BOOT: &str = "_boot";

fn ensure() { let _ = Command::new("tmux").args(["-L", SOCKET, "new-session", "-d", "-s", BOOT]).status(); }
fn kill() { let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status(); }

async fn spawn() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let cfg = terminal_hub_server::Config { tmux_socket: SOCKET.into(), tmux_session: BOOT.into() };
    let app = terminal_hub_server::router_with(cfg).await.unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn crud_round_trip() {
    ensure(); let addr = spawn().await; let c = reqwest::Client::new();
    let created: serde_json::Value = c.post(format!("http://{addr}/api/sessions"))
        .json(&serde_json::json!({ "display_name": "build" })).send().await.unwrap().json().await.unwrap();
    let id = created["session"]["id"].as_str().unwrap().to_string();
    let listed: serde_json::Value = c.get(format!("http://{addr}/api/sessions")).send().await.unwrap().json().await.unwrap();
    assert!(listed["sessions"].as_array().unwrap().iter().any(|s| s["id"] == id));
    let st = c.delete(format!("http://{addr}/api/sessions/{id}")).send().await.unwrap().status();
    assert_eq!(st, 204);
    kill();
}

#[tokio::test(flavor = "multi_thread")]
async fn two_tabs_mirror_same_session() {
    ensure(); let addr = spawn().await; let c = reqwest::Client::new();
    let cr: serde_json::Value = c.post(format!("http://{addr}/api/sessions"))
        .json(&serde_json::json!({ "display_name": "mirror" })).send().await.unwrap().json().await.unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();
    let url = format!("ws://{addr}/ws/attach/{id}");
    let (mut a, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut b, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    a.send(Message::Text("echo mirror-test\r".into())).await.unwrap();
    let (mut sa, mut sb) = (false, false);
    let dl = tokio::time::Instant::now() + Duration::from_secs(3);
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
    kill();
    assert!(sa && sb);
}

#[tokio::test(flavor = "multi_thread")]
async fn reattach_replays_scrollback() {
    ensure(); let addr = spawn().await; let c = reqwest::Client::new();
    let cr: serde_json::Value = c.post(format!("http://{addr}/api/sessions"))
        .json(&serde_json::json!({ "display_name": "scroll" })).send().await.unwrap().json().await.unwrap();
    let id = cr["session"]["id"].as_str().unwrap().to_string();
    let url = format!("ws://{addr}/ws/attach/{id}");
    {
        let (mut w, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        w.send(Message::Text("echo scrollback-marker\r".into())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = w.close(None).await;
    }
    let (mut w2, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let mut saw = false;
    let dl = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < dl && !saw {
        if let Ok(Some(Ok(Message::Binary(by)))) = tokio::time::timeout(Duration::from_millis(200), w2.next()).await {
            if std::str::from_utf8(&by).map(|s| s.contains("scrollback-marker")).unwrap_or(false) { saw = true; }
        }
    }
    let _ = c.delete(format!("http://{addr}/api/sessions/{id}")).send().await;
    kill();
    assert!(saw);
}
```

Run: `cargo test -p terminal-hub-server --test api -- --nocapture`
Expected: all three pass.

- [ ] **Step 6: Commit**

```bash
git add crates/server/
git commit -m "feat(server): REST sessions API + per-session Hub + scrollback replay"
```

---

## Task 4: Sidebar UI

**Files:**
- Modify: `crates/server/static/index.html`
- Modify: `crates/server/static/app.css`
- Modify: `crates/server/static/app.js`

- [ ] **Step 1: Markup**

Replace `crates/server/static/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>terminal-hub</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
    <link rel="stylesheet" href="/app.css">
  </head>
  <body>
    <aside id="sidebar">
      <header>
        <h1>terminal-hub</h1>
        <button id="new-session">+ New session</button>
      </header>
      <ul id="session-list"></ul>
    </aside>
    <main id="terminal"></main>
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
    <script src="/app.js" type="module"></script>
  </body>
</html>
```

- [ ] **Step 2: CSS**

Replace `crates/server/static/app.css`:

```css
html, body { margin: 0; height: 100%; background: #111; color: #ddd;
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif; }
body { display: grid; grid-template-columns: 220px 1fr; height: 100vh; }
#sidebar { background: #181818; border-right: 1px solid #2a2a2a; display: flex; flex-direction: column; }
#sidebar header { padding: 12px; border-bottom: 1px solid #2a2a2a; }
#sidebar header h1 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em;
  margin: 0 0 8px 0; color: #888; }
#sidebar header button { width: 100%; padding: 6px 8px; background: #2a2a2a; color: #ddd;
  border: 0; cursor: pointer; }
#sidebar header button:hover { background: #353535; }
#session-list { list-style: none; margin: 0; padding: 0; overflow-y: auto; flex: 1; }
#session-list li { padding: 8px 12px; cursor: pointer; border-bottom: 1px solid #1f1f1f;
  display: flex; justify-content: space-between; align-items: center; }
#session-list li:hover { background: #222; }
#session-list li.active { background: #2a2a2a; color: #fff; }
#session-list li button { background: transparent; border: 0; color: #666; cursor: pointer; }
#session-list li button:hover { color: #f55; }
#terminal { padding: 8px; }
```

- [ ] **Step 3: JS**

Replace `crates/server/static/app.js`:

```js
const term = new Terminal({ cursorBlink: true, fontFamily: "Menlo, monospace",
  fontSize: 13, scrollback: 5000 });
term.open(document.getElementById("terminal"));
term.writeln("terminal-hub — pick a session from the sidebar or create one.");

let activeWs = null;
let activeId = null;

async function refreshSessions() {
  const r = await fetch("/api/sessions");
  const { sessions } = await r.json();
  const ul = document.getElementById("session-list");
  ul.innerHTML = "";
  for (const s of sessions) {
    const li = document.createElement("li");
    if (s.id === activeId) li.classList.add("active");
    const label = document.createElement("span");
    label.textContent = s.display_name;
    label.style.cursor = "pointer";
    label.addEventListener("click", () => attach(s.id));
    const kill = document.createElement("button");
    kill.textContent = "×"; kill.title = "kill session";
    kill.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      if (!confirm(`Kill "${s.display_name}"?`)) return;
      await fetch(`/api/sessions/${s.id}`, { method: "DELETE" });
      if (activeId === s.id) detach();
      refreshSessions();
    });
    li.append(label, kill);
    ul.append(li);
  }
}

function detach() { if (activeWs) activeWs.close(); activeWs = null; activeId = null; term.reset(); }

function attach(id) {
  detach();
  activeId = id;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/attach/${id}`);
  ws.binaryType = "arraybuffer";
  ws.addEventListener("message", (ev) => {
    if (ev.data instanceof ArrayBuffer) term.write(new Uint8Array(ev.data));
    else term.write(ev.data);
  });
  ws.addEventListener("close", () => {
    if (activeId === id) term.writeln("\r\n\x1b[31mdisconnected\x1b[0m");
  });
  activeWs = ws;
  refreshSessions();
}

term.onData((d) => { if (activeWs?.readyState === WebSocket.OPEN) activeWs.send(d); });

document.getElementById("new-session").addEventListener("click", async () => {
  const name = prompt("Session name?", "shell");
  if (!name) return;
  const r = await fetch("/api/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ display_name: name }),
  });
  const { session } = await r.json();
  await refreshSessions();
  attach(session.id);
});

refreshSessions();
setInterval(refreshSessions, 5000);
```

- [ ] **Step 4: Manual smoke**

Open browser, create two sessions, switch between them, kill one. Open the same session in two tabs, type in one, watch the other mirror it.

- [ ] **Step 5: Commit**

```bash
git add crates/server/static/
git commit -m "feat(frontend): sidebar with session list, create, switch, kill"
```

---

## Done criteria for M2

- All M1 tests still pass.
- `cargo test --workspace` passes.
- Manual: create 3 sessions, attach two tabs to one, observe mirroring.
- Manual: refresh browser, prior scrollback replays.
- `cargo clippy --workspace -- -D warnings` clean.

**Next milestone:** M3 — single-user auth (TLS + CLI enroll + WebAuthn + SQLite). See `2026-05-21-m3-auth-single-user.md`.
