# M1 — Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single hardcoded terminal session, served in a browser, with bytes flowing both directions through a `tmux -CC` control-mode pipe. No auth, no sidebar, no multi-session.

**Architecture:** Cargo workspace with three crates: `tmux-client` (control-mode protocol parser + child-process driver), `server` (axum HTTP + WebSocket), and `cli` (placeholder bin for future enroll/bootstrap commands). Frontend is a single static HTML page using xterm.js from a CDN. terminal-hub assumes a tmux server is already running on socket `terminal-hub` (the user starts it with `tmux -L terminal-hub new-session -d -s scratch`).

**Tech Stack:** Rust (edition 2021), tokio, axum 0.7, tower-http, tracing, xterm.js 5.x, vanilla HTML/JS. tmux ≥ 3.0 required at runtime.

**Spec reference:** `docs/superpowers/specs/2026-05-21-terminal-hub-design.md` §5, §8 (tmux backend), §14 (stack picks).

---

## Task 1: Initialize Cargo workspace

**Files:**
- Create: `Cargo.toml`
- Create: `crates/tmux-client/Cargo.toml`
- Create: `crates/tmux-client/src/lib.rs`
- Create: `crates/server/Cargo.toml`
- Create: `crates/server/src/main.rs`
- Create: `crates/cli/Cargo.toml`
- Create: `crates/cli/src/main.rs`
- Create: `rust-toolchain.toml`
- Create: `.gitignore`

- [ ] **Step 1: Create the root workspace manifest**

Create `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/tmux-client", "crates/server", "crates/cli"]

[workspace.package]
edition = "2021"
rust-version = "1.79"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
tokio = { version = "1.40", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
thiserror = "1"
```

- [ ] **Step 2: Create the tmux-client crate skeleton**

Create `crates/tmux-client/Cargo.toml`:

```toml
[package]
name = "tmux-client"
version = "0.1.0"
edition.workspace = true

[dependencies]
tokio = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["test-util", "macros"] }
```

Create `crates/tmux-client/src/lib.rs`:

```rust
//! tmux control-mode (-CC) client.

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(2 + 2, 4);
    }
}
```

- [ ] **Step 3: Create the server crate skeleton**

Create `crates/server/Cargo.toml`:

```toml
[package]
name = "terminal-hub-server"
version = "0.1.0"
edition.workspace = true

[[bin]]
name = "terminal-hub"
path = "src/main.rs"

[dependencies]
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }
```

Create `crates/server/src/main.rs`:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!("terminal-hub starting");
    Ok(())
}
```

- [ ] **Step 4: Create the cli crate skeleton**

Create `crates/cli/Cargo.toml`:

```toml
[package]
name = "terminal-hub-cli"
version = "0.1.0"
edition.workspace = true

[[bin]]
name = "terminal-hub-cli"
path = "src/main.rs"

[dependencies]
anyhow = { workspace = true }
```

Create `crates/cli/src/main.rs`:

```rust
fn main() -> anyhow::Result<()> {
    println!("terminal-hub-cli (placeholder; commands land in M3)");
    Ok(())
}
```

- [ ] **Step 5: Pin the toolchain and ignore build output**

Create `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.79"
components = ["rustfmt", "clippy"]
```

Create `.gitignore`:

```
/target
**/*.rs.bk
.DS_Store
*.swp
/.terminal-hub-dev/
```

- [ ] **Step 6: Verify the workspace builds and tests pass**

Run: `cargo build --workspace`
Expected: clean build of three crates.

Run: `cargo test --workspace`
Expected: `tests::smoke ... ok`; 0 failures.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/ rust-toolchain.toml .gitignore
git commit -m "chore: initialize cargo workspace with three crate skeletons"
```

---

## Task 2: tmux-client — parse a control-mode `%begin`/`%end` block

`tmux -CC` interleaves async event lines (`%output …`) with command-response blocks delimited by `%begin <args>` and `%end <args>` (or `%error <args>` on failure). Body lines between the delimiters are the command's stdout.

**Files:**
- Create: `crates/tmux-client/src/protocol.rs`
- Modify: `crates/tmux-client/src/lib.rs`

- [ ] **Step 1: Write the protocol module with tests inline**

Create `crates/tmux-client/src/protocol.rs`:

```rust
//! Line-oriented tmux control-mode protocol decoder.

use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    CommandOk { body: String },
    CommandErr { body: String },
    PaneOutput { pane: String, raw: String },
    Unknown(String),
}

#[derive(Default)]
pub struct Decoder {
    state: State,
    pending: Vec<String>,
}

#[derive(Default, Debug)]
enum State {
    #[default]
    Idle,
    InBlock,
}

impl Decoder {
    pub fn push_line(&mut self, line: &str) -> VecDeque<Event> {
        let mut out = VecDeque::new();
        match &self.state {
            State::Idle => {
                if line.starts_with("%begin") {
                    self.pending.clear();
                    self.state = State::InBlock;
                } else if let Some(rest) = line.strip_prefix("%output ") {
                    if let Some((pane, raw)) = rest.split_once(' ') {
                        out.push_back(Event::PaneOutput {
                            pane: pane.to_string(),
                            raw: raw.to_string(),
                        });
                    } else {
                        out.push_back(Event::Unknown(line.to_string()));
                    }
                } else {
                    out.push_back(Event::Unknown(line.to_string()));
                }
            }
            State::InBlock => {
                if line.starts_with("%end") || line.starts_with("%error") {
                    let err = line.starts_with("%error");
                    let body = std::mem::take(&mut self.pending).join("\n");
                    self.state = State::Idle;
                    out.push_back(if err {
                        Event::CommandErr { body }
                    } else {
                        Event::CommandOk { body }
                    });
                } else {
                    self.pending.push(line.to_string());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_command_ok_block() {
        let mut d = Decoder::default();
        assert!(d.push_line("%begin 1234 1 1").is_empty());
        assert!(d.push_line("session-one").is_empty());
        assert!(d.push_line("session-two").is_empty());
        let ev = d.push_line("%end 1234 1 1");
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev.into_iter().next().unwrap(),
            Event::CommandOk { body: "session-one\nsession-two".to_string() }
        );
    }

    #[test]
    fn decodes_a_command_err_block() {
        let mut d = Decoder::default();
        d.push_line("%begin 1 1 1");
        d.push_line("no such session");
        let ev = d.push_line("%error 1 1 1");
        assert_eq!(
            ev.into_iter().next().unwrap(),
            Event::CommandErr { body: "no such session".to_string() }
        );
    }

    #[test]
    fn decodes_a_pane_output_line() {
        let mut d = Decoder::default();
        let ev = d.push_line("%output %0 hello\\r\\n");
        assert_eq!(
            ev.into_iter().next().unwrap(),
            Event::PaneOutput { pane: "%0".to_string(), raw: "hello\\r\\n".to_string() }
        );
    }
}
```

Update `crates/tmux-client/src/lib.rs`:

```rust
//! tmux control-mode (-CC) client.

pub mod protocol;
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p tmux-client`
Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/tmux-client/src/
git commit -m "feat(tmux-client): decode %begin/%end/%output control-mode lines"
```

---

## Task 3: tmux-client — spawn `tmux -CC` and stream stdout

Wraps the child process. Read stdout line-by-line through the `Decoder` and emit events on a tokio mpsc channel. Writes to stdin sent via a `send_command` method.

**Files:**
- Create: `crates/tmux-client/src/conn.rs`
- Modify: `crates/tmux-client/src/lib.rs`
- Create: `crates/tmux-client/tests/integration.rs`

- [ ] **Step 1: Implement `Connection`**

Create `crates/tmux-client/src/conn.rs`:

```rust
//! Manages the lifecycle of a `tmux -CC` child process.

use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;

use crate::protocol::{Decoder, Event};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to spawn tmux: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("tmux exited unexpectedly")]
    Exited,
}

pub struct Connection {
    _child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<Event>,
}

impl Connection {
    pub async fn attach(socket: &str, session: &str) -> Result<Self, Error> {
        let mut cmd = Command::new("tmux");
        cmd.args(["-L", socket, "-CC", "attach-session", "-t", session])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().ok_or(Error::Exited)?;
        let stdout = child.stdout.take().ok_or(Error::Exited)?;

        let (tx, rx) = mpsc::channel::<Event>(256);
        tokio::spawn(read_loop(stdout, tx));

        Ok(Self { _child: child, stdin, rx })
    }

    pub async fn send_command(&mut self, cmd: &str) -> Result<(), Error> {
        self.stdin.write_all(cmd.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}

async fn read_loop(stdout: tokio::process::ChildStdout, tx: mpsc::Sender<Event>) {
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();
    let mut decoder = Decoder::default();
    while let Ok(Some(line)) = lines.next_line().await {
        for ev in decoder.push_line(&line) {
            if tx.send(ev).await.is_err() {
                break;
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self where Self: Sized {
        // Distinguished only by error message — both Spawn and Exited can wrap io::Error.
        // Use Spawn as the catch-all for write/flush failures.
        let _ = e; Error::Exited
    }
}
```

Wait — the `From<io::Error>` impl conflicts. Drop it. The `send_command` returns `Result<(), Error>`; convert write errors via `?` using the existing `#[from]` on `Spawn`. Final file:

```rust
//! Manages the lifecycle of a `tmux -CC` child process.

use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;

use crate::protocol::{Decoder, Event};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tmux io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tmux exited unexpectedly")]
    Exited,
}

pub struct Connection {
    _child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<Event>,
}

impl Connection {
    pub async fn attach(socket: &str, session: &str) -> Result<Self, Error> {
        let mut cmd = Command::new("tmux");
        cmd.args(["-L", socket, "-CC", "attach-session", "-t", session])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().ok_or(Error::Exited)?;
        let stdout = child.stdout.take().ok_or(Error::Exited)?;

        let (tx, rx) = mpsc::channel::<Event>(256);
        tokio::spawn(read_loop(stdout, tx));

        Ok(Self { _child: child, stdin, rx })
    }

    pub async fn send_command(&mut self, cmd: &str) -> Result<(), Error> {
        self.stdin.write_all(cmd.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}

async fn read_loop(stdout: tokio::process::ChildStdout, tx: mpsc::Sender<Event>) {
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();
    let mut decoder = Decoder::default();
    while let Ok(Some(line)) = lines.next_line().await {
        for ev in decoder.push_line(&line) {
            if tx.send(ev).await.is_err() {
                break;
            }
        }
    }
}
```

Update `crates/tmux-client/src/lib.rs`:

```rust
//! tmux control-mode (-CC) client.

pub mod conn;
pub mod protocol;
```

- [ ] **Step 2: Write the integration test**

Create `crates/tmux-client/tests/integration.rs`:

```rust
use std::process::Command;
use tmux_client::conn::Connection;
use tmux_client::protocol::Event;

fn ensure_server(socket: &str, session: &str) {
    let _ = Command::new("tmux")
        .args(["-L", socket, "new-session", "-d", "-s", session])
        .status();
}

fn kill_server(socket: &str) {
    let _ = Command::new("tmux").args(["-L", socket, "kill-server"]).status();
}

#[tokio::test(flavor = "multi_thread")]
async fn list_sessions_round_trip() {
    let socket = "terminal-hub-test-m1";
    let session = "smoke";
    ensure_server(socket, session);

    let mut conn = Connection::attach(socket, session).await.expect("attach");
    conn.send_command("list-sessions -F '#{session_name}'").await.unwrap();

    let mut got = None;
    for _ in 0..200 {
        if let Some(ev) = conn.recv().await {
            if let Event::CommandOk { body } = ev {
                got = Some(body);
                break;
            }
        }
    }
    kill_server(socket);

    let body = got.expect("a CommandOk before timeout");
    assert!(body.lines().any(|l| l == session), "expected {session} in {body:?}");
}
```

- [ ] **Step 3: Run**

Run: `cargo test -p tmux-client --test integration -- --nocapture`
Expected: `list_sessions_round_trip ... ok`.

- [ ] **Step 4: Commit**

```bash
git add crates/tmux-client/src/conn.rs crates/tmux-client/src/lib.rs crates/tmux-client/tests/
git commit -m "feat(tmux-client): spawn tmux -CC child and emit decoded events"
```

---

## Task 4: server — axum hello world with health endpoint

**Files:**
- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/lib.rs`
- Modify: `crates/server/src/main.rs`
- Create: `crates/server/tests/http.rs`

- [ ] **Step 1: Add HTTP dependencies and a lib target**

Update `crates/server/Cargo.toml`:

```toml
[package]
name = "terminal-hub-server"
version = "0.1.0"
edition.workspace = true

[lib]
path = "src/lib.rs"

[[bin]]
name = "terminal-hub"
path = "src/main.rs"

[dependencies]
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }
axum = { version = "0.7", features = ["ws"] }
tower = "0.5"
tower-http = { version = "0.5", features = ["fs", "trace"] }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "test-util"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```

- [ ] **Step 2: Create the library with a `router()` factory**

Create `crates/server/src/lib.rs`:

```rust
use axum::{routing::get, Router};

pub fn router() -> Router {
    Router::new().route("/healthz", get(|| async { "ok" }))
}
```

Replace `crates/server/src/main.rs`:

```rust
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let bind = std::env::var("TERMINAL_HUB_BIND").unwrap_or_else(|_| "127.0.0.1:5999".into());
    tracing::info!(%bind, "terminal-hub listening");
    let listener = TcpListener::bind(&bind).await?;
    axum::serve(listener, terminal_hub_server::router()).await?;
    Ok(())
}
```

- [ ] **Step 3: Write the integration test**

Create `crates/server/tests/http.rs`:

```rust
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn spawn_app() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = terminal_hub_server::router();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn health_returns_ok() {
    let addr = spawn_app().await;
    let body = reqwest::get(format!("http://{addr}/healthz"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "ok");
}
```

- [ ] **Step 4: Run**

Run: `cargo test -p terminal-hub-server --test http`
Expected: `health_returns_ok ... ok`.

- [ ] **Step 5: Manual smoke**

Run: `cargo run -p terminal-hub-server`, then in another shell `curl http://127.0.0.1:5999/healthz` → `ok`. Stop with Ctrl-C.

- [ ] **Step 6: Commit**

```bash
git add crates/server/
git commit -m "feat(server): axum hello world with /healthz endpoint and HTTP test"
```

---

## Task 5: Static frontend — xterm.js page served from server

**Files:**
- Create: `crates/server/static/index.html`
- Create: `crates/server/static/app.js`
- Create: `crates/server/static/app.css`
- Modify: `crates/server/src/lib.rs`
- Modify: `crates/server/tests/http.rs`

- [ ] **Step 1: Static files**

Create `crates/server/static/index.html`:

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
    <div id="terminal"></div>
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
    <script src="/app.js" type="module"></script>
  </body>
</html>
```

Create `crates/server/static/app.css`:

```css
html, body { margin: 0; height: 100%; background: #111; }
#terminal { height: 100vh; padding: 8px; }
```

Create `crates/server/static/app.js`:

```js
const term = new Terminal({ cursorBlink: true, fontFamily: "Menlo, monospace", fontSize: 13 });
term.open(document.getElementById("terminal"));
term.writeln("terminal-hub M1 walking skeleton — connecting…");
```

- [ ] **Step 2: Wire static serving**

Update `crates/server/src/lib.rs`:

```rust
use axum::{routing::get, Router};
use tower_http::services::ServeDir;

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .fallback_service(ServeDir::new(static_dir()))
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("static");
    p
}
```

- [ ] **Step 3: Extend the HTTP test**

Add to `crates/server/tests/http.rs`:

```rust
#[tokio::test]
async fn root_serves_index_html() {
    let addr = spawn_app().await;
    let body = reqwest::get(format!("http://{addr}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("<title>terminal-hub</title>"), "got: {body}");
    assert!(body.contains("xterm"), "should reference xterm.js");
}
```

- [ ] **Step 4: Run**

Run: `cargo test -p terminal-hub-server --test http`
Expected: both tests pass.

- [ ] **Step 5: Manual smoke**

`cargo run -p terminal-hub-server`, open `http://127.0.0.1:5999/`. Expect xterm.js rendering the placeholder text on a dark background.

- [ ] **Step 6: Commit**

```bash
git add crates/server/static/ crates/server/src/lib.rs crates/server/tests/http.rs
git commit -m "feat(server): serve xterm.js frontend from /"
```

---

## Task 6: server — WebSocket echo endpoint (proves the WS path)

Before wiring to tmux, prove the WebSocket plumbing works.

**Files:**
- Modify: `crates/server/Cargo.toml`
- Modify: `crates/server/src/lib.rs`
- Create: `crates/server/tests/ws.rs`

- [ ] **Step 1: Add dev deps**

Add to `crates/server/Cargo.toml` `[dev-dependencies]`:

```toml
tokio-tungstenite = "0.23"
futures-util = "0.3"
```

- [ ] **Step 2: Add the echo handler**

Update `crates/server/src/lib.rs`:

```rust
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;
use tower_http::services::ServeDir;

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws/echo", any(ws_echo))
        .fallback_service(ServeDir::new(static_dir()))
}

async fn ws_echo(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_echo)
}

async fn handle_echo(mut socket: WebSocket) {
    while let Some(Ok(msg)) = socket.recv().await {
        if let Message::Text(t) = msg {
            if socket.send(Message::Text(t)).await.is_err() {
                return;
            }
        }
    }
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("static");
    p
}
```

- [ ] **Step 3: Write the test**

Create `crates/server/tests/ws.rs`:

```rust
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

async fn spawn_app() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = terminal_hub_server::router();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn ws_echoes_text() {
    let addr = spawn_app().await;
    let url = format!("ws://{addr}/ws/echo");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.expect("connect");
    ws.send(Message::Text("hello".into())).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::Text("hello".into()));
}
```

- [ ] **Step 4: Run**

Run: `cargo test -p terminal-hub-server --test ws`
Expected: `ws_echoes_text ... ok`.

- [ ] **Step 5: Commit**

```bash
git add crates/server/
git commit -m "feat(server): /ws/echo endpoint with round-trip test"
```

---

## Task 7: server — wire `/ws/attach` to a tmux session

Integration step. `/ws/attach` opens a `tmux_client::Connection` to the configured socket + session, fans pane output into the WebSocket as binary frames, and forwards WebSocket input to tmux via `send-keys -l`.

**Files:**
- Modify: `crates/server/Cargo.toml`
- Modify: `crates/server/src/lib.rs`
- Create: `crates/server/src/attach.rs`
- Create: `crates/server/tests/attach.rs`

- [ ] **Step 1: Add `tmux-client` as a dependency**

Update `crates/server/Cargo.toml` `[dependencies]`:

```toml
tmux-client = { path = "../tmux-client" }
```

- [ ] **Step 2: Implement the attach handler**

Create `crates/server/src/attach.rs`:

```rust
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
```

- [ ] **Step 3: Add config + route**

Replace `crates/server/src/lib.rs`:

```rust
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;
use std::sync::Arc;
use tower_http::services::ServeDir;

mod attach;

pub struct Config {
    pub tmux_socket: String,
    pub tmux_session: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tmux_socket: std::env::var("TERMINAL_HUB_TMUX_SOCKET")
                .unwrap_or_else(|_| "terminal-hub".into()),
            tmux_session: std::env::var("TERMINAL_HUB_TMUX_SESSION")
                .unwrap_or_else(|_| "scratch".into()),
        }
    }
}

pub fn router() -> Router { router_with(Config::default()) }

pub fn router_with(cfg: Config) -> Router {
    let state = Arc::new(cfg);
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws/echo", any(ws_echo))
        .route("/ws/attach", any(attach::ws_attach))
        .fallback_service(ServeDir::new(static_dir()))
        .with_state(state)
}

async fn ws_echo(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_echo)
}
async fn handle_echo(mut s: WebSocket) {
    while let Some(Ok(m)) = s.recv().await {
        if let Message::Text(t) = m {
            if s.send(Message::Text(t)).await.is_err() { return; }
        }
    }
}

fn static_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("static");
    p
}
```

Update `main.rs` is unchanged.

- [ ] **Step 4: Write the integration test**

Create `crates/server/tests/attach.rs`:

```rust
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const SOCKET: &str = "terminal-hub-test-m1-attach";
const SESSION: &str = "scratch";

fn ensure_server() {
    let _ = Command::new("tmux")
        .args(["-L", SOCKET, "new-session", "-d", "-s", SESSION])
        .status();
}

fn kill_server() {
    let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status();
}

async fn spawn_app() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        tmux_socket: SOCKET.into(),
        tmux_session: SESSION.into(),
    };
    let app = terminal_hub_server::router_with(cfg);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_echoes_typed_chars() {
    ensure_server();
    let addr = spawn_app().await;
    let url = format!("ws://{addr}/ws/attach");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

    ws.send(Message::Text("echo ping\r".into())).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut saw_ping = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) if std::str::from_utf8(&b).map(|s| s.contains("ping")).unwrap_or(false) => {
                saw_ping = true;
                break;
            }
            _ => {}
        }
    }

    kill_server();
    assert!(saw_ping, "expected to see 'ping' echoed back from the shell");
}
```

- [ ] **Step 5: Run**

Run: `cargo test -p terminal-hub-server --test attach -- --nocapture`
Expected: `attach_echoes_typed_chars ... ok`.

- [ ] **Step 6: Commit**

```bash
git add crates/server/
git commit -m "feat(server): /ws/attach proxies bytes between browser and tmux session"
```

---

## Task 8: Frontend — connect xterm.js to `/ws/attach`

**Files:**
- Modify: `crates/server/static/app.js`

- [ ] **Step 1: Replace the placeholder script**

Update `crates/server/static/app.js`:

```js
const term = new Terminal({
  cursorBlink: true,
  fontFamily: "Menlo, monospace",
  fontSize: 13,
  scrollback: 5000,
});
term.open(document.getElementById("terminal"));
term.writeln("terminal-hub M1 — connecting…");

const proto = location.protocol === "https:" ? "wss" : "ws";
const ws = new WebSocket(`${proto}://${location.host}/ws/attach`);
ws.binaryType = "arraybuffer";

ws.addEventListener("open", () => {
  term.writeln("\x1b[32mconnected\x1b[0m");
});
ws.addEventListener("message", (ev) => {
  if (ev.data instanceof ArrayBuffer) {
    term.write(new Uint8Array(ev.data));
  } else {
    term.write(ev.data);
  }
});
ws.addEventListener("close", () => {
  term.writeln("\r\n\x1b[31mdisconnected\x1b[0m");
});

term.onData((data) => {
  if (ws.readyState === WebSocket.OPEN) ws.send(data);
});
```

- [ ] **Step 2: Manual end-to-end smoke**

One-time tmux server bootstrap (dev only):

```bash
tmux -L terminal-hub new-session -d -s scratch
```

Then:

```bash
cargo run -p terminal-hub-server
```

Open `http://127.0.0.1:5999/`. Type `echo hello` ⏎. Expect:

```
terminal-hub M1 — connecting…
connected
$ echo hello
hello
$
```

If escape codes show literally (`\033[…`): fix `unescape_octal` in `attach.rs`.

- [ ] **Step 3: Commit**

```bash
git add crates/server/static/app.js
git commit -m "feat(frontend): wire xterm.js to /ws/attach"
```

---

## Task 9: README and CLAUDE.md status

**Files:**
- Create: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: README**

Create `README.md`:

```markdown
# terminal-hub

A Rust web server that hosts long-lived terminal sessions backed by tmux and exposes them through a browser.

## Status

M1 (walking skeleton) — one hardcoded session, no auth. See `docs/superpowers/plans/` for milestones.

## Dev setup

Requires Rust ≥ 1.79, tmux ≥ 3.0.

    tmux -L terminal-hub new-session -d -s scratch
    cargo run -p terminal-hub-server
    open http://127.0.0.1:5999/

Stop the tmux server: `tmux -L terminal-hub kill-server`.

## Tests

    cargo test --workspace

Integration tests start and stop their own ephemeral tmux servers; they require `tmux` on `PATH`.
```

- [ ] **Step 2: Update CLAUDE.md status section**

Replace the `## Repository status` block in `CLAUDE.md` with:

```markdown
## Repository status

M1 (walking skeleton) complete. Cargo workspace with three crates (`tmux-client`, `server`, `cli`). One hardcoded tmux session attachable in the browser at `/`. No auth yet. See `docs/superpowers/specs/2026-05-21-terminal-hub-design.md` for the full design and `docs/superpowers/plans/` for milestone plans.

Build: `cargo build --workspace`
Test: `cargo test --workspace` (some tests require `tmux` on PATH)
Run: `cargo run -p terminal-hub-server` (after `tmux -L terminal-hub new-session -d -s scratch`)
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: README and CLAUDE.md status for M1 completion"
```

---

## Done criteria for M1

- `cargo build --workspace` passes
- `cargo test --workspace` passes with `tmux` installed
- Manual smoke in Task 8 Step 2 produces a working browser terminal
- `cargo clippy --workspace -- -D warnings` clean
- `git log --oneline` shows ~9 commits, one per task

**Next milestone:** M2 — multi-session local + sidebar. See `docs/superpowers/plans/2026-05-21-m2-multi-session-local.md`.
