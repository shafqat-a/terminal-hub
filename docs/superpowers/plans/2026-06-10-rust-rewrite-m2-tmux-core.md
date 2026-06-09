# Rust Rewrite M2 — tmux Core (sessions, interactive WS, terminal UI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** tmux-backed terminal sessions with full CRUD, an interactive WebSocket wire-compatible with the Go implementation (JSON output/input/resize envelope, capture-pane repaint on attach), and the ported terminal UI.

**Architecture decision (recorded spec deviation):** The design spec sketched tmux *control mode* (Approach A). Investigation of both reference codebases changed this: the working Go implementation holds **one PTY per session** running `tmux new-session -A` and broadcasts raw bytes; control mode + octal-escape parsing is what the buggy legacy terminal-hub used — that escaping layer is implicated in its rendering bugs. M2 therefore follows the Go architecture: PTY-attach per session (server holds the PTY; viewers fan out in-process), `capture-pane -e -p -S -2000` repaint on every attach (LF→CRLF), resize via PTY ioctl. The spec's centerpiece — tmux owns state, reconnect repaints exactly — is preserved. The legacy `tmux-client` control-mode crate is NOT reused.

**Tech Stack additions:** portable-pty 0.8, uuid v1 (v4 feature), futures-util, time 0.3; dev: tokio-tungstenite (integration test).

**Execution environment:** ALL commands on Annihilator in `~/git/terminal-hub` (branch main) via
`ssh -p 22 -o BatchMode=yes shafqat@192.168.0.66 'export PATH=$HOME/.cargo/bin:$PATH && cd ~/git/terminal-hub && <command>'`.
File writes via python3 heredoc. `cargo fmt --all` before every commit; `cargo fmt --all -- --check` and `cargo clippy --workspace -- -D warnings` must stay clean at every commit (no #[allow]; test-only helpers may use `#[cfg(test)]`). Go reference: `~/git/ai-dev-conductor` (feat/file-transfer). tmux is installed on the host and in CI.

---

### Wire contract (extracted from Go source — normative)

**WS /ws/{id}** (auth-gated; token usually arrives as `?token=` for WS):
- Text frames both directions carry JSON: `{"type":"...","data":"...","mime":"...","rows":N,"cols":N}` (omit empty fields).
- Server→client: only `{"type":"output","data":"<utf8 string>"}`.
- On connect, FIRST message = snapshot: `tmux capture-pane -t <name> -e -p -S -2000`, bytes with bare `\n` replaced by `\r\n`, sent as one `output` message (lossy UTF-8 conversion acceptable: Go sends through a JSON string too).
- Client→server text: `input` (data = literal keystrokes incl. control chars) → write bytes to PTY; `resize` (rows, cols; ignore if either is 0) → PTY resize; `paste-image` (mime + base64 data) → **M2: accept and drop with a tracing::debug note** (implemented in M5).
- Client→server binary frames: raw bytes → write to PTY unmodified.
- Ping every 30s; treat no inbound frame for 60s as dead. Per-message write timeout 10s.
- Multiple viewers: all receive output (broadcast); any may send input; last resize wins.
- Slow viewer: broadcast Lagged → skip (continue), never block other viewers or grow unboundedly.

**Session CRUD** (all under auth):
- `GET /api/sessions` → 200 JSON array of `{"id","name","createdAt","status","lastActivityAt","lastClientDisconnectAt","cols","rows"}`; `createdAt` formatted `"YYYY-MM-DD HH:MM:SS"` (Go `2006-01-02 15:04:05`, local time); `status` ∈ "running"|"detached"|"dead" (M2 emits "running"; others wired in M3); `lastActivityAt` unix secs; `lastClientDisconnectAt` unix secs (0 while a client is attached or never attached).
- `POST /api/sessions` body optional `{"name":"..."}` → 201 `{"id":"<8 hex>","name":"<name-or-id>"}`; spawn failure → 500 `{"error":"<msg>"}`. (Session cap → 429 arrives in M3.)
- `PUT /api/sessions/{id}` `{"name":"..."}` → 200 `{"success":true}`; empty name → 400 `{"error":"name required"}`; unknown id → 404 `{"error":"session <id> not found"}`.
- `DELETE /api/sessions/{id}` → 200 `{"success":true}`; unknown → 404 same shape.
- Session id: 8 lowercase hex chars (Go: uuid[:8]). tmux session name `aidc_<id>`; private socket `<data_dir>/tmux.sock`; env: `TMUX` removed, `TERM=xterm-256color`; shell: add `shell: String` to Config — lookup `AI_CONDUCTOR_SHELL`, default `std::env::var("SHELL")` then `/bin/bash` fallback (with config tests).

**tmux invocations** (always `tmux -S <data_dir>/tmux.sock ...`):
- spawn-in-PTY: `new-session -A -s aidc_<id> -- <shell>`
- `has-session -t <name>`; `kill-session -t <name>`; `list-sessions -F '#{session_name}'` (server-not-running → empty list, NOT error); `capture-pane -t <name> -e -p -S -2000`.

---

## Task 1: tmux helper crate

**Files:** Create `crates/tmux/Cargo.toml`, `crates/tmux/src/lib.rs`. Modify workspace `Cargo.toml` members.

Deps: `tokio = { workspace = true }`, `thiserror = { workspace = true }`. Dev-deps: `tempfile = "3"`.

Public API (all async via `tokio::process::Command`, env `TMUX` removed + `TERM=xterm-256color` set on every invocation):
```rust
pub fn socket_path(data_dir: &Path) -> PathBuf;            // data_dir/tmux.sock
pub fn session_name(id: &str) -> String;                   // format!("aidc_{id}")
pub enum TmuxError { Io(std::io::Error), Failed { stderr: String } } // thiserror
pub async fn run(data_dir: &Path, args: &[&str]) -> Result<Vec<u8>, TmuxError>; // stdout on success
pub async fn has_session(data_dir: &Path, name: &str) -> bool;
pub async fn kill_session(data_dir: &Path, name: &str) -> Result<(), TmuxError>;
pub async fn list_sessions(data_dir: &Path) -> Vec<String>; // empty on any failure (no server yet)
pub async fn capture_pane(data_dir: &Path, name: &str, lines: u32) -> Result<Vec<u8>, TmuxError>;
   // args: capture-pane -t name -e -p -S -<lines>
pub fn attach_args(data_dir: &Path, name: &str, shell: &str) -> Vec<String>;
   // ["-S", sock, "new-session", "-A", "-s", name, "--", shell] — consumed by the PTY spawner
```

TDD with a REAL tmux against a tempdir socket: create detached session via `run(["new-session","-d","-s","aidc_t1","--","/bin/sh"])`, has_session true/false, list contains it, capture_pane returns bytes after `send-keys` of an echo (poll up to ~2s), kill_session, list empty after. Unique tempdir socket per test so parallel tests can't collide; always kill created sessions before test ends.

Commit: `feat(tmux): tmux helper crate with socketed command wrappers`

---

## Task 2: PTY-backed session runtime + manager

**Files:** Create `crates/server/src/session/mod.rs`, `crates/server/src/session/pty.rs`. Modify `crates/server/Cargo.toml` (add `portable-pty = "0.8"`, `tmux = { path = "../tmux" }`, `uuid = { version = "1", features = ["v4"] }`, `time = { version = "0.3", features = ["formatting", "local-offset"] }`), `main.rs` (`mod session;`), `config.rs` (add `shell` field + tests), `crates/store` (sessions table).

`pty.rs` — runtime around one tmux-attach PTY:
```rust
pub struct PtyHandle {
    pub output: tokio::sync::broadcast::Sender<Vec<u8>>, // capacity 1024
    writer: std::sync::Mutex<Box<dyn std::io::Write + Send>>,
    master: std::sync::Mutex<Box<dyn portable_pty::MasterPty + Send>>,
    pub last_activity: std::sync::Arc<std::sync::atomic::AtomicI64>, // unix secs, set by reader thread
    child: std::sync::Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
}
impl PtyHandle {
    pub fn spawn(data_dir: &Path, name: &str, shell: &str, rows: u16, cols: u16) -> Result<Arc<Self>, PtyError>;
    // native_pty_system().openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
    // CommandBuilder::new("tmux") + tmux::attach_args; env TERM=xterm-256color; env_remove TMUX
    // slave.spawn_command; DROP the slave; master.try_clone_reader(); master.take_writer()
    // std::thread reader loop: 4096-byte read → last_activity.store(unix_now) → output.send(buf[..n].to_vec()).ok()
    //   (send error = no receivers = fine); read 0/Err → thread exits (tmux client died = detached/killed)
    pub fn write(&self, bytes: &[u8]) -> std::io::Result<()>;       // lock writer (poison-recover), write_all + flush
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError>; // master.resize(PtySize{...})
    pub fn detach(&self);                                            // child.kill().ok() — tmux session survives
}
```
Locks follow the project convention: `unwrap_or_else(|e| e.into_inner())`.

TDD against real tmux: spawn with /bin/sh in tempdir, subscribe, `write(b"echo m2proof\n")`, collect broadcast frames with timeout until "m2proof" appears (assemble bytes across frames), resize(40,120) then poll `tmux -S <sock> display-message -p -t <name> '#{window_width}'` → "120", detach, `has_session` still true, kill cleanup.

`session/mod.rs` — manager + metadata:
```rust
pub struct Session { pub id: String, pub name: std::sync::Mutex<String>, pub created_at: i64,
    pub size: std::sync::Mutex<(u16, u16)>,          // (cols, rows), default (80, 24)
    pub last_client_disconnect: std::sync::atomic::AtomicI64,
    pub viewers: std::sync::atomic::AtomicUsize,
    pub pty: std::sync::Arc<pty::PtyHandle> }
impl Session { pub fn viewer_attached(&self); pub fn viewer_detached(&self); } // counts + disconnect stamp
pub struct Manager { data_dir: PathBuf, shell: String,
    sessions: tokio::sync::RwLock<HashMap<String, Arc<Session>>>, store: Arc<store::Store> }
impl Manager {
    pub fn new(data_dir, shell, store) -> Self;
    pub async fn create(&self, name: Option<String>) -> Result<Arc<Session>, CreateError>;
      // id = &uuid::Uuid::new_v4().simple().to_string()[..8]; name defaults to id;
      // PtyHandle::spawn (24 rows, 80 cols); insert; store.upsert_session(id, name, created_at)
    pub async fn list(&self) -> Vec<SessionInfo>;   // serde Serialize, EXACT camelCase wire names
    pub async fn get(&self, id: &str) -> Option<Arc<Session>>;
    pub async fn rename(&self, id: &str, name: &str) -> Result<(), NotFound>; // store.rename_session too
    pub async fn delete(&self, id: &str) -> Result<(), NotFound>; // pty.detach, tmux::kill_session, store.delete_session
}
```
`SessionInfo` serializes: id, name, createdAt (formatted string), status ("running"), lastActivityAt (i64), lastClientDisconnectAt (i64), cols, rows. createdAt formatting: `time` crate, format_description `[year]-[month]-[day] [hour]:[minute]:[second]`, local offset via `UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC)` — pin with a unit test on a fixed timestamp (assert against the same computation's UTC rendering to stay TZ-independent, plus regex shape test at the API layer).

Store additions (crates/store, TDD): `sessions` table `(id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'running')`; methods `upsert_session(id, name, created_at)`, `rename_session(id, name) -> bool (found)`, `delete_session(id) -> bool`, `list_sessions() -> Vec<(String, String, i64, String)>`.

Commits: `feat(store): sessions table` → `feat(session): PTY-backed tmux session runtime` → `feat(session): manager with CRUD and store persistence`

---

## Task 3: Session CRUD endpoints

**Files:** Modify `crates/server/src/handlers.rs`, `crates/server/src/app.rs`.

AppState gains `pub manager: session::Manager`; `AppState.store` becomes `Arc<store::Store>` shared with the manager (adjust build_state + middleware accordingly).

Handlers per the wire contract: GET list (200 array), POST create (201 {id,name}; 500 {"error":msg} on spawn failure), PUT rename (200 {"success":true} / 400 {"error":"name required"} / 404 {"error":"session <id> not found"}), DELETE (200 {"success":true} / 404). Replace the `/api/sessions` placeholder route; add POST/PUT/DELETE inside the protected router.

Tests (app.rs tests module — test_app tempdir doubles as data_dir so tmux sockets are isolated; delete sessions within each test): create→201 + 8-char id; list shows all 8 fields, createdAt matches `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$` (regex via plain string checks, no new deps: split/len checks acceptable); rename flow 200→list reflects; rename ""→400; rename unknown→404 exact body; delete→200, list empty, `tmux::has_session` false; delete unknown→404.

Commit: `feat(api): session CRUD with Go-compatible wire shapes`

---

## Task 4: Interactive WebSocket

**Files:** Create `crates/server/src/ws.rs`. Modify `app.rs` (route `/ws/:id` in protected router; `mod ws;` in main.rs), `Cargo.toml` (axum features ["ws"], `futures-util = "0.3"`; dev-dep `tokio-tungstenite = "0.23"`).

```rust
pub async fn ws_session(State(state): State<SharedState>, Path(id): Path<String>, ws: WebSocketUpgrade) -> Response {
    let Some(sess) = state.manager.get(&id).await else {
        return json_error(StatusCode::NOT_FOUND, &format!("session {id} not found"));
    };
    let data_dir = state.cfg.data_dir.clone();
    ws.on_upgrade(move |socket| pump(socket, sess, data_dir))
}
async fn pump(socket: WebSocket, sess: Arc<Session>, data_dir: PathBuf) {
    sess.viewer_attached();
    // snapshot: tmux::capture_pane(&data_dir, &tmux::session_name(&sess.id), 2000)
    //   → bytes replace b"\n" with b"\r\n" (verbatim Go bytes.ReplaceAll) → 
    //   Text(json!({"type":"output","data": String::from_utf8_lossy(&snap)}).to_string())
    let mut rx = sess.pty.output.subscribe();
    let (mut sink, mut stream) = socket.split();
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    let mut last_inbound = Instant::now();
    loop {
        tokio::select! {
            out = rx.recv() => match out {
                Ok(bytes) => { /* Text(output envelope, from_utf8_lossy); 10s write timeout; err → break */ }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            },
            frame = stream.next() => {
                last_inbound = Instant::now();
                match frame {
                    Some(Ok(Message::Text(t))) => { /* parse ClientMsg{type,data,rows,cols,mime}:
                        "input" → sess.pty.write(data.as_bytes()).ok();
                        "resize" if rows>0 && cols>0 → pty.resize(rows,cols).ok() + *sess.size.lock... = (cols,rows);
                        "paste-image" → tracing::debug!("paste-image deferred to M5");
                        other/parse-fail → ignore */ }
                    Some(Ok(Message::Binary(b))) => { sess.pty.write(&b).ok(); }
                    Some(Ok(_)) => {}            // axum auto-pongs pings
                    Some(Err(_)) | None => break,
                }
            },
            _ = ping.tick() => {
                if last_inbound.elapsed() > Duration::from_secs(60) { break; }
                /* send Message::Ping(vec![]) with 10s timeout; err → break */
            }
        }
    }
    sess.viewer_detached();
}
```
ClientMsg: serde Deserialize with defaults so absent fields parse.

Tests (real TCP server in-test, NOT oneshot):
```rust
async fn spawn_server() -> (SocketAddr, SharedState, tempfile::TempDir) {
  // build_state over tempdir cfg; axum::serve(TcpListener::bind("127.0.0.1:0"), build_app(state)
  //   .into_make_service_with_connect_info::<SocketAddr>()) in tokio::spawn; return local_addr
}
#[tokio::test] ws_end_to_end:
  // state.manager.create(None); state.store.add_auth_session("wstoken", i64::MAX/4 or now+9999)
  // tokio_tungstenite::connect_async("ws://{addr}/ws/{id}?token=wstoken")
  // first msg: JSON with type=="output" (snapshot; any data)
  // send input {"type":"input","data":"echo WSPROOF\n"}; read until some output frame contains "WSPROOF" (5s budget)
  // send {"type":"resize","cols":120,"rows":40}; connection stays alive (send another echo, get output)
  // send Binary(b"\r".to_vec()); still alive; close. manager.delete at end.
#[tokio::test] ws_unknown_session_is_404: connect_async to /ws/zzzzzzzz?token=valid → handshake error w/ HTTP 404
#[tokio::test] ws_requires_auth: no token → handshake error (401 from middleware)
```

Commit: `feat(ws): interactive session WebSocket with capture-pane repaint on attach`

---

## Task 5: Terminal UI port

**Files:** Create `web/templates/terminal.html`, `web/static/js/app.js` (ported from `~/git/ai-dev-conductor/web/`). Modify `app.rs` (/terminal serves the page), `assets.rs` (terminal_page handler).

Strip Go template directives exactly as for login.html: every `{{...}}` removed; repair ALL `BASE_PATH` plumbing including the WS URL construction (`ws(s)://host + BASE_PATH + /ws/...` → absolute `/ws/...`) and fetch prefixes. app.js references share/upload/download endpoints that arrive in M4 — leave that code intact (buttons 404 gracefully); add one comment line at the top of the ported file noting M4 fills them. Verify: `grep -c '{{'` = 0 and `grep -c 'BASE_PATH'` = 0 in both files. Replace the `/terminal` placeholder route with `assets::terminal_page` (serves `templates/terminal.html`).

Tests: `/terminal` with token → 200 text/html, body contains `xterm` and `/ws/`, contains no `{{` and no `BASE_PATH` (mirror the login-page invariants test).

Commit: `feat(web): port terminal UI (xterm.js, palette, themes, mobile keys)`

---

## Task 6: Milestone gate, smoke, docs, push

1. Full gate: `cargo test --workspace` + `cargo clippy --workspace -- -D warnings` + `cargo fmt --all -- --check` — all green.
2. Real-binary smoke (single SSH session, scratch port + data dir): login via curl → POST /api/sessions → assert `tmux -S <scratch>/tmux.sock list-sessions` shows `aidc_<id>` → GET /api/sessions shows the 8 fields → PUT rename → DELETE → tmux session gone → GET /terminal with token returns the ported page. Paste outputs. Clean up scratch dir + pkill the binary.
3. Spec amendment: append to `docs/superpowers/specs/2026-06-10-ai-dev-conductor-rust-rewrite-design.md` §3 an "Amendment (M2)" paragraph: PTY-attach architecture replaces control mode, with the rationale from this plan's header.
4. Docs hygiene: tick all checkboxes in the M1 plan file (they were executed); this M2 plan's too as tasks complete.
5. Commit `docs: M2 spec amendment + plan checkbox hygiene`; `git push origin main`; poll https://api.github.com/repos/shafqat-a/terminal-hub/actions/runs until the run for HEAD concludes — must be success.

## M2 exit criteria
- All tests green including real-tmux PTY + WS integration tests; clippy/fmt clean; CI green on GitHub.
- Smoke proves: create→tmux session exists; WS snapshot + echo round-trip (in tests); rename/delete parity; /terminal serves ported UI.
- Carry-forwards remain open: SIGTERM (M6), `..` guard in assets + tower→dev-deps + unix_now relocation (M5 hardening).
