//! Chat API: turn-based question → reply over a terminal session.
//!
//! A mobile client that only wants "ask, get an answer" — not a live console —
//! talks to these endpoints. Each question is typed into the session's PTY
//! exactly as a human would; the reply is whatever the program running in
//! that console (a shell, Claude Code, any REPL) prints afterwards, captured
//! from tmux as plain text and persisted so old turns can be re-read later
//! without touching the terminal at all.
//!
//! Wire contract (all under auth; timestamps are unix milliseconds):
//!
//! - `POST   /api/sessions/:id/chat`             ask; `wait:true` long-polls the reply
//! - `GET    /api/sessions/:id/chat`             turns, cursor-paginated (`after`/`before`/`limit`)
//! - `GET    /api/sessions/:id/chat/stream`      SSE: live upserts of turns (`?after=` catch-up)
//! - `GET    /api/sessions/:id/chat/:msg_id`     one turn; `?wait=secs` long-polls while pending
//! - `POST   /api/sessions/:id/chat/:msg_id/cancel` stop waiting (`interrupt:true` sends Ctrl-C)
//! - `DELETE /api/sessions/:id/chat`             wipe the session's chat history
//! - `POST   /api/sessions/:id/chat/sync`        import console scrollback as turns (also automatic)
//! - `GET    /api/chat/overview`                 every session + newest turn, one round-trip
//! - `GET    /api/server/info`                   name/version/capabilities for multi-server clients
//!
//! # How a reply is captured
//!
//! tmux is the model (see the design spec): before the question is sent we
//! record the pane's scrollback size and visible screen. Afterwards the pane
//! is polled; the capture window starts at the old screen top so everything
//! that appeared since — however far it scrolled — is in view. The reply is
//! that window minus the old screen prefix, the echoed question, and trailing
//! prompt/status chrome. It is *settled* when the screen stops changing:
//! quickly (`settle_ms`) once a prompt is visible and no busy marker is, or
//! after a longer silence (`idle_ms`) otherwise, so a silent long-running
//! command is not cut off the moment its echo lands. A hard `timeout` bounds
//! the wait; whatever was captured by then is kept with status `timeout`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream::{self, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{broadcast, watch};

use crate::app::SharedState;
use crate::handlers::json_error;
use crate::session::Session;
use crate::transcript::norm;
use crate::util::unix_now_ms;

// ---- Tunables ---------------------------------------------------------------

/// Pane poll cadence while a reply is pending.
const POLL_INTERVAL: Duration = Duration::from_millis(150);
/// Minimum gap between partial-content publishes (DB write + SSE fan-out).
const PUBLISH_INTERVAL: Duration = Duration::from_millis(400);
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;
pub const MAX_TIMEOUT_SECS: u64 = 900;
const DEFAULT_SETTLE_MS: u64 = 1000;
const DEFAULT_IDLE_MS: u64 = 5000;
const MIN_SETTLE_MS: u64 = 200;
const MAX_IDLE_MS: u64 = 60_000;
/// Largest question accepted (bytes).
const MAX_TEXT_BYTES: usize = 64 * 1024;
/// Largest reply kept (bytes); older content is dropped from the front.
const MAX_REPLY_BYTES: usize = 200 * 1024;
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 500;
/// Characters of a turn shown in the overview preview.
const PREVIEW_CHARS: usize = 200;

pub const SOURCE_IMPORT: &str = "import";
/// How much scrollback a sync parses (lines above the screen).
const SYNC_SCROLLBACK_LINES: i64 = 5000;
/// Stored user turns consulted to align a parsed transcript.
const SYNC_ALIGN_WINDOW: usize = 20;
/// Re-sync cadence while a chat stream is open.
const STREAM_SYNC_INTERVAL: Duration = Duration::from_secs(3);

pub const ROLE_USER: &str = "user";
pub const ROLE_ASSISTANT: &str = "assistant";

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_DONE: &str = "done";
pub const STATUS_TIMEOUT: &str = "timeout";
pub const STATUS_CANCELLED: &str = "cancelled";
pub const STATUS_ERROR: &str = "error";

// ---- Wire types -------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub id: i64,
    pub session_id: String,
    pub role: String,
    pub content: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<i64>,
    /// "chat" | "import" (parsed from the console's scrollback).
    pub source: String,
}

impl From<store::ChatRow> for ChatMessage {
    fn from(r: store::ChatRow) -> Self {
        ChatMessage {
            id: r.id,
            session_id: r.session_id,
            role: r.role,
            content: r.content,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
            request_id: r.request_id,
            source: r.source,
        }
    }
}

// ---- Hub: pending replies + live event fan-out ------------------------------

/// Receives `Some(interrupt)` once a cancel is requested for a pending reply.
type CancelRx = watch::Receiver<Option<bool>>;

/// One in-flight reply for a session.
pub struct Pending {
    pub request_id: i64,
    pub reply_id: i64,
    done: watch::Sender<bool>,
    /// `Some(interrupt)` once a cancel was requested.
    cancel: watch::Sender<Option<bool>>,
}

impl Pending {
    pub fn done_rx(&self) -> watch::Receiver<bool> {
        self.done.subscribe()
    }
}

/// Process-wide chat coordination: at most one pending reply per session and
/// a broadcast of every turn upsert for SSE subscribers.
pub struct ChatHub {
    pending: Mutex<HashMap<String, Arc<Pending>>>,
    events: broadcast::Sender<ChatMessage>,
    /// Sessions with a scrollback sync in flight (never two at once).
    syncing: Mutex<std::collections::HashSet<String>>,
}

impl Default for ChatHub {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatHub {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(1024);
        ChatHub {
            pending: Mutex::new(HashMap::new()),
            events,
            syncing: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Claim the sync slot for a session; `false` when one is running.
    fn begin_sync(&self, session_id: &str) -> bool {
        self.syncing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session_id.to_string())
    }

    fn end_sync(&self, session_id: &str) {
        self.syncing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(session_id);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ChatMessage> {
        self.events.subscribe()
    }

    pub fn publish(&self, msg: ChatMessage) {
        // No subscribers is not an error.
        let _ = self.events.send(msg);
    }

    pub fn pending_for(&self, session_id: &str) -> Option<Arc<Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session_id)
            .cloned()
    }

    /// Register a pending reply; `Err` carries the existing one when the
    /// session is already busy.
    fn begin(
        &self,
        session_id: &str,
        request_id: i64,
        reply_id: i64,
    ) -> Result<(Arc<Pending>, CancelRx), Arc<Pending>> {
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(session_id) {
            return Err(Arc::clone(existing));
        }
        let (done, _) = watch::channel(false);
        let (cancel, cancel_rx) = watch::channel(None);
        let p = Arc::new(Pending {
            request_id,
            reply_id,
            done,
            cancel,
        });
        map.insert(session_id.to_string(), Arc::clone(&p));
        Ok((p, cancel_rx))
    }

    fn finish(&self, session_id: &str, p: &Pending) {
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if map
            .get(session_id)
            .map(|cur| cur.reply_id == p.reply_id)
            .unwrap_or(false)
        {
            map.remove(session_id);
        }
        p.done.send_replace(true);
    }
}

// ---- Pure text helpers ------------------------------------------------------

fn is_box_char(c: char) -> bool {
    matches!(
        c,
        '─' | '│'
            | '┌'
            | '┐'
            | '└'
            | '┘'
            | '╭'
            | '╮'
            | '╰'
            | '╯'
            | '┃'
            | '║'
            | '═'
            | '╌'
            | '┄'
            | '━'
    )
}

/// A line's "core": box-drawing chrome and whitespace stripped from both ends.
fn core(line: &str) -> &str {
    line.trim_matches(|c: char| c.is_whitespace() || is_box_char(c))
}

/// Shell/REPL prompt heuristic: a short line ending in a prompt character.
pub fn is_prompt_like(line: &str) -> bool {
    let c = core(line);
    if c.is_empty() || c.chars().count() > 80 {
        return false;
    }
    c.ends_with(['$', '#', '%', '>', '❯', '»'])
}

/// A busy marker printed by agent TUIs (Claude Code, Codex) while they work:
/// an "esc to interrupt" hint, or a spinner line such as
/// "* Moonwalking… (1m 15s · ↓ 4.2k tokens)" (the turn footer
/// "✻ Worked for 3s · done" is not busy).
pub fn is_busy_line(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    if l.contains("esc to interrupt") || l.contains("esc to cancel") {
        return true;
    }
    let c = line.trim_start();
    matches!(
        c.chars().next(),
        Some('*' | '✻' | '✶' | '✳' | '✢' | '✽' | '·' | '⠋')
    ) && c.contains('…')
        && !l.contains("· done")
}

/// A short line with no letters or digits at all ("...", "$", "│ │").
fn is_punctuation_only(line: &str) -> bool {
    let c = core(line);
    !c.is_empty() && c.chars().count() <= 4 && !c.chars().any(char::is_alphanumeric)
}

/// Status/help chrome that is never part of an answer.
fn is_chrome_line(line: &str) -> bool {
    let c = core(line);
    c.is_empty()
        || (c.starts_with('?') && c.contains("shortcuts"))
        || c.starts_with("⏵⏵")
        || c.starts_with("⏸")
}

/// Screen-idle verdict over the tail of a capture: a prompt is visible and no
/// busy marker is.
pub fn looks_idle(lines: &[&str]) -> bool {
    let tail: Vec<&str> = lines
        .iter()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(12)
        .copied()
        .collect();
    if tail.iter().any(|l| is_busy_line(l)) {
        return false;
    }
    tail.iter().any(|l| is_prompt_like(l))
}

/// Reduce the raw capture window to the reply text.
///
/// `before_screen` is the visible screen (trailing-blank-trimmed) at send
/// time; `window` starts at that screen's old top line. `question` is the
/// text that was typed.
pub fn extract_reply(before_screen: &[String], window: &str, question: &str) -> String {
    let lines: Vec<&str> = window.lines().map(str::trim_end).collect();

    // Preferred: anchor on the echoed question itself (the last prompt line
    // whose input is our question) and take everything after it. This is
    // immune to TUIs redrawing the old screen region above it.
    let probe: String = question
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(40)
        .collect();
    if probe.chars().count() >= 3 {
        let anchor = lines.iter().rposition(|l| {
            crate::transcript::prompt_input(l)
                .map(|input| {
                    let input: String = input.chars().take(40).collect();
                    input == probe || (input.len() >= 10 && probe.starts_with(&input))
                })
                .unwrap_or(false)
        });
        if let Some(i) = anchor {
            let mut body: Vec<&str> = lines[i + 1..].to_vec();
            // Wrapped/continued lines of the question itself: REPL "..."
            // continuations, indented wraps, or a verbatim further line of a
            // multi-line question. Output that merely resembles the question
            // (e.g. `echo <text>`) is not touched.
            let q_lines: Vec<&str> = question.lines().map(str::trim).collect();
            // Remainder of the first question line beyond the probe: a
            // soft-wrapped echo continues with exactly this text.
            let remainder: String = q_lines
                .first()
                .map(|l| l.chars().skip(probe.chars().count()).collect::<String>())
                .unwrap_or_default();
            let mut remainder = remainder.trim_start().to_string();
            while let Some(first) = body.first() {
                let t = first.trim();
                let cont = crate::transcript::user_continuation(first)
                    .map(|rest| rest.trim().is_empty() || question.contains(rest.trim()))
                    .unwrap_or(false);
                let verbatim = !t.is_empty() && q_lines[1..].contains(&t);
                let wrapped = !t.is_empty() && !remainder.is_empty() && remainder.starts_with(t);
                if cont || verbatim || wrapped {
                    if wrapped {
                        remainder = remainder[t.len()..].trim_start().to_string();
                    }
                    body.remove(0);
                } else {
                    break;
                }
            }
            return cap_reply(&crate::transcript::clean_answer(body));
        }
    }

    // 1. Drop the unchanged prefix that is just the old screen.
    let mut start = 0;
    while start < lines.len()
        && start < before_screen.len()
        && lines[start] == before_screen[start].trim_end()
    {
        start += 1;
    }
    let mut body: Vec<&str> = lines[start..].to_vec();

    // 2. Leading blanks, then the echoed question: every line of it in
    //    order (a pasted block is echoed line by line), each possibly
    //    soft-wrapped onto a continuation line.
    while body.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
        body.remove(0);
    }
    for q_line in question.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let probe: String = q_line.chars().take(40).collect();
        let Some(first) = body.first() else { break };
        if !first.contains(probe.as_str()) {
            break;
        }
        body.remove(0);
        let rest: String = q_line.chars().skip(probe.chars().count()).collect();
        let rest_probe: String = rest.trim().chars().take(20).collect();
        if !rest_probe.is_empty()
            && body
                .first()
                .map(|l| core(l).starts_with(rest_probe.as_str()))
                .unwrap_or(false)
        {
            body.remove(0);
        }
    }
    // A REPL's empty continuation prompt ("...") or a bare prompt left
    // between the echo and the output.
    while body
        .first()
        .map(|l| is_chrome_line(l) || is_prompt_like(l) || is_punctuation_only(l))
        .unwrap_or(false)
    {
        body.remove(0);
    }

    // 3. Trailing chrome: blanks, bare prompts, box frames, help/status lines.
    while let Some(last) = body.last() {
        if is_chrome_line(last) || is_prompt_like(last) {
            body.pop();
        } else {
            break;
        }
    }
    while body.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
        body.remove(0);
    }

    cap_reply(&body.join("\n"))
}

/// How the question is delivered to the pane (`send_mode` in the request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SendMode {
    /// Type single-line text; paste multi-line text when the program has
    /// bracketed paste enabled. Right for shells and agent TUIs alike.
    #[default]
    Auto,
    /// Always type character-for-character (LF becomes Enter).
    Type,
    /// Always wrap in a bracketed paste (falls back to typing when the
    /// program has not enabled the mode).
    Paste,
}

/// Bytes that put `text` into the pane's input line. Enter is sent
/// separately (see `press_enter`) so TUIs finish ingesting the text first.
pub fn keystrokes(text: &str, mode: SendMode, bracketed_paste_active: bool) -> Vec<u8> {
    let paste = bracketed_paste_active
        && match mode {
            SendMode::Auto => text.contains('\n'),
            SendMode::Type => false,
            SendMode::Paste => true,
        };
    let mut out = Vec::with_capacity(text.len() + 16);
    if paste {
        out.extend_from_slice(b"\x1b[200~");
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(b"\x1b[201~");
    } else {
        // Enter is CR on a tty; a bare LF would be typed as a literal.
        out.extend_from_slice(text.replace('\n', "\r").as_bytes());
    }
    out
}

/// Gap between the text and its Enter so a TUI's input handler sees the
/// question as typed text, not as one chunk that swallows the newline.
const ENTER_DELAY: Duration = Duration::from_millis(40);

fn preview(content: &str) -> String {
    let mut p: String = content.chars().take(PREVIEW_CHARS).collect();
    if content.chars().count() > PREVIEW_CHARS {
        p.push('…');
    }
    p
}

// ---- Reply engine -----------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct ReplyOptions {
    pub timeout: Duration,
    pub settle: Duration,
    pub idle: Duration,
}

struct Baseline {
    metrics: tmux::PaneMetrics,
    screen: Vec<String>,
}

async fn snapshot(
    data_dir: &std::path::Path,
    tmux_name: &str,
) -> Result<Baseline, tmux::TmuxError> {
    let metrics = tmux::pane_metrics(data_dir, tmux_name).await?;
    let raw = tmux::capture_pane_plain(data_dir, tmux_name, 0).await?;
    let mut screen: Vec<String> = String::from_utf8_lossy(&raw)
        .lines()
        .map(|l| l.trim_end().to_string())
        .collect();
    while screen.last().map(|l| l.is_empty()).unwrap_or(false) {
        screen.pop();
    }
    Ok(Baseline { metrics, screen })
}

/// Background task: poll the pane until the reply settles, publishing partial
/// content along the way, then persist the final turn and release the session.
async fn run_reply(
    state: SharedState,
    sess: Arc<Session>,
    pending: Arc<Pending>,
    mut cancel_rx: CancelRx,
    base: Baseline,
    question: String,
    opts: ReplyOptions,
) {
    let data_dir = state.cfg.data_dir.clone();
    let tmux_name = tmux::session_name(&sess.id);
    let mut closed_rx = sess.closed.subscribe();

    let started = Instant::now();
    let mut last_change = started;
    let mut last_window: Option<String> = None;
    let mut last_publish: Option<Instant> = None;
    let mut published_content = String::new();

    let finish = |status: &str, content: String| {
        let now = unix_now_ms();
        state
            .store
            .update_chat_message(pending.reply_id, &content, status, now)
            .ok();
        if let Ok(Some(row)) = state.store.get_chat_message(pending.reply_id) {
            state.chat.publish(row.into());
        }
        state.chat.finish(&sess.id, &pending);
    };

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        if let Some(interrupt) = *cancel_rx.borrow_and_update() {
            if interrupt {
                sess.pty.write(b"\x03").ok();
            }
            let content = last_window
                .as_deref()
                .map(|w| extract_reply(&base.screen, w, &question))
                .unwrap_or_default();
            finish(STATUS_CANCELLED, content);
            return;
        }
        if *closed_rx.borrow_and_update() {
            finish(STATUS_ERROR, published_content);
            return;
        }

        let metrics = match tmux::pane_metrics(&data_dir, &tmux_name).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("chat: pane metrics failed for {}: {e}", sess.id);
                finish(STATUS_ERROR, published_content);
                return;
            }
        };
        let above = (metrics.history_size - base.metrics.history_size).max(0);
        let window = match tmux::capture_pane_plain(&data_dir, &tmux_name, above).await {
            Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
            Err(e) => {
                tracing::warn!("chat: capture failed for {}: {e}", sess.id);
                finish(STATUS_ERROR, published_content);
                return;
            }
        };

        let now = Instant::now();
        let changed = last_window.as_deref() != Some(window.as_str());
        if changed {
            last_change = now;
        }
        let quiet = now.duration_since(last_change);
        let elapsed = now.duration_since(started);

        let lines: Vec<&str> = window.lines().collect();
        let settled = (quiet >= opts.settle && looks_idle(&lines)) || quiet >= opts.idle;

        if settled || elapsed >= opts.timeout {
            let content = extract_reply(&base.screen, &window, &question);
            finish(if settled { STATUS_DONE } else { STATUS_TIMEOUT }, content);
            return;
        }

        if changed {
            last_window = Some(window.clone());
            let due = last_publish
                .map(|t| now.duration_since(t) >= PUBLISH_INTERVAL)
                .unwrap_or(true);
            if due {
                let content = extract_reply(&base.screen, &window, &question);
                if content != published_content {
                    published_content = content;
                    state
                        .store
                        .update_chat_message(
                            pending.reply_id,
                            &published_content,
                            STATUS_PENDING,
                            unix_now_ms(),
                        )
                        .ok();
                    if let Ok(Some(row)) = state.store.get_chat_message(pending.reply_id) {
                        state.chat.publish(row.into());
                    }
                }
                last_publish = Some(now);
            }
        }
    }
}

// ---- Scrollback sync --------------------------------------------------------

/// Import turns that happened on the console itself (typed in the full
/// terminal UI, or before the chat client was ever opened) so the chat shows
/// the console's real history.
///
/// The scrollback is parsed into question/answer pairs and aligned with what
/// is already stored: everything after the most recent stored question that
/// still appears in the transcript is new. Chat-originated questions are
/// typed into the same console, so they align too and are never duplicated.
/// The final pair is imported only when the console looks idle, and an
/// imported reply is refreshed while its output keeps growing.
///
/// Returns the number of turns (pairs) inserted.
pub async fn sync_scrollback(state: &SharedState, session_id: &str) -> usize {
    if state.manager.get(session_id).await.is_none() || state.chat.pending_for(session_id).is_some()
    {
        return 0;
    }
    if !state.chat.begin_sync(session_id) {
        return 0;
    }
    let result = sync_inner(state, session_id).await;
    state.chat.end_sync(session_id);
    result
}

async fn sync_inner(state: &SharedState, session_id: &str) -> usize {
    let data_dir = state.cfg.data_dir.clone();
    let tmux_name = tmux::session_name(session_id);
    let raw = match tmux::capture_pane_plain(&data_dir, &tmux_name, SYNC_SCROLLBACK_LINES).await {
        Ok(raw) => raw,
        Err(e) => {
            tracing::debug!("chat sync: capture failed for {session_id}: {e}");
            return 0;
        }
    };
    let text = String::from_utf8_lossy(&raw);
    let lines: Vec<&str> = text.lines().collect();
    let idle = looks_idle(&lines);
    let mut turns = crate::transcript::parse(&text);
    if !idle {
        // The last pair is still being answered; pick it up next time.
        turns.pop();
    }
    if turns.is_empty() {
        return 0;
    }

    let stored = state
        .store
        .recent_user_turns(session_id, SYNC_ALIGN_WINDOW)
        .unwrap_or_default();

    // Alignment: new material starts after the stored question that sits
    // furthest along the transcript (backfilled rows have late ids but early
    // timestamps, so "newest id" is not "latest in the console"). Every
    // aligned turn also gets its reply refreshed: the transcript is the
    // canonical rendering of an answer — an imported one may have grown, a
    // chat-captured one may have been misread by the screen-delta.
    let mut start = 0;
    let mut aligned = stored.is_empty();
    for (user_row, reply_row) in &stored {
        let want = norm(&user_row.content);
        let Some(i) = turns.iter().rposition(|t| norm(&t.user) == want) else {
            continue;
        };
        start = start.max(i + 1);
        aligned = true;
        if let Some(reply) = reply_row {
            let fresh = cap_reply(&turns[i].assistant);
            let settled = reply.status == STATUS_DONE || reply.status == STATUS_TIMEOUT;
            if settled
                && !fresh.is_empty()
                && reply.content != fresh
                && state
                    .store
                    .update_chat_message(reply.id, &fresh, STATUS_DONE, unix_now_ms())
                    .unwrap_or(false)
            {
                if let Some(m) = load(state, reply.id) {
                    state.chat.publish(m);
                }
            }
        }
    }

    // Backfill: console turns older than the oldest stored question (a chat
    // that started before this console's history was ever imported). Only
    // when every stored question is in view, so this runs at most once.
    let mut backfilled = 0;
    if aligned && !stored.is_empty() && stored.len() < SYNC_ALIGN_WINDOW {
        let (oldest, _) = stored
            .iter()
            .min_by_key(|(u, _)| (u.created_at, u.id))
            .expect("non-empty");
        let want = norm(&oldest.content);
        if let Some(j) = turns.iter().position(|t| norm(&t.user) == want) {
            let known: std::collections::HashSet<String> =
                stored.iter().map(|(u, _)| norm(&u.content)).collect();
            let older: Vec<&crate::transcript::Turn> = turns[..j]
                .iter()
                .filter(|t| !t.user.trim().is_empty() && !known.contains(&norm(&t.user)))
                .collect();
            // Stamp them before the oldest stored turn, in order.
            let n = older.len() as i64;
            for (k, turn) in older.iter().enumerate() {
                let ts = oldest.created_at - (n - k as i64);
                if insert_pair(state, session_id, turn, ts) {
                    backfilled += 1;
                }
            }
        }
    }

    // A cleared history must not come back: the clear mark is the last
    // question that was visible at clear time; only what follows it counts.
    if !aligned || start == 0 {
        if let Ok(Some(anchor)) = state.store.chat_clear_mark(session_id) {
            let anchor = norm(&anchor);
            if let Some(i) = turns.iter().rposition(|t| norm(&t.user) == anchor) {
                start = start.max(i + 1);
                aligned = true;
            }
        }
    }
    let known: std::collections::HashSet<String> =
        stored.iter().map(|(u, _)| norm(&u.content)).collect();

    let mut inserted = backfilled;
    for (i, turn) in turns.iter().enumerate() {
        if aligned {
            if i < start {
                continue;
            }
        } else if known.contains(&norm(&turn.user)) {
            // Nothing stored is visible any more (scrolled out): import only
            // what we have definitely never seen.
            continue;
        }
        if insert_pair(state, session_id, turn, unix_now_ms()) {
            inserted += 1;
        }
    }
    if inserted > 0 {
        tracing::info!("chat sync: imported {inserted} console turns for session {session_id}");
    }
    inserted
}

/// Store one parsed question/answer pair (source "import") stamped `ts`.
fn insert_pair(
    state: &SharedState,
    session_id: &str,
    turn: &crate::transcript::Turn,
    ts: i64,
) -> bool {
    let user = turn.user.trim();
    if user.is_empty() || user.len() > MAX_TEXT_BYTES {
        return false;
    }
    let Ok(q) = state.store.insert_chat_message_from(
        session_id,
        ROLE_USER,
        user,
        STATUS_DONE,
        None,
        ts,
        SOURCE_IMPORT,
    ) else {
        return false;
    };
    let Ok(a) = state.store.insert_chat_message_from(
        session_id,
        ROLE_ASSISTANT,
        &cap_reply(&turn.assistant),
        STATUS_DONE,
        Some(q),
        ts,
        SOURCE_IMPORT,
    ) else {
        return false;
    };
    for id in [q, a] {
        if let Some(m) = load(state, id) {
            state.chat.publish(m);
        }
    }
    true
}

/// Trim a parsed reply to the stored size cap (kept from the end).
fn cap_reply(text: &str) -> String {
    if text.len() <= MAX_REPLY_BYTES {
        return text.to_string();
    }
    let mut cut = text.len() - MAX_REPLY_BYTES;
    while cut < text.len() && !text.is_char_boundary(cut) {
        cut += 1;
    }
    format!("…{}", &text[cut..])
}

/// Aborts the periodic sync task when the stream it belongs to is dropped.
struct SyncGuard(tokio::task::JoinHandle<()>);

impl Drop for SyncGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// ---- Handlers ---------------------------------------------------------------

fn message_json(msg: &ChatMessage) -> serde_json::Value {
    serde_json::to_value(msg).unwrap_or_else(|_| json!({}))
}

fn load(state: &SharedState, id: i64) -> Option<ChatMessage> {
    state
        .store
        .get_chat_message(id)
        .ok()
        .flatten()
        .map(Into::into)
}

async fn wait_for_reply(pending: &Pending, limit: Duration) {
    let mut rx = pending.done_rx();
    let _ = tokio::time::timeout(limit, rx.wait_for(|d| *d)).await;
}

/// POST /api/sessions/:id/chat
pub async fn chat_send(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    #[derive(Deserialize)]
    struct SendRequest {
        #[serde(default)]
        text: String,
        #[serde(default = "default_true")]
        wait: bool,
        timeout: Option<u64>,
        settle_ms: Option<u64>,
        idle_ms: Option<u64>,
        #[serde(default)]
        send_mode: SendMode,
    }
    fn default_true() -> bool {
        true
    }

    let req = match serde_json::from_slice::<SendRequest>(&body) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid request"),
    };
    // What gets typed keeps any trailing newlines (a REPL block needs its
    // terminating blank line); what gets stored and echo-matched does not.
    let typed_text = req.text.replace("\r\n", "\n");
    let text = typed_text.trim_end_matches('\n').to_string();
    if text.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "text is required");
    }
    if text.len() > MAX_TEXT_BYTES {
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "text too large");
    }
    let settle_ms = req
        .settle_ms
        .unwrap_or(DEFAULT_SETTLE_MS)
        .clamp(MIN_SETTLE_MS, MAX_IDLE_MS);
    let idle_ms = req
        .idle_ms
        .unwrap_or(DEFAULT_IDLE_MS)
        .clamp(settle_ms, MAX_IDLE_MS);
    let opts = ReplyOptions {
        timeout: Duration::from_secs(
            req.timeout
                .unwrap_or(DEFAULT_TIMEOUT_SECS)
                .clamp(1, MAX_TIMEOUT_SECS),
        ),
        settle: Duration::from_millis(settle_ms),
        idle: Duration::from_millis(idle_ms),
    };

    let sess = match state.manager.get(&id).await {
        Some(s) => s,
        None => return json_error(StatusCode::NOT_FOUND, "session not running"),
    };

    if let Some(p) = state.chat.pending_for(&id) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "reply pending", "reply_id": p.reply_id, "request_id": p.request_id})),
        )
            .into_response();
    }

    let data_dir = state.cfg.data_dir.clone();
    let tmux_name = tmux::session_name(&id);
    let base = match snapshot(&data_dir, &tmux_name).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("chat: snapshot failed for session {id}: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    let now = unix_now_ms();
    let request_id =
        match state
            .store
            .insert_chat_message(&id, ROLE_USER, &text, STATUS_DONE, None, now)
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("chat: insert question failed: {e}");
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            }
        };
    let reply_id = match state.store.insert_chat_message(
        &id,
        ROLE_ASSISTANT,
        "",
        STATUS_PENDING,
        Some(request_id),
        now,
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("chat: insert reply failed: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    let (pending, cancel_rx) = match state.chat.begin(&id, request_id, reply_id) {
        Ok(v) => v,
        Err(p) => {
            // Lost a race with a concurrent ask: undo our rows.
            state
                .store
                .update_chat_message(reply_id, "", STATUS_CANCELLED, unix_now_ms())
                .ok();
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "reply pending", "reply_id": p.reply_id, "request_id": p.request_id})),
            )
                .into_response();
        }
    };

    if let Some(q) = load(&state, request_id) {
        state.chat.publish(q);
    }
    if let Some(r) = load(&state, reply_id) {
        state.chat.publish(r);
    }

    let bracketed = sess
        .pty
        .modes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .reassert_sequence()
        .contains("?2004h");
    let typed = match sess
        .pty
        .write(&keystrokes(&typed_text, req.send_mode, bracketed))
    {
        Ok(()) => {
            tokio::time::sleep(ENTER_DELAY).await;
            sess.pty.write(b"\r")
        }
        Err(e) => Err(e),
    };
    if let Err(e) = typed {
        tracing::error!("chat: pty write failed for session {id}: {e}");
        state
            .store
            .update_chat_message(reply_id, "", STATUS_ERROR, unix_now_ms())
            .ok();
        state.chat.finish(&id, &pending);
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    tokio::spawn(run_reply(
        Arc::clone(&state),
        Arc::clone(&sess),
        Arc::clone(&pending),
        cancel_rx,
        base,
        text,
        opts,
    ));

    if req.wait {
        wait_for_reply(&pending, opts.timeout + Duration::from_secs(2)).await;
    }

    let question = load(&state, request_id);
    let reply = load(&state, reply_id);
    let status = if reply
        .as_ref()
        .map(|r| r.status == STATUS_PENDING)
        .unwrap_or(false)
    {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    (
        status,
        Json(json!({
            "question": question.as_ref().map(message_json),
            "reply": reply.as_ref().map(message_json),
        })),
    )
        .into_response()
}

fn parse_i64(params: &HashMap<String, String>, key: &str) -> Option<i64> {
    params.get(key).and_then(|v| v.parse().ok())
}

/// GET /api/sessions/:id/chat?after=&before=&limit=
pub async fn chat_list(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let after = parse_i64(&params, "after");
    let before = parse_i64(&params, "before");
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PAGE)
        .clamp(1, MAX_PAGE);

    // Known session = live, or a store row (detached/dead consoles keep their
    // chat until deleted).
    let known = state.manager.get(&id).await.is_some()
        || state.store.get_session(&id).ok().flatten().is_some();
    if !known {
        return json_error(StatusCode::NOT_FOUND, "session not found");
    }

    // Opening a thread (no cursor) first mirrors whatever happened on the
    // console since the last look.
    if after.is_none() && before.is_none() {
        sync_scrollback(&state, &id).await;
    }

    match state.store.list_chat_messages(&id, after, before, limit) {
        Ok((rows, has_more)) => {
            let messages: Vec<ChatMessage> = rows.into_iter().map(Into::into).collect();
            let pending = state.chat.pending_for(&id).map(|p| p.reply_id);
            (
                StatusCode::OK,
                Json(json!({
                    "session_id": id,
                    "messages": messages,
                    "has_more": has_more,
                    "pending_reply_id": pending,
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("chat: list failed for session {id}: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// GET /api/sessions/:id/chat/:msg_id?wait=secs
pub async fn chat_get(
    State(state): State<SharedState>,
    Path((id, msg_id)): Path<(String, i64)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let wait_secs = params
        .get("wait")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        .min(MAX_TIMEOUT_SECS);

    let Some(msg) = load(&state, msg_id).filter(|m| m.session_id == id) else {
        return json_error(StatusCode::NOT_FOUND, "message not found");
    };

    if wait_secs > 0 && msg.status == STATUS_PENDING {
        if let Some(p) = state.chat.pending_for(&id).filter(|p| p.reply_id == msg_id) {
            wait_for_reply(&p, Duration::from_secs(wait_secs)).await;
        }
    }
    match load(&state, msg_id) {
        Some(m) => (StatusCode::OK, Json(message_json(&m))).into_response(),
        None => json_error(StatusCode::NOT_FOUND, "message not found"),
    }
}

/// POST /api/sessions/:id/chat/:msg_id/cancel  {"interrupt": bool}
pub async fn chat_cancel(
    State(state): State<SharedState>,
    Path((id, msg_id)): Path<(String, i64)>,
    body: Bytes,
) -> Response {
    #[derive(Deserialize, Default)]
    struct CancelRequest {
        #[serde(default)]
        interrupt: bool,
    }
    let req = if body.is_empty() {
        CancelRequest::default()
    } else {
        match serde_json::from_slice::<CancelRequest>(&body) {
            Ok(r) => r,
            Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid request"),
        }
    };

    let Some(p) = state.chat.pending_for(&id).filter(|p| p.reply_id == msg_id) else {
        return match load(&state, msg_id).filter(|m| m.session_id == id) {
            Some(m) => (StatusCode::OK, Json(message_json(&m))).into_response(),
            None => json_error(StatusCode::NOT_FOUND, "message not found"),
        };
    };
    p.cancel.send_replace(Some(req.interrupt));
    wait_for_reply(&p, Duration::from_secs(5)).await;
    match load(&state, msg_id) {
        Some(m) => (StatusCode::OK, Json(message_json(&m))).into_response(),
        None => json_error(StatusCode::NOT_FOUND, "message not found"),
    }
}

/// DELETE /api/sessions/:id/chat
pub async fn chat_clear(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    if let Some(p) = state.chat.pending_for(&id) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "reply pending", "reply_id": p.reply_id, "request_id": p.request_id})),
        )
            .into_response();
    }
    // Record where the console stands so the sync does not re-import what
    // was just cleared.
    if state.manager.get(&id).await.is_some() {
        let tmux_name = tmux::session_name(&id);
        if let Ok(raw) =
            tmux::capture_pane_plain(&state.cfg.data_dir, &tmux_name, SYNC_SCROLLBACK_LINES).await
        {
            let text = String::from_utf8_lossy(&raw);
            if let Some(last) = crate::transcript::parse(&text).last() {
                state.store.set_chat_clear_mark(&id, last.user.trim()).ok();
            }
        }
    }
    match state.store.clear_chat(&id) {
        Ok(n) => (StatusCode::OK, Json(json!({"deleted": n}))).into_response(),
        Err(e) => {
            tracing::error!("chat: clear failed for session {id}: {e}");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// POST /api/sessions/:id/chat/sync
pub async fn chat_sync(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    if state.manager.get(&id).await.is_none() {
        return json_error(StatusCode::NOT_FOUND, "session not running");
    }
    let imported = sync_scrollback(&state, &id).await;
    (StatusCode::OK, Json(json!({"imported": imported}))).into_response()
}

/// GET /api/sessions/:id/chat/stream?after=
///
/// Server-sent events. Every event is a full turn (`event: message`), sent
/// again whenever its content/status changes — clients upsert by `id`. The
/// stream opens with the turns newer than `after` (or the last page when
/// omitted) so a reconnecting client never misses anything; a `resync` event
/// means the client fell behind and should re-fetch via `GET .../chat`.
pub async fn chat_stream(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let known = state.manager.get(&id).await.is_some()
        || state.store.get_session(&id).ok().flatten().is_some();
    if !known {
        return json_error(StatusCode::NOT_FOUND, "session not found");
    }

    // Subscribe before the catch-up read so nothing slips between the two.
    let rx = state.chat.subscribe();
    sync_scrollback(&state, &id).await;
    // Keep mirroring the console while the stream is open, so turns typed in
    // the full terminal UI appear in the chat as they finish.
    let guard = {
        let state = Arc::clone(&state);
        let id = id.clone();
        SyncGuard(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(STREAM_SYNC_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                sync_scrollback(&state, &id).await;
            }
        }))
    };
    let after = parse_i64(&params, "after");
    let initial: Vec<ChatMessage> = state
        .store
        .list_chat_messages(&id, after, None, DEFAULT_PAGE)
        .map(|(rows, _)| rows.into_iter().map(Into::into).collect())
        .unwrap_or_default();

    let catch_up = stream::iter(initial.into_iter().map(to_event));
    let session_id = id.clone();
    let live = stream::unfold((rx, guard), move |(mut rx, guard)| {
        let session_id = session_id.clone();
        async move {
            loop {
                match rx.recv().await {
                    Ok(msg) if msg.session_id == session_id => {
                        return Some((to_event(msg), (rx, guard)))
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        return Some((Ok(Event::default().event("resync").data("{}")), (rx, guard)))
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }
    });
    let events: std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> =
        Box::pin(catch_up.chain(live));

    Sse::new(events)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn to_event(msg: ChatMessage) -> Result<Event, Infallible> {
    Ok(Event::default()
        .event("message")
        .id(msg.id.to_string())
        .data(serde_json::to_string(&msg).unwrap_or_else(|_| "{}".into())))
}

/// GET /api/chat/overview
///
/// Every session with its newest turn, ordered by most recent activity.
pub async fn chat_overview(State(state): State<SharedState>) -> Response {
    let sessions = state.manager.list().await;
    // Mirror each live console so previews reflect the terminal, too.
    for s in sessions.iter().filter(|s| s.status == "running") {
        sync_scrollback(&state, &s.id).await;
    }
    let summaries: HashMap<String, store::ChatSummary> = state
        .store
        .chat_summaries()
        .unwrap_or_default()
        .into_iter()
        .map(|s| (s.session_id.clone(), s))
        .collect();

    let mut items: Vec<(i64, serde_json::Value)> = sessions
        .into_iter()
        .map(|s| {
            let summary = summaries.get(&s.id);
            let live_pending = state.chat.pending_for(&s.id).map(|p| p.reply_id);
            let chat = summary.map(|c| {
                json!({
                    "count": c.count,
                    "pending": c.pending || live_pending.is_some(),
                    "pending_reply_id": live_pending,
                    "last": {
                        "id": c.last.id,
                        "role": c.last.role,
                        "status": c.last.status,
                        "preview": preview(&c.last.content),
                        "source": c.last.source,
                        "created_at": c.last.created_at,
                        "updated_at": c.last.updated_at,
                    }
                })
            });
            let activity_ms = summary
                .map(|c| c.last.updated_at)
                .unwrap_or(0)
                .max(s.last_activity_at * 1000);
            (
                activity_ms,
                json!({
                    "id": s.id,
                    "name": s.name,
                    "status": s.status,
                    "created_at": s.created_at,
                    "last_activity_at": s.last_activity_at,
                    "chat": chat,
                }),
            )
        })
        .collect();
    items.sort_by_key(|item| std::cmp::Reverse(item.0));

    (
        StatusCode::OK,
        Json(json!({
            "server": server_info_json(&state).await,
            "sessions": items.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
            "generated_at": unix_now_ms(),
        })),
    )
        .into_response()
}

async fn server_info_json(state: &SharedState) -> serde_json::Value {
    let sessions = state.manager.list().await;
    let running = sessions.iter().filter(|s| s.status == "running").count();
    json!({
        "name": state.cfg.server_name,
        "version": env!("CARGO_PKG_VERSION"),
        "base_path": state.cfg.base_path,
        "sessions": {"running": running, "total": sessions.len()},
        "capabilities": ["sessions", "chat", "chat-stream", "chat-sync", "exec", "history", "share", "files", "ws"],
        "chat": {
            "default_timeout": DEFAULT_TIMEOUT_SECS,
            "max_timeout": MAX_TIMEOUT_SECS,
            "default_settle_ms": DEFAULT_SETTLE_MS,
            "default_idle_ms": DEFAULT_IDLE_MS,
        },
    })
}

/// GET /api/server/info
pub async fn server_info(State(state): State<SharedState>) -> Response {
    (StatusCode::OK, Json(server_info_json(&state).await)).into_response()
}

// ---- Unit tests -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn prompt_detection() {
        assert!(is_prompt_like("user@host:~/git$ "));
        assert!(is_prompt_like("# "));
        assert!(is_prompt_like("│ >                         │"));
        assert!(is_prompt_like(">"));
        assert!(is_prompt_like("❯ "));
        assert!(!is_prompt_like("total 42"));
        assert!(!is_prompt_like(""));
        assert!(!is_prompt_like("──────────"));
        let long = format!("{}$", "x".repeat(100));
        assert!(!is_prompt_like(&long));
    }

    #[test]
    fn busy_lines() {
        assert!(is_busy_line("✻ Thinking… (esc to interrupt)"));
        assert!(is_busy_line("* Moonwalking… (1m 15s · ↓ 4.2k tokens)"));
        assert!(!is_busy_line("✻ Worked for 3s · done 4:57 PM"));
        assert!(!is_busy_line("⏺ answer… with an ellipsis"));
    }

    #[test]
    fn idle_needs_prompt_and_no_busy_marker() {
        assert!(looks_idle(&["hello", "", "$ "]));
        assert!(!looks_idle(&["hello", "", ""]));
        assert!(!looks_idle(&[
            "✻ Thinking… (esc to interrupt)",
            "╭────╮",
            "│ >  │",
            "╰────╯",
        ]));
        assert!(looks_idle(&[
            "answer",
            "╭────╮",
            "│ >  │",
            "╰────╯",
            "  ? for shortcuts"
        ]));
    }

    #[test]
    fn extract_shell_reply() {
        let before = screen(&["Last login: today", "user@host:~$"]);
        let window = "Last login: today\nuser@host:~$ echo hi\nhi\nuser@host:~$ \n\n\n";
        assert_eq!(extract_reply(&before, window, "echo hi"), "hi");
    }

    #[test]
    fn extract_keeps_multiline_and_strips_prompt_only_at_tail() {
        let before = screen(&["$ "]);
        let window = "$ ls -1\nCargo.toml\nsrc\n$ \n";
        assert_eq!(extract_reply(&before, window, "ls -1"), "Cargo.toml\nsrc");
    }

    #[test]
    fn extract_agent_tui_reply() {
        let before = screen(&[
            "╭──────────────────────────╮",
            "│ >                        │",
            "╰──────────────────────────╯",
            "  ? for shortcuts",
        ]);
        let window = "\
> what is 2+2

⏺ 2 + 2 = 4

╭──────────────────────────╮
│ >                        │
╰──────────────────────────╯
  ? for shortcuts
";
        assert_eq!(extract_reply(&before, window, "what is 2+2"), "⏺ 2 + 2 = 4");
    }

    #[test]
    fn extract_pasted_block_echo_dropped() {
        let before = screen(&["$ "]);
        let window = "$ for i in 1 2; do\n  echo row $i\ndone\nrow 1\nrow 2\n$ \n";
        assert_eq!(
            extract_reply(&before, window, "for i in 1 2; do\n  echo row $i\ndone"),
            "row 1\nrow 2"
        );
    }

    #[test]
    fn extract_repl_block_continuation_prompt_dropped() {
        let before = screen(&[">>> "]);
        let window = ">>> for i in range(2):\n...     print(i)\n... \n0\n1\n>>> \n";
        assert_eq!(
            extract_reply(&before, window, "for i in range(2):\n    print(i)\n"),
            "0\n1"
        );
    }

    #[test]
    fn extract_output_resembling_question_is_kept() {
        let before = screen(&["$ "]);
        let q = "echo this is a deliberately long command line that will surely wrap somewhere";
        let window = format!("$ {q}\n{}\n$ \n", &q[5..]);
        assert_eq!(extract_reply(&before, &window, q), &q[5..]);
    }

    #[test]
    fn extract_agent_reply_anchored_on_echo_despite_redrawn_screen() {
        // The old screen region is redrawn with different wrapping, so a
        // strict prefix match fails; the echoed question anchors instead.
        let before = screen(&["❯ earlier question", "", "⏺ earlier answer", "❯ "]);
        let window = "\
❯ earlier question that got re-joined differently
⏺ earlier answer

❯ what changed since the deploy?

⏺ Two things changed.

  Details here.

✻ Worked for 3s · done 5:01 PM

────────────
❯
────────────
  ? for shortcuts
";
        assert_eq!(
            extract_reply(&before, window, "what changed since the deploy?"),
            "⏺ Two things changed.\n\n  Details here."
        );
    }

    #[test]
    fn extract_anchor_skips_wrapped_question_lines() {
        let q = "please summarise the following long paragraph of text for me in one line";
        let before = screen(&["❯ "]);
        let window = format!("❯ {}\n  {}\n\n⏺ Summary here\n❯ \n", &q[..40], &q[40..]);
        assert_eq!(extract_reply(&before, &window, q), "⏺ Summary here");
    }

    #[test]
    fn extract_empty_when_nothing_new() {
        let before = screen(&["$ "]);
        assert_eq!(extract_reply(&before, "$ \n\n", "true"), "");
    }

    #[test]
    fn extract_wrapped_echo_dropped() {
        let q = "please summarise the following long paragraph of text for me in one line";
        let before = screen(&["> "]);
        let window = format!("> {}\n{}\n\nSummary here\n> \n", &q[..40], &q[40..]);
        assert_eq!(extract_reply(&before, &window, q), "Summary here");
    }

    #[test]
    fn extract_caps_reply_size() {
        let before = screen(&[]);
        let big = "y".repeat(MAX_REPLY_BYTES + 100);
        let out = extract_reply(&before, &format!("$ cmd\n{big}\n$ "), "cmd");
        assert!(out.len() <= MAX_REPLY_BYTES + 4);
        assert!(out.starts_with('…'));
    }

    #[test]
    fn keystrokes_modes() {
        // Auto: single-line is typed even with bracketed paste active …
        assert_eq!(keystrokes("ls", SendMode::Auto, true), b"ls");
        // … multi-line is pasted when the program supports it …
        assert_eq!(
            keystrokes("a\nb", SendMode::Auto, true),
            b"\x1b[200~a\nb\x1b[201~".to_vec()
        );
        // … and typed (LF → Enter) when it does not.
        assert_eq!(keystrokes("ls\npwd", SendMode::Auto, false), b"ls\rpwd");
        assert_eq!(keystrokes("a\nb", SendMode::Type, true), b"a\rb");
        assert_eq!(
            keystrokes("x", SendMode::Paste, true),
            b"\x1b[200~x\x1b[201~".to_vec()
        );
        assert_eq!(keystrokes("x", SendMode::Paste, false), b"x");
    }

    #[test]
    fn preview_truncates_with_ellipsis() {
        assert_eq!(preview("short"), "short");
        let long = "z".repeat(PREVIEW_CHARS + 5);
        let p = preview(&long);
        assert_eq!(p.chars().count(), PREVIEW_CHARS + 1);
        assert!(p.ends_with('…'));
    }

    #[tokio::test]
    async fn hub_single_pending_per_session() {
        let hub = ChatHub::new();
        let (p, _rx) = hub.begin("s1", 1, 2).ok().expect("first begin");
        assert!(hub.begin("s1", 3, 4).is_err());
        assert!(hub.begin("s2", 3, 4).is_ok());
        assert_eq!(hub.pending_for("s1").unwrap().reply_id, 2);
        let mut done = p.done_rx();
        hub.finish("s1", &p);
        assert!(hub.pending_for("s1").is_none());
        assert!(*done.borrow_and_update());
    }
}
