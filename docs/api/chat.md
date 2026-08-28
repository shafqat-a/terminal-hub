# Chat API — question/reply over a terminal session

Contract for clients (the mobile app) that want a turn-based chat with a
console rather than a live terminal. One server = one terminal-hub instance;
the app can hold several `{base_url, name, token}` entries and treat each
session on each server as a chat thread.

Every question is typed into the session's PTY exactly as a person would; the
reply is whatever the program in that console prints afterwards (a shell,
Claude Code, a Python REPL — anything). Turns are persisted in the hub's
SQLite DB, so old chats are re-read from the DB and never touch the terminal.

Implementation: `crates/server/src/chat.rs`. All timestamps below are unix
**milliseconds**.

## Authentication

1. `POST /api/login` `{"password": "…"}` → `{"token": "…"}` (64 hex chars).
2. Send it as `X-Session-Token: <token>` on every call. For `EventSource`
   (which cannot set headers) use `?token=<token>` instead.
3. Tokens expire after `AI_CONDUCTOR_SESSION_TIMEOUT` (default 24 h). A `401`
   with `{"error":"unauthorized"}` means: log in again.
4. If the hub is mounted under `AI_CONDUCTOR_BASE_PATH`, prefix every path
   (`/terminal/api/...`). `GET /api/server/info` reports `base_path`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/server/info` | Identify the server (name, version, capabilities, chat limits) |
| GET | `/api/chat/overview` | All sessions + newest turn each — the app's home screen in one call |
| GET | `/api/sessions` / `POST` / `PUT :id` / `DELETE :id` | Existing session CRUD |
| POST | `/api/sessions/:id/chat` | Ask a question (optionally wait for the reply) |
| GET | `/api/sessions/:id/chat` | Turn history, cursor-paginated |
| GET | `/api/sessions/:id/chat/stream` | SSE live feed of turn upserts |
| GET | `/api/sessions/:id/chat/:msg_id` | One turn; `?wait=` long-polls while pending |
| POST | `/api/sessions/:id/chat/:msg_id/cancel` | Stop waiting; optionally send Ctrl-C |
| DELETE | `/api/sessions/:id/chat` | Wipe the session's chat history |
| POST | `/api/sessions/:id/chat/sync` | Import the console's scrollback as turns now (also happens automatically) |

### Turn object

```json
{
  "id": 42,
  "session_id": "d29e0c27",
  "role": "assistant",            // "user" | "assistant"
  "content": "Linux 7.0.0-29-generic\nhello from Annihilator",
  "status": "done",               // see below
  "created_at": 1787908399954,
  "updated_at": 1787908401210,
  "request_id": 41,               // assistant turns only: the user turn answered
  "source": "chat"                // "chat" (asked via this API) | "import" (parsed from the console)
}
```

`status` values: `pending` (reply still being captured — `content` holds the
partial text so far), `done`, `timeout` (hard timeout hit; partial content
kept), `cancelled`, `interrupted` (server restarted mid-reply), `error`
(console died or tmux failed). User turns are always `done`.

### `GET /api/server/info`

```json
{
  "name": "Annihilator", "version": "0.1.0", "base_path": "",
  "sessions": {"running": 3, "total": 4},
  "capabilities": ["sessions","chat","chat-stream","exec","history","share","files","ws"],
  "chat": {"default_timeout": 120, "max_timeout": 900,
           "default_settle_ms": 1000, "default_idle_ms": 5000}
}
```

`name` comes from `AI_CONDUCTOR_SERVER_NAME` (default: hostname). Check
`capabilities` contains `"chat"` when adding a server.

### `GET /api/chat/overview`

One round-trip for the session list screen. Sessions are ordered by most
recent activity (chat or terminal), newest first. `chat` is `null` for a
session that has never been chatted with.

```json
{
  "server": { …same as /api/server/info… },
  "generated_at": 1787908500000,
  "sessions": [
    {
      "id": "d29e0c27", "name": "mobile-test", "status": "running",
      "created_at": "2026-08-28 09:13:19", "last_activity_at": 1787908480,
      "chat": {
        "count": 12, "pending": false, "pending_reply_id": null,
        "last": {"id": 12, "role": "assistant", "status": "done",
                 "preview": "back in shell", "created_at": …, "updated_at": …}
      }
    }
  ]
}
```

`status` is `running` (askable), `detached` or `dead` (history readable,
asking returns 404). `last_activity_at` is in **seconds** (legacy field);
`preview` is the first 200 characters of the turn.

### `POST /api/sessions/:id/chat`

```json
{
  "text": "what does this error mean?",
  "wait": true,          // default true: long-poll until the reply settles
  "timeout": 120,        // seconds, 1..900 (default 120). Agents can take minutes.
  "settle_ms": 1000,     // quiet time before "done" once a prompt is visible (200..60000)
  "idle_ms": 5000,       // quiet time before "done" when no prompt is recognised
  "send_mode": "auto"    // "auto" | "type" | "paste"
}
```

Responses:

* `200` — `wait:true` and the reply settled (or timed out) within `timeout`:
  `{"question": <turn>, "reply": <turn>}`.
* `202` — `wait:false`, or the wait window elapsed while still pending:
  same body, `reply.status == "pending"`. Follow up with the stream or
  `GET …/chat/:reply_id?wait=30`.
* `409` — this console already has a reply pending:
  `{"error":"reply pending","reply_id":…,"request_id":…}`. One question at a
  time per console; cancel or wait.
* `404` — session not running. `400` — empty text / bad JSON. `413` — text
  over 64 KiB.

**How the reply is detected.** The pane is polled every 150 ms. The reply is
"done" when the screen has stopped changing for `settle_ms` *and* a prompt
line is visible (`$`, `#`, `>`, `❯`, … at the end of a short line) with no
busy marker (`esc to interrupt`), or when it has been quiet for `idle_ms`
regardless. Agent TUIs animate a spinner/timer while working, so they never
look quiet until they finish. A silent long-running shell command shows no
prompt, so it gets the longer `idle_ms` grace. Tune per request: chat with
Claude Code works well with the defaults; a plain shell can use
`settle_ms: 300` for snappier turns.

**How the text is sent.** `auto` types single-line text and, when the
program has enabled bracketed paste (Claude Code, bash 5, Python REPL),
pastes multi-line text as one block so it is not submitted line by line.
Enter is sent 40 ms after the text. Trailing newlines in `text` are typed as
extra Enters (a Python block needs its blank terminating line) but are not
stored. `type` forces character typing (LF = Enter); `paste` forces a
bracketed paste. Interactive prompts inside a console ("Do you want to
proceed? 1. Yes") simply come back as the reply; answer them with the next
question (`"1"`).

**What the reply contains.** Plain text (no ANSI), wrapped lines re-joined,
minus the old screen, the echoed question, and trailing prompt/box/help
chrome. Capped at 200 KiB (kept from the end). While `pending`, `content` is
refreshed at most every 400 ms.

### `GET /api/sessions/:id/chat`

Query: `after=<id>` (turns newer than id, ascending — catch-up),
`before=<id>` (turns older than id — scroll back), neither (newest page),
`limit` (1..500, default 50).

```json
{"session_id": "d29e0c27", "messages": [ <turn>, … ], "has_more": true,
 "pending_reply_id": null}
```

`messages` is always ascending by `id`. `has_more` refers to the direction
walked. Works for detached/dead sessions too (history only).

Recommended app flow for opening a thread: `GET …/chat?limit=50` → render →
open the stream with `after=<last id seen>`. For scrolling up:
`GET …/chat?before=<oldest id>&limit=50`.

### `GET /api/sessions/:id/chat/stream?after=<id>`

`text/event-stream`. Every event is a full turn, re-sent whenever its
content or status changes — upsert by `id` on the client:

```
event: message
id: 43
data: {"id":43,"session_id":"d29e0c27","role":"assistant","status":"pending","content":"partial…",…}
```

The stream opens by replaying the turns newer than `after` (or the newest
page when omitted), so reconnecting with the last id seen never loses a
turn. A keep-alive comment arrives every 15 s. `event: resync` (`data: {}`)
means the client fell behind; re-fetch with `GET …/chat?after=`. Use
`?token=` for auth.

### `GET /api/sessions/:id/chat/:msg_id?wait=<secs>`

Returns the turn. With `wait` (≤ 900) and a `pending` reply, the response
is held until the reply settles or the wait elapses — a polling alternative
to SSE for clients without EventSource. `404` if the id is not in this
session.

### `POST /api/sessions/:id/chat/:msg_id/cancel`

Body optional: `{"interrupt": true}` also sends Ctrl-C to the console.
Returns the turn with status `cancelled` (content = whatever was captured).
Calling it on a settled turn just returns the turn.

### Console history is imported automatically

A console that was driven from the full terminal UI (or from before the
chat client existed) is not empty in the chat: the hub parses the pane's
scrollback (up to 5000 lines) into question/answer pairs and stores them as
turns with `source: "import"`. Recognised prompts: shells
(`user@host:~/dir$ cmd`, `$`, `#`, `❯`), Claude Code (`❯ question` /
`> question` with indented continuation lines; `⏺` answers; spinner, timing
and box chrome stripped), REPLs (`>>>` / `...`).

When it runs: on `GET …/chat` without a cursor, when a stream opens and every
3 s while it stays open, on `/api/chat/overview` for running sessions, and
on `POST …/chat/sync` (`{"imported": n}`). Parsed turns are aligned with the
stored ones — the newest stored question that is still visible marks where
new material starts — so nothing is duplicated, including questions asked
through this API (they are typed into the same console). The last pair is
only imported once the console looks idle; an imported reply is refreshed
while its output keeps growing. Clearing the history records a watermark so
the cleared turns do not come back. Imported turns carry the import time,
not the time they happened.

### `DELETE /api/sessions/:id/chat`

`{"deleted": <count>}`. `409` while a reply is pending. Deleting the session
itself also drops its chat.

## Built-in web client: `/remote`

The hub ships a mobile-first web client at `GET /remote` (public HTML shell;
every API call it makes is authenticated as usual) — `web/templates/remote.html`,
`web/static/js/remote.js`, `web/static/css/remote.css`. It is the reference
implementation of this contract and the interim "app" until the Android
client exists:

* Home pane: every configured server with its sessions from `/api/chat/overview`
  (status dot, last-turn preview, count / typing indicator), `+ Session`,
  add/remove servers, sign-in sheet on 401.
* Chat pane: turns from `/chat` (+ "Load earlier"), live updates from
  `/chat/stream` with backoff reconnect and long-poll fallback, `Stop`
  (cancel + Ctrl-C) while pending, "Fast mode" toggle (`settle_ms: 300`),
  clear history. Hash routes (`#/s/<server>/<session>`) so the Android back
  button works; drafts persist per thread.
* Servers are the same `ai_conductor_servers` localStorage list the terminal
  UI uses: the local server rides the session cookie, others store a token.
* Installable: `static/remote.webmanifest` (standalone display, icon), so
  "Add to Home Screen" gives an app-like window on Android/iOS.

## Multi-server model for the app

* Store per server: `base_url`, `name` (from `/api/server/info`), `token`.
* Home screen: call `/api/chat/overview` on each server in parallel; merge.
* Thread screen: `/chat` page + `/chat/stream`; POST with `wait:false` and
  let the stream deliver partial content, or `wait:true` for the simplest
  request/response UI (keep the HTTP client timeout above `timeout` + 5 s).
* Same console from multiple devices is fine: turns are server-side; the
  second device gets `409` while the first's question is pending.

## Curl walkthrough

```sh
H=http://192.168.0.66:5050
TOK=$(curl -s -X POST $H/api/login -H 'Content-Type: application/json' \
      -d '{"password":"…"}' | jq -r .token)
curl -s $H/api/chat/overview -H "X-Session-Token: $TOK" | jq
SID=$(curl -s -X POST $H/api/sessions -H "X-Session-Token: $TOK" \
      -H 'Content-Type: application/json' -d '{"name":"phone"}' | jq -r .id)
curl -s -X POST $H/api/sessions/$SID/chat -H "X-Session-Token: $TOK" \
     -H 'Content-Type: application/json' -d '{"text":"uname -a"}' | jq .reply.content
curl -sN "$H/api/sessions/$SID/chat/stream?token=$TOK&after=0"
```
