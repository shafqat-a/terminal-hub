# Rust Rewrite M4 — Parity 2 (shares, file transfer, base path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox steps.

**Goal:** Read-only share links (mint/list/revoke + public viewer page + public read-only WS), file upload/download into the session working directory, and base-path mounting — wire-compatible with Go feat/file-transfer.

**Execution environment:** Same as M1–M3 (Annihilator, ~/git/terminal-hub, branch main, ssh -p 22, python3 heredocs, TDD, fmt+clippy --all-targets -D warnings clean per commit, no #[allow], no unsafe, Arc-clone into spawned tasks, real tmux).

---

### Wire contract (normative — extracted from Go)

**POST /api/sessions/{id}/share** (auth): body optional `{"ttlSeconds": N}` (0/absent → default `AI_CONDUCTOR_SHARE_TTL` env, default 24h; capped at 30 days silently). → 201:
`{"id":"<16hex>","sessionId":"<id>","mode":"read","token":"<64hex>","path":"/s/<token>","url":"<PUBLIC_URL>/s/<token>" or "/s/<token>" when PUBLIC_URL unset,"expiresAt":<unix>}`.
id = 8 rand bytes hex; token = 32 rand bytes hex, returned ONCE; DB stores sha256(token) raw 32-byte BLOB. 404 `{"error":"session <id> not found"}` if session unknown (live check ok).

**GET /api/sessions/{id}/shares** (auth) → 200 array of `{"id","sessionId","mode","createdAt","expiresAt","revoked":bool}` ordered created_at DESC. Token never included.

**DELETE /api/shares/{id}** (auth) → 200 `{"success":true}` (UPDATE revoked=1). For unknown-id behavior, READ the Go handler (`api/shares.go` in ~/git/ai-dev-conductor) and MATCH it exactly; document which behavior was matched.

**RedeemShare(hash, now)**: row WHERE token_hash=? AND revoked=0 AND expires_at>now → (session_id, mode, true) else false. No state change.

**GET /s/{token}** (PUBLIC): valid → 200 share.html; invalid → 404 share_invalid.html. No detail leakage.

**GET /ws/share/{token}** (PUBLIC, no auth): invalid token → HTTP 404 before upgrade; valid but session not live → 404; valid → upgrade, capture-pane snapshot output frame, then live stream. READ-ONLY: input/resize/paste-image/binary frames silently dropped (loop continues; pongs processed). No mid-connection expiry enforcement (Go parity). Reuse existing pump with a `read_only: bool` param. Share viewers count as viewers (viewer_attached/detached fire — Go parity, affects idle reaping).

**store schema v3** (transactional migration): `share_links (id TEXT PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE, session_id TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'read', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)` + `CREATE INDEX idx_share_links_session ON share_links(session_id)`. Methods: insert_share, list_shares(session_id) DESC, revoke_share(id), redeem_share(hash, now).

**POST /api/sessions/{id}/upload** (auth): multipart field `file`. Dest = session CWD = readlink(/proc/<pane_pid>/cwd); pane_pid via `tmux display-message -p -t <name> '#{pane_pid}'`. Filename sanitized (Go: base(clean("/"+name)); reject ".", "/", empty/whitespace). Cap `AI_CONDUCTOR_MAX_UPLOAD_BYTES` default 100 MiB → over-limit 413. → 201 `{"name":"<sanitized>","size":<bytes>}`. Errors: 404 `{"error":"session not found"}` (not live); 503 `{"error":"cannot resolve working directory"}`; 400 `{"error":"missing file field"}` / `{"error":"invalid filename"}`; 500 on write failure.

**GET /api/sessions/{id}/download?path=rel** (auth): confinement = join(cwd, rel) + relative-back check (escape → 403 `{"error":"path outside working directory"}`); missing param → 400 `{"error":"path is required"}`; missing file or directory → 404 `{"error":"file not found"}`; success → 200 bytes + `Content-Disposition: attachment; filename="<basename>"` + guessed content-type.

**Base path** (`AI_CONDUCTOR_BASE_PATH`, normalize: trim spaces+slashes → "" or "/prefix"):
- Routing: non-empty → mount the ENTIRE app under the prefix (axum `Router::nest`) + `GET /prefix` → 301 `/prefix/`; requests outside the prefix 404 (Go parity).
- Cookie Path = base_path + "/".
- Middleware: is_api_request strips base_path before checking /api|/ws; unauth redirect to base_path + "/".
- Share mint `path` = base_path + "/s/" + token; `url` = PUBLIC_URL + path (or path alone when PUBLIC_URL empty).
- Frontend: restore placeholders — templates carry literal `__BASE_PATH__` tokens (script global `window.BASE_PATH = "__BASE_PATH__";` + `__BASE_PATH__`-prefixed asset href/src) and app.js/share.js use `(window.BASE_PATH || '')` prefixes at the previously stripped sites (see diff of port commits b42c733 + the U2 share port). assets.rs substitutes `__BASE_PATH__` → cfg.base_path at serve time for templates/*.html and static/js/*.js (cache substituted bytes).

Config additions: `share_ttl: Duration` (AI_CONDUCTOR_SHARE_TTL default 24h), `public_url: String` (default ""), `max_upload_bytes: u64` (AI_CONDUCTOR_MAX_UPLOAD_BYTES default 104857600), `base_path: String` (normalized, default ""). All with tests.

---

## Execution units

### - [x] U1 — Store v3 + share endpoints
Migration v3 (transactional); 4 store methods TDD'd (insert / list DESC / revoke / redeem incl. expiry, revoked, wrong-hash cases). Config: share_ttl + public_url (tests). Handlers mint/list/revoke per contract (rand id/token; sha256 hash; ttl cap 30d; 404 unknown session; match Go's revoke-of-unknown behavior after reading the Go handler). Routes in protected router. Integration tests: mint 201 shape exact (id 16 hex chars, token 64, path, url with AND without PUBLIC_URL via test_app_with); list excludes token + ordered DESC + revoked flag transitions; revoke → redeem fails; expired row (inserted directly with past expires_at) → redeem fails.
Commit: `feat(shares): mint/list/revoke endpoints with hashed share tokens`

### - [x] U2 — Share viewer + public read-only WS
Port share.html, share_invalid.html, share.js from the Go checkout KEEPING base-path plumbing as `__BASE_PATH__` placeholders (where Go had {{.BasePath}}); implement the serve-time substitution helper NOW (base_path="" today → substitutes to empty string; U4 feeds real values). PUBLIC routes (outside auth router): GET /s/:token (redeem → share.html 200 | share_invalid.html 404), GET /ws/share/:token. Refactor ws::pump → `pump(socket, sess, data_dir, read_only: bool)`; share WS: redeem → manager.get live? → upgrade read_only=true; 404s per contract before upgrade.
Tests: share page valid → 200 contains "VIEW ONLY"; invalid → 404 contains "isn't available"; share WS connect with minted token, NO auth → snapshot frame arrives; read-only enforcement: send input frame `{"type":"input","data":"echo SHOULD_NOT_RUN\n"}` + binary frame, wait ~1s, tmux capture-pane does NOT contain "SHOULD_NOT_RUN"; revoked token → handshake 404; share for deleted session → 404.
Commit: `feat(shares): public share viewer page and read-only share WebSocket`

### - [x] U3 — Upload/download
Config max_upload_bytes (+tests). tmux crate: `pane_pid(data_dir, name) -> Result<u32, TmuxError>`. Session cwd(): pane_pid → read_link(/proc/<pid>/cwd). axum "multipart" feature; DefaultBodyLimit on the upload route; over-limit → 413 (verify axum behavior and map to wire shape). Pure fns `sanitize_filename(&str) -> Option<String>` and `confine_path(base: &Path, rel: &str) -> Option<PathBuf>` with unit tests (.., absolute, empty, whitespace, "./x", separators). Download with Content-Disposition + mime_guess; directory → 404. Routes protected.
Integration tests (real tmux): upload small file → 201 {name,size} AND file exists at the session's actual cwd (resolve via the same pane_pid readlink in the test); download round-trip bytes equal; download path=../../etc/passwd → 403; download missing → 404; upload filename "../evil" → stored as "evil"; oversize (max set to 1024 via test_app_with) → 413. Cleanup uploaded files + sessions.
Commit: `feat(files): upload/download into session working directory`

### - [x] U4 — Base path
Config base_path normalization (+tests: "  /app/ " → "/app", "" → "", "a/b" → "/a/b"). build_app: non-empty → outer Router::nest + bare-prefix 301; root requests 404. Cookie Path = base_path+"/". Middleware strip-prefix for is_api_request + redirect target. Share mint path/url prefixed. assets.rs `__BASE_PATH__` substitution wired to cfg (cache per file). Frontend: restore `(window.BASE_PATH || '')` prefixes in app.js (the 5 sites stripped in b42c733 — read that commit's diff) and share.js; add `window.BASE_PATH = "__BASE_PATH__";` global + placeholder-prefixed hrefs to terminal.html, login.html (share pages already carry placeholders from U2). CRITICAL: with base_path="" behavior must be byte-identical to today — run the FULL existing suite immediately after the frontend edits, before new tests.
Tests (test_app_with base_path "/app" + a spawn_server variant): /app/api/health 200, /api/health 404; login under /app → cookie Path=/app/; /app/terminal HTML contains `window.BASE_PATH = "/app"` and zero literal `__BASE_PATH__`; unauth /app/terminal → 303 Location /app/; GET /app → 301 /app/; WS /app/ws/<id>?token= round-trip works; share mint path starts /app/s/.
Commit: `feat(server): base-path mounting with serve-time asset substitution`

### - [x] U5 — Gate + smoke + push
1. Full gate; paste summaries.
2. Content-verified smoke (fresh `cargo build` in the same SSH session; kill by exact PID, never pkill -f):
   - Share lifecycle: mint via API key → curl /s/<token> 200 contains VIEW ONLY → garbage token 404 → revoke → same token now 404.
   - Upload/download round-trip with sha256sum comparison.
   - Base-path instance (AI_CONDUCTOR_BASE_PATH=/conductor, second port): login + create + /conductor/terminal all work; same endpoints at root 404.
3. Leave a fresh server running for the controller's browser pass: 0.0.0.0:8125, password m4browser, fresh data dir, base_path EMPTY; create one session and mint one share; REPORT the share URL and session id; do NOT kill this server.
4. Tick M4 checkboxes; commit `docs: M4 complete — checkboxes`; push; poll CI to success.

## Exit criteria
Tests green (~140+), clippy/fmt clean, CI green, smoke proves share mint→view→revoke lifecycle + upload/download checksum round-trip + base-path instance, share viewer browser-verified by controller afterwards.
