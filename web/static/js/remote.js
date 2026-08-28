/* Remote — mobile-first chat client over the terminal-hub chat API.
 *
 * One page, two panes (home: servers + sessions; chat: one session's turns),
 * hash-routed so the browser/Android back button works:
 *   #/                      home
 *   #/s/<serverId>/<sid>    chat thread
 *
 * Servers are shared with the terminal UI via localStorage
 * ('ai_conductor_servers'): the local server authenticates with the session
 * cookie, remote servers with a stored X-Session-Token.
 *
 * Live updates come from the SSE stream (/chat/stream); when it is not
 * available the pending reply is long-polled instead. See docs/api/chat.md.
 */
(function () {
    'use strict';

    const BASE = window.BASE_PATH || '';
    const SERVERS_KEY = 'ai_conductor_servers';
    const PAGE = 50;
    const AGENT_TIMEOUT = 600;   // seconds we let a reply run (agents think for minutes)
    const FAST_SETTLE_MS = 300;  // "fast mode": plain shells settle quickly

    // ---- tiny helpers -------------------------------------------------------

    const $ = (id) => document.getElementById(id);
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const el = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // Turns are shown in time order; imported console history can carry
    // timestamps older than rows with smaller ids (backfill).
    const byTime = (a, b) => (a.created_at - b.created_at) || (a.id - b.id);

    function timeAgo(ms) {
        if (!ms) return '';
        const d = Date.now() - ms;
        if (d < 60e3) return 'now';
        if (d < 3600e3) return Math.floor(d / 60e3) + 'm';
        if (d < 86400e3) return Math.floor(d / 3600e3) + 'h';
        if (d < 7 * 86400e3) return Math.floor(d / 86400e3) + 'd';
        return new Date(ms).toLocaleDateString();
    }
    function clock(ms) {
        const d = new Date(ms);
        const sameDay = new Date().toDateString() === d.toDateString();
        const t = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return sameDay ? t : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + t;
    }

    let toastTimer = null;
    function toast(text, bad) {
        const t = $('toast');
        t.textContent = text;
        t.className = 'toast' + (bad ? ' bad' : '');
        t.hidden = false;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => { t.hidden = true; }, 3200);
    }

    // ---- servers ------------------------------------------------------------

    const LOCAL = { id: 'local', name: 'This server', url: '', token: null, isLocal: true, connected: true };

    function loadServers() {
        try {
            const stored = JSON.parse(localStorage.getItem(SERVERS_KEY) || 'null');
            if (Array.isArray(stored) && stored.length) {
                if (!stored.find((s) => s.isLocal)) stored.unshift({ ...LOCAL });
                return stored;
            }
        } catch { /* corrupt storage: start fresh */ }
        return [{ ...LOCAL }];
    }
    function saveServers(servers) {
        localStorage.setItem(SERVERS_KEY, JSON.stringify(servers));
    }
    function baseUrl(server) {
        if (server.isLocal || !server.url) return window.location.origin + BASE;
        return server.url.replace(/\/$/, '');
    }
    function serverLabel(server) {
        if (server.isLocal) return server.name || 'This server';
        return server.name || server.url;
    }

    class AuthError extends Error { constructor(server) { super('unauthorized'); this.server = server; } }

    async function api(server, path, options = {}) {
        const headers = { ...(options.headers || {}) };
        let credentials = 'same-origin';
        if (!server.isLocal) {
            credentials = 'omit';
            if (server.token) headers['X-Session-Token'] = server.token;
        }
        const res = await fetch(baseUrl(server) + path, { ...options, headers, credentials });
        if (res.status === 401) throw new AuthError(server);
        return res;
    }
    async function apiJson(server, path, options) {
        const res = await api(server, path, options);
        let data = null;
        try { data = await res.json(); } catch { /* no body */ }
        if (!res.ok) {
            const err = new Error((data && data.error) || ('HTTP ' + res.status));
            err.status = res.status;
            err.data = data;
            throw err;
        }
        return data;
    }

    // ---- sheet (login / add server) -----------------------------------------

    function openSheet({ title, sub, needName, submitLabel, onSubmit, prefill }) {
        return new Promise((resolve) => {
            const sheet = $('sheet');
            const form = $('sheet-form');
            const err = $('sheet-error');
            $('sheet-title').textContent = title;
            $('sheet-sub').textContent = sub || '';
            $('sheet-name-row').hidden = !needName;
            $('sheet-url-row').hidden = !needName;
            $('sheet-name').value = (prefill && prefill.name) || '';
            $('sheet-url').value = (prefill && prefill.url) || '';
            $('sheet-password').value = '';
            $('sheet-submit').textContent = submitLabel || 'Sign in';
            err.hidden = true;
            sheet.hidden = false;
            setTimeout(() => (needName ? $('sheet-name') : $('sheet-password')).focus(), 50);

            const close = (value) => {
                sheet.hidden = true;
                form.onsubmit = null;
                $('sheet-cancel').onclick = null;
                resolve(value);
            };
            $('sheet-cancel').onclick = () => close(null);
            form.onsubmit = async (e) => {
                e.preventDefault();
                const btn = $('sheet-submit');
                btn.disabled = true;
                err.hidden = true;
                try {
                    const value = await onSubmit({
                        name: $('sheet-name').value.trim(),
                        url: $('sheet-url').value.trim().replace(/\/$/, ''),
                        password: $('sheet-password').value,
                    });
                    close(value);
                } catch (ex) {
                    err.textContent = ex.message || 'Failed';
                    err.hidden = false;
                } finally {
                    btn.disabled = false;
                }
            };
        });
    }

    async function login(server, password) {
        const res = await fetch(baseUrl(server) + '/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password }),
            credentials: server.isLocal ? 'same-origin' : 'omit',
        });
        if (res.status === 429) throw new Error('Too many attempts — wait a minute');
        if (!res.ok) throw new Error('Wrong password');
        const data = await res.json();
        return data.token;
    }

    // ---- app ----------------------------------------------------------------

    class RemoteApp {
        constructor() {
            this.servers = loadServers();
            this.overview = new Map();   // serverId -> {info, sessions, error, auth}
            this.thread = null;          // current chat thread state
            this.authPrompting = new Set();
            this.bind();
            window.addEventListener('hashchange', () => this.route());
            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'visible') this.onVisible();
            });
            window.addEventListener('online', () => this.onVisible());
            this.route();
            this.refreshAll();
        }

        bind() {
            $('btn-refresh').onclick = () => this.refreshAll(true);
            $('btn-add-server').onclick = () => this.addServer();
            $('btn-back').onclick = () => this.goHome();
            $('composer').onsubmit = (e) => { e.preventDefault(); this.send(); };
            $('btn-stop').onclick = () => this.stop();
            $('btn-chat-menu').onclick = (e) => { e.stopPropagation(); this.toggleMenu(); };
            document.addEventListener('click', () => this.toggleMenu(false));
            $('chat-menu').onclick = (e) => {
                const action = e.target && e.target.dataset && e.target.dataset.action;
                if (action) this.menuAction(action);
            };

            const input = $('input');
            const coarse = window.matchMedia('(pointer: coarse)').matches;
            input.addEventListener('keydown', (e) => {
                // Desktop: Enter sends, Shift+Enter newline. Touch: Enter is a
                // newline (the send button is right there); Ctrl/Cmd+Enter sends.
                if (e.key === 'Enter' && !e.isComposing) {
                    if ((!coarse && !e.shiftKey) || e.ctrlKey || e.metaKey) {
                        e.preventDefault();
                        this.send();
                    }
                }
            });
            input.addEventListener('input', () => {
                this.autosize();
                if (this.thread) localStorage.setItem(this.draftKey(), input.value);
            });
        }

        autosize() {
            const input = $('input');
            input.style.height = 'auto';
            input.style.height = Math.min(input.scrollHeight, window.innerHeight * 0.4) + 'px';
        }

        // ---- routing ----

        route() {
            const m = /^#\/s\/([^/]+)\/([^/]+)$/.exec(location.hash || '');
            if (m) {
                this.openThread(decodeURIComponent(m[1]), decodeURIComponent(m[2]));
            } else {
                this.closeThread();
                $('app').dataset.view = 'home';
            }
        }
        goHome() {
            if (location.hash && location.hash !== '#/') history.back();
            else this.route();
        }

        onVisible() {
            this.refreshAll();
            if (this.thread) {
                this.thread.stream && this.thread.stream.close();
                this.thread.stream = null;
                this.loadThread(this.thread, true).then(() => this.connectStream(this.thread));
            }
        }

        // ---- home ----

        async refreshAll(manual) {
            const btn = $('btn-refresh');
            btn.disabled = true;
            await Promise.all(this.servers.map((s) => this.refreshServer(s)));
            btn.disabled = false;
            this.renderHome();
            if (manual) toast('Refreshed');
        }

        async refreshServer(server) {
            const entry = this.overview.get(server.id) || {};
            try {
                const data = await apiJson(server, '/api/chat/overview');
                this.overview.set(server.id, { info: data.server, sessions: data.sessions, error: null, auth: false });
                if (!server.isLocal && server.name !== data.server.name && !server.renamed) {
                    // Adopt the server's own name unless the user picked one.
                    server.name = data.server.name;
                    saveServers(this.servers);
                }
            } catch (e) {
                if (e instanceof AuthError) {
                    this.overview.set(server.id, { ...entry, error: null, auth: true });
                    this.requireAuth(server);
                } else {
                    this.overview.set(server.id, { ...entry, error: e.message || 'unreachable', auth: false });
                }
            }
            this.renderHome();
        }

        async requireAuth(server) {
            if (this.authPrompting.has(server.id)) return false;
            this.authPrompting.add(server.id);
            try {
                const ok = await openSheet({
                    title: server.isLocal ? 'Sign in' : 'Sign in to ' + serverLabel(server),
                    sub: server.isLocal ? window.location.host : server.url,
                    onSubmit: async ({ password }) => {
                        const token = await login(server, password);
                        if (!server.isLocal) { server.token = token; saveServers(this.servers); }
                        return true;
                    },
                });
                if (ok) {
                    await this.refreshServer(server);
                    if (this.thread && this.thread.server.id === server.id) {
                        await this.loadThread(this.thread, true);
                        this.connectStream(this.thread);
                    }
                }
                return !!ok;
            } finally {
                this.authPrompting.delete(server.id);
            }
        }

        async addServer() {
            const server = await openSheet({
                title: 'Add server',
                sub: 'Another terminal-hub instance reachable from this device.',
                needName: true,
                submitLabel: 'Add',
                onSubmit: async ({ name, url, password }) => {
                    if (!/^https?:\/\//.test(url)) throw new Error('URL must start with http:// or https://');
                    const s = { id: Math.random().toString(36).slice(2, 10), name, url, token: null, isLocal: false, connected: true, renamed: !!name };
                    s.token = await login(s, password);
                    return s;
                },
            });
            if (!server) return;
            this.servers.push(server);
            saveServers(this.servers);
            await this.refreshServer(server);
            toast('Added ' + serverLabel(server));
        }

        removeServer(server) {
            if (server.isLocal) return;
            if (!confirm('Remove ' + serverLabel(server) + ' from this device?')) return;
            this.servers = this.servers.filter((s) => s.id !== server.id);
            saveServers(this.servers);
            this.overview.delete(server.id);
            if (this.thread && this.thread.server.id === server.id) { location.hash = '#/'; }
            this.renderHome();
        }

        async newSession(server) {
            const name = prompt('Session name (optional):', '');
            if (name === null) return;
            try {
                const data = await apiJson(server, '/api/sessions', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(name ? { name } : {}),
                });
                await this.refreshServer(server);
                location.hash = '#/s/' + encodeURIComponent(server.id) + '/' + encodeURIComponent(data.id);
            } catch (e) {
                if (e instanceof AuthError) this.requireAuth(server);
                else toast('Could not create session: ' + e.message, true);
            }
        }

        renderHome() {
            const list = $('home-list');
            list.innerHTML = '';
            for (const server of this.servers) {
                const ov = this.overview.get(server.id) || {};
                const status = ov.auth ? 'auth' : ov.error ? 'offline' : 'running';
                const card = el(`<div class="server" data-server="${esc(server.id)}">
                    <div class="server-head">
                        <span class="dot ${status}" title="${esc(ov.error || (ov.auth ? 'sign in required' : 'online'))}"></span>
                        <div class="server-meta">
                            <div class="server-name">${esc(serverLabel(server))}</div>
                            <div class="server-url">${esc(server.isLocal ? window.location.host : server.url)}${ov.info ? ' · v' + esc(ov.info.version) : ''}</div>
                        </div>
                        <button class="chip-btn primary" data-act="new">+ Session</button>
                        <button class="icon-btn" data-act="more" aria-label="Server options">&#x22ee;</button>
                    </div>
                </div>`);
                card.querySelector('[data-act="new"]').onclick = () => this.newSession(server);
                card.querySelector('[data-act="more"]').onclick = () => this.serverMenu(server);

                if (ov.auth) {
                    const b = el(`<div class="server-error">Signed out. <a href="#">Sign in</a></div>`);
                    b.querySelector('a').onclick = (e) => { e.preventDefault(); this.requireAuth(server); };
                    card.appendChild(b);
                } else if (ov.error) {
                    card.appendChild(el(`<div class="server-error">Unreachable: ${esc(ov.error)}</div>`));
                } else if (!ov.sessions) {
                    card.appendChild(el(`<div class="empty">Loading…</div>`));
                } else if (!ov.sessions.length) {
                    card.appendChild(el(`<div class="empty">No sessions yet. Tap <b>+ Session</b> to open a console.</div>`));
                } else {
                    for (const s of ov.sessions) card.appendChild(this.sessionRow(server, s));
                }
                list.appendChild(card);
            }
        }

        sessionRow(server, s) {
            const chat = s.chat;
            let preview = '<span class="who">No messages yet</span>';
            if (chat && chat.last) {
                const who = chat.last.role === 'user' ? 'You: ' : '';
                const text = chat.last.preview || (chat.last.role === 'assistant' ? '(no output)' : '');
                preview = `<span class="who">${esc(who)}</span>${esc(text.replace(/\s+/g, ' '))}`;
            }
            const when = chat && chat.last ? chat.last.updated_at : (s.last_activity_at || 0) * 1000;
            const active = this.thread && this.thread.server.id === server.id && this.thread.sessionId === s.id;
            const row = el(`<button class="session${active ? ' active' : ''}" data-session="${esc(s.id)}">
                <span class="dot ${esc(s.status)}" title="${esc(s.status)}"></span>
                <span class="session-main">
                    <div class="session-name">${esc(s.name)}</div>
                    <div class="session-preview">${preview}</div>
                </span>
                <span class="session-side">
                    <span>${esc(timeAgo(when))}</span>
                    ${chat && chat.pending ? '<span class="typing"><i></i><i></i><i></i></span>' : (chat ? '<span>' + chat.count + '</span>' : '')}
                </span>
            </button>`);
            row.onclick = () => { location.hash = '#/s/' + encodeURIComponent(server.id) + '/' + encodeURIComponent(s.id); };
            return row;
        }

        serverMenu(server) {
            const choices = server.isLocal
                ? ['Sign in again', 'Refresh']
                : ['Sign in again', 'Refresh', 'Remove server'];
            const pick = prompt(choices.map((c, i) => (i + 1) + '. ' + c).join('\n'), '');
            const idx = parseInt(pick, 10) - 1;
            if (choices[idx] === 'Sign in again') this.requireAuth(server);
            else if (choices[idx] === 'Refresh') this.refreshServer(server);
            else if (choices[idx] === 'Remove server') this.removeServer(server);
        }

        // ---- thread ----

        draftKey() { return 'remote_draft_' + this.thread.server.id + '_' + this.thread.sessionId; }
        fastKey() { return 'remote_fast_' + this.thread.server.id + '_' + this.thread.sessionId; }

        async openThread(serverId, sessionId) {
            const server = this.servers.find((s) => s.id === serverId);
            if (!server) { location.hash = '#/'; return; }
            if (this.thread && this.thread.server.id === serverId && this.thread.sessionId === sessionId) {
                $('app').dataset.view = 'chat';
                return;
            }
            this.closeThread();
            const thread = {
                server, sessionId,
                messages: new Map(),
                lastId: 0, oldestId: 0, hasMore: false,
                pendingId: null, stream: null, streamBackoff: 1000, pollAbort: null,
                fast: localStorage.getItem('remote_fast_' + serverId + '_' + sessionId) === '1',
            };
            this.thread = thread;
            $('app').dataset.view = 'chat';
            $('messages').innerHTML = '';
            $('input').value = localStorage.getItem(this.draftKey()) || '';
            this.autosize();
            this.setLive('connecting', 'warn');
            this.renderHeader();
            this.renderHome();
            await this.loadThread(thread);
            if (this.thread === thread) this.connectStream(thread);
        }

        closeThread() {
            if (!this.thread) return;
            const t = this.thread;
            t.stream && t.stream.close();
            t.pollAbort && t.pollAbort.abort();
            this.thread = null;
            $('input').value = '';
            $('messages').innerHTML = '';
            $('messages').appendChild(el('<div class="placeholder" id="chat-placeholder">Pick a session to start chatting.</div>'));
            this.renderHome();
        }

        sessionInfo(thread) {
            const ov = this.overview.get(thread.server.id);
            return ov && ov.sessions ? ov.sessions.find((s) => s.id === thread.sessionId) : null;
        }

        renderHeader() {
            const t = this.thread;
            if (!t) return;
            const s = this.sessionInfo(t);
            $('chat-title').textContent = s ? s.name : t.sessionId;
            $('chat-server').textContent = serverLabel(t.server) + (s && s.status !== 'running' ? ' · ' + s.status : '') + (t.fast ? ' · fast' : '');
            $('chat-menu').querySelector('[data-action="fast"]').dataset.on = t.fast ? 'true' : 'false';
        }

        setLive(text, cls) {
            const p = $('chat-live');
            p.textContent = text;
            p.className = 'pill' + (cls ? ' ' + cls : '');
        }

        async loadThread(thread, quiet) {
            try {
                const data = await apiJson(thread.server, `/api/sessions/${encodeURIComponent(thread.sessionId)}/chat?limit=${PAGE}`);
                if (this.thread !== thread) return;
                if (!quiet) thread.messages.clear();
                for (const m of data.messages) thread.messages.set(m.id, m);
                thread.hasMore = data.has_more;
                thread.pendingId = data.pending_reply_id;
                const ids = [...thread.messages.keys()];
                thread.oldestId = ids.length ? Math.min(...ids) : 0;
                thread.lastId = ids.length ? Math.max(...ids) : 0;
                this.renderMessages(true);
                if (thread.pendingId && !thread.stream) this.pollPending(thread, thread.pendingId);
            } catch (e) {
                if (this.thread !== thread) return;
                if (e instanceof AuthError) { this.setLive('signed out', 'bad'); this.requireAuth(thread.server); }
                else if (e.status === 404) { this.setLive('gone', 'bad'); toast('Session not found', true); }
                else { this.setLive('offline', 'bad'); toast(e.message, true); }
            }
        }

        async loadOlder() {
            const t = this.thread;
            if (!t || !t.hasMore || t.loadingOlder) return;
            t.loadingOlder = true;
            const box = $('messages');
            const keepHeight = box.scrollHeight - box.scrollTop;
            try {
                const data = await apiJson(t.server, `/api/sessions/${encodeURIComponent(t.sessionId)}/chat?before=${t.oldestId}&limit=${PAGE}`);
                if (this.thread !== t) return;
                for (const m of data.messages) t.messages.set(m.id, m);
                t.hasMore = data.has_more;
                const ids = [...t.messages.keys()];
                t.oldestId = ids.length ? Math.min(...ids) : 0;
                this.renderMessages(false);
                box.scrollTop = box.scrollHeight - keepHeight;
            } catch (e) {
                toast(e.message, true);
            } finally {
                t.loadingOlder = false;
            }
        }

        upsert(thread, m) {
            if (m.session_id !== thread.sessionId) return;
            thread.messages.set(m.id, m);
            if (m.id > thread.lastId) thread.lastId = m.id;
            if (!thread.oldestId || m.id < thread.oldestId) thread.oldestId = m.id;
            if (m.role === 'assistant') {
                if (m.status === 'pending') thread.pendingId = m.id;
                else if (thread.pendingId === m.id) thread.pendingId = null;
            }
        }

        // ---- rendering ----

        renderMessages(scrollToEnd) {
            const t = this.thread;
            if (!t) return;
            const box = $('messages');
            const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
            box.innerHTML = '';
            if (t.hasMore) {
                const b = el('<button class="load-more">Load earlier messages</button>');
                b.onclick = () => this.loadOlder();
                box.appendChild(b);
            }
            const sorted = [...t.messages.values()].sort(byTime);
            if (!sorted.length) {
                box.appendChild(el('<div class="placeholder">Nothing here yet — ask the console something.</div>'));
            }
            for (const m of sorted) box.appendChild(this.messageEl(m));
            this.renderComposerState();
            if (scrollToEnd || nearBottom) box.scrollTop = box.scrollHeight;
        }

        messageEl(m) {
            const pending = m.status === 'pending';
            const emptyReply = m.role === 'assistant' && !m.content && !pending;
            const node = el(`<div class="msg ${esc(m.role)}" data-id="${m.id}" data-ts="${m.created_at}">
                <div class="bubble${emptyReply ? ' empty-reply' : ''}"></div>
                <div class="meta"></div>
            </div>`);
            const bubble = node.querySelector('.bubble');
            if (emptyReply) bubble.textContent = 'no output';
            else bubble.textContent = m.content;
            if (pending) {
                const dots = el('<span class="typing"><i></i><i></i><i></i></span>');
                if (m.content) bubble.appendChild(document.createTextNode('\n'));
                bubble.appendChild(dots);
            }
            const meta = node.querySelector('.meta');
            const tag = m.status !== 'done' ? `<span class="tag ${esc(m.status)}">${esc(m.status)}</span>` : '';
            const src = m.source === 'import' ? '<span class="tag import" title="Imported from the console">terminal</span>' : '';
            meta.innerHTML = `<span>${esc(clock(m.created_at))}</span>${tag}${src}`;
            return node;
        }

        patchMessage(m) {
            const box = $('messages');
            const existing = box.querySelector(`.msg[data-id="${m.id}"]`);
            const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
            const fresh = this.messageEl(m);
            if (existing) existing.replaceWith(fresh);
            else {
                box.querySelector('.placeholder')?.remove();
                // Keep id order even when the stream delivers a turn before
                // the POST that created it has returned.
                const next = [...box.querySelectorAll('.msg')].find((n) => byTime({ created_at: Number(n.dataset.ts), id: Number(n.dataset.id) }, m) > 0);
                if (next) box.insertBefore(fresh, next);
                else box.appendChild(fresh);
            }
            this.renderComposerState();
            if (nearBottom) box.scrollTop = box.scrollHeight;
        }

        renderComposerState() {
            const t = this.thread;
            const pending = !!(t && t.pendingId);
            $('btn-stop').hidden = !pending;
            $('btn-send').disabled = pending;
            $('input').placeholder = pending ? 'Waiting…' : 'Ask the console…';
        }

        // ---- live updates ----

        connectStream(thread) {
            if (!thread || this.thread !== thread || !('EventSource' in window)) return;
            thread.stream && thread.stream.close();
            let url = baseUrl(thread.server) + `/api/sessions/${encodeURIComponent(thread.sessionId)}/chat/stream?after=${thread.lastId}`;
            if (!thread.server.isLocal && thread.server.token) url += '&token=' + encodeURIComponent(thread.server.token);
            const es = new EventSource(url, { withCredentials: thread.server.isLocal });
            thread.stream = es;
            es.addEventListener('open', () => {
                thread.streamBackoff = 1000;
                this.setLive('live', 'live');
            });
            es.addEventListener('message', (ev) => {
                let m;
                try { m = JSON.parse(ev.data); } catch { return; }
                this.upsert(thread, m);
                this.patchMessage(m);
                if (m.role === 'assistant' && m.status !== 'pending') this.refreshServer(thread.server);
            });
            es.addEventListener('resync', () => this.loadThread(thread, true));
            es.onerror = () => {
                es.close();
                if (this.thread !== thread) return;
                thread.stream = null;
                this.setLive('reconnecting', 'warn');
                if (thread.pendingId) this.pollPending(thread, thread.pendingId);
                const wait = thread.streamBackoff;
                thread.streamBackoff = Math.min(wait * 2, 15000);
                setTimeout(() => {
                    if (this.thread === thread && !thread.stream) {
                        this.loadThread(thread, true).then(() => this.connectStream(thread));
                    }
                }, wait);
            };
        }

        /** Long-poll fallback while the stream is down. */
        async pollPending(thread, replyId) {
            if (thread.polling === replyId) return;
            thread.polling = replyId;
            const ctrl = new AbortController();
            thread.pollAbort = ctrl;
            try {
                while (this.thread === thread && thread.pendingId === replyId && !thread.stream) {
                    let m;
                    try {
                        m = await apiJson(thread.server, `/api/sessions/${encodeURIComponent(thread.sessionId)}/chat/${replyId}?wait=25`, { signal: ctrl.signal });
                    } catch (e) {
                        if (ctrl.signal.aborted) return;
                        await sleep(2000);
                        continue;
                    }
                    this.upsert(thread, m);
                    this.patchMessage(m);
                    if (m.status !== 'pending') { this.refreshServer(thread.server); break; }
                }
            } finally {
                if (thread.polling === replyId) thread.polling = null;
            }
        }

        // ---- actions ----

        async send() {
            const t = this.thread;
            const input = $('input');
            const text = input.value;
            if (!t || !text.trim() || t.pendingId) return;
            const s = this.sessionInfo(t);
            if (s && s.status !== 'running') { toast('This session is not running', true); return; }
            input.value = '';
            this.autosize();
            localStorage.removeItem(this.draftKey());
            const body = { text, wait: false, timeout: AGENT_TIMEOUT };
            if (t.fast) body.settle_ms = FAST_SETTLE_MS;
            try {
                const data = await apiJson(t.server, `/api/sessions/${encodeURIComponent(t.sessionId)}/chat`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                });
                if (this.thread !== t) return;
                for (const m of [data.question, data.reply]) if (m) { this.upsert(t, m); this.patchMessage(m); }
                $('messages').scrollTop = $('messages').scrollHeight;
                if (!t.stream && t.pendingId) this.pollPending(t, t.pendingId);
            } catch (e) {
                if (this.thread === t) { input.value = text; this.autosize(); }
                if (e instanceof AuthError) this.requireAuth(t.server);
                else if (e.status === 409) { t.pendingId = e.data.reply_id; this.renderComposerState(); toast('Still waiting for the previous reply'); this.loadThread(t, true); }
                else toast(e.message, true);
            }
            input.focus({ preventScroll: true });
        }

        async stop() {
            const t = this.thread;
            if (!t || !t.pendingId) return;
            try {
                const m = await apiJson(t.server, `/api/sessions/${encodeURIComponent(t.sessionId)}/chat/${t.pendingId}/cancel`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ interrupt: true }),
                });
                if (this.thread !== t) return;
                this.upsert(t, m);
                this.patchMessage(m);
            } catch (e) {
                toast(e.message, true);
            }
        }

        toggleMenu(force) {
            const menu = $('chat-menu');
            menu.hidden = force === undefined ? !menu.hidden : !force;
        }

        async menuAction(action) {
            const t = this.thread;
            this.toggleMenu(false);
            if (!t) return;
            if (action === 'fast') {
                t.fast = !t.fast;
                localStorage.setItem(this.fastKey(), t.fast ? '1' : '0');
                this.renderHeader();
                toast(t.fast ? 'Fast mode: replies settle after 0.3 s of quiet' : 'Agent mode: waits for prompts/spinners');
            } else if (action === 'refresh') {
                await this.loadThread(t, false);
                toast('Reloaded');
            } else if (action === 'clear') {
                if (!confirm('Delete all chat history for this session?')) return;
                try {
                    await apiJson(t.server, `/api/sessions/${encodeURIComponent(t.sessionId)}/chat`, { method: 'DELETE' });
                    t.messages.clear();
                    t.lastId = 0; t.oldestId = 0; t.hasMore = false;
                    this.renderMessages(true);
                    this.refreshServer(t.server);
                } catch (e) {
                    toast(e.message, true);
                }
            }
        }
    }

    window.remoteApp = new RemoteApp();
})();
