// Ported from ai-dev-conductor (Go). Share/upload/download endpoints arrive in M4.
// Terminal color themes. The xterm block is passed straight to Terminal.options.theme.
const THEMES = {
    tokyonight: {
        label: 'Tokyo Night',
        bg: '#1a1b26', panel: '#24283b', border: '#414868', accent: '#7aa2f7', text: '#c0caf5',
        xterm: {
            background: '#1a1b26', foreground: '#c0caf5', cursor: '#c0caf5', selectionBackground: '#33467c',
            black: '#15161e', red: '#f7768e', green: '#9ece6a', yellow: '#e0af68', blue: '#7aa2f7',
            magenta: '#bb9af7', cyan: '#7dcfff', white: '#a9b1d6', brightBlack: '#414868', brightRed: '#f7768e',
            brightGreen: '#9ece6a', brightYellow: '#e0af68', brightBlue: '#7aa2f7', brightMagenta: '#bb9af7',
            brightCyan: '#7dcfff', brightWhite: '#c0caf5',
        },
    },
    dracula: {
        label: 'Dracula',
        bg: '#282a36', panel: '#21222c', border: '#44475a', accent: '#bd93f9', text: '#f8f8f2',
        xterm: {
            background: '#282a36', foreground: '#f8f8f2', cursor: '#f8f8f2', selectionBackground: '#44475a',
            black: '#21222c', red: '#ff5555', green: '#50fa7b', yellow: '#f1fa8c', blue: '#bd93f9',
            magenta: '#ff79c6', cyan: '#8be9fd', white: '#f8f8f2', brightBlack: '#6272a4', brightRed: '#ff6e6e',
            brightGreen: '#69ff94', brightYellow: '#ffffa5', brightBlue: '#d6acff', brightMagenta: '#ff92df',
            brightCyan: '#a4ffff', brightWhite: '#ffffff',
        },
    },
    solarizedDark: {
        label: 'Solarized Dark',
        bg: '#002b36', panel: '#073642', border: '#0a4b5a', accent: '#268bd2', text: '#93a1a1',
        xterm: {
            background: '#002b36', foreground: '#93a1a1', cursor: '#93a1a1', selectionBackground: '#073642',
            black: '#073642', red: '#dc322f', green: '#859900', yellow: '#b58900', blue: '#268bd2',
            magenta: '#d33682', cyan: '#2aa198', white: '#eee8d5', brightBlack: '#586e75', brightRed: '#cb4b16',
            brightGreen: '#586e75', brightYellow: '#657b83', brightBlue: '#839496', brightMagenta: '#6c71c4',
            brightCyan: '#93a1a1', brightWhite: '#fdf6e3',
        },
    },
    light: {
        label: 'Light',
        bg: '#fafafa', panel: '#eceff4', border: '#d8dee9', accent: '#2563eb', text: '#2e3440',
        xterm: {
            background: '#fafafa', foreground: '#2e3440', cursor: '#2e3440', selectionBackground: '#d8dee9',
            black: '#2e3440', red: '#bf616a', green: '#a3be8c', yellow: '#d08770', blue: '#5e81ac',
            magenta: '#b48ead', cyan: '#88c0d0', white: '#e5e9f0', brightBlack: '#4c566a', brightRed: '#bf616a',
            brightGreen: '#a3be8c', brightYellow: '#ebcb8b', brightBlue: '#81a1c1', brightMagenta: '#b48ead',
            brightCyan: '#8fbcbb', brightWhite: '#eceff4',
        },
    },
    gruvboxDark: {
        label: 'Gruvbox Dark',
        bg: '#282828', panel: '#3c3836', border: '#504945', accent: '#fabd2f', text: '#ebdbb2',
        xterm: {
            background: '#282828', foreground: '#ebdbb2', cursor: '#ebdbb2', selectionBackground: '#504945',
            black: '#282828', red: '#cc241d', green: '#98971a', yellow: '#d79921', blue: '#458588',
            magenta: '#b16286', cyan: '#689d6a', white: '#a89984', brightBlack: '#928374', brightRed: '#fb4934',
            brightGreen: '#b8bb26', brightYellow: '#fabd2f', brightBlue: '#83a598', brightMagenta: '#d3869b',
            brightCyan: '#8ec07c', brightWhite: '#ebdbb2',
        },
    },
    nord: {
        label: 'Nord',
        bg: '#2e3440', panel: '#3b4252', border: '#4c566a', accent: '#88c0d0', text: '#d8dee9',
        xterm: {
            background: '#2e3440', foreground: '#d8dee9', cursor: '#d8dee9', selectionBackground: '#434c5e',
            black: '#3b4252', red: '#bf616a', green: '#a3be8c', yellow: '#ebcb8b', blue: '#81a1c1',
            magenta: '#b48ead', cyan: '#88c0d0', white: '#e5e9f0', brightBlack: '#4c566a', brightRed: '#bf616a',
            brightGreen: '#a3be8c', brightYellow: '#ebcb8b', brightBlue: '#81a1c1', brightMagenta: '#b48ead',
            brightCyan: '#8fbcbb', brightWhite: '#eceff4',
        },
    },
    catppuccinMocha: {
        label: 'Catppuccin Mocha',
        bg: '#1e1e2e', panel: '#181825', border: '#313244', accent: '#cba6f7', text: '#cdd6f4',
        xterm: {
            background: '#1e1e2e', foreground: '#cdd6f4', cursor: '#f5e0dc', selectionBackground: '#45475a',
            black: '#45475a', red: '#f38ba8', green: '#a6e3a1', yellow: '#f9e2af', blue: '#89b4fa',
            magenta: '#f5c2e7', cyan: '#94e2d5', white: '#bac2de', brightBlack: '#585b70', brightRed: '#f38ba8',
            brightGreen: '#a6e3a1', brightYellow: '#f9e2af', brightBlue: '#89b4fa', brightMagenta: '#f5c2e7',
            brightCyan: '#94e2d5', brightWhite: '#a6adc8',
        },
    },
    oneDark: {
        label: 'One Dark',
        bg: '#282c34', panel: '#21252b', border: '#3e4451', accent: '#61afef', text: '#abb2bf',
        xterm: {
            background: '#282c34', foreground: '#abb2bf', cursor: '#abb2bf', selectionBackground: '#3e4451',
            black: '#282c34', red: '#e06c75', green: '#98c379', yellow: '#e5c07b', blue: '#61afef',
            magenta: '#c678dd', cyan: '#56b6c2', white: '#abb2bf', brightBlack: '#5c6370', brightRed: '#e06c75',
            brightGreen: '#98c379', brightYellow: '#d19a66', brightBlue: '#61afef', brightMagenta: '#c678dd',
            brightCyan: '#56b6c2', brightWhite: '#ffffff',
        },
    },
    monokai: {
        label: 'Monokai',
        bg: '#272822', panel: '#1e1f1c', border: '#49483e', accent: '#a6e22e', text: '#f8f8f2',
        xterm: {
            background: '#272822', foreground: '#f8f8f2', cursor: '#f8f8f2', selectionBackground: '#49483e',
            black: '#272822', red: '#f92672', green: '#a6e22e', yellow: '#e6db74', blue: '#66d9ef',
            magenta: '#ae81ff', cyan: '#a1efe4', white: '#f8f8f2', brightBlack: '#75715e', brightRed: '#f92672',
            brightGreen: '#a6e22e', brightYellow: '#e6db74', brightBlue: '#66d9ef', brightMagenta: '#ae81ff',
            brightCyan: '#a1efe4', brightWhite: '#f9f8f5',
        },
    },
};

const FONT_FAMILY = "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Menlo, monospace";

class TerminalManager {
    constructor() {
        // Current connection state
        this.currentServerId = null;
        this.currentSessionId = null;
        this.ws = null;
        this.term = null;
        this.fitAddon = null;
        this.manualDisconnect = false;
        this.creatingSession = false;   // in-flight guard so one click makes one session
        this.reconnectAttempts = 0;
        this.reconnectTimer = null;
        this.maxReconnectAttempts = 20;

        // Server management
        this.servers = this.loadServers();

        // Preferences (theme + font size) and per-session activity bookkeeping.
        this.prefs = this.loadPrefs();
        this.activitySeen = {};          // "serverId:sessionId" -> last activity ts acknowledged
        this.ctrlArmed = false;          // mobile Ctrl key one-shot modifier

        // DOM elements
        this.sessionListEl = document.getElementById('session-list');
        this.placeholderEl = document.getElementById('placeholder');
        this.containerEl = document.getElementById('terminal-container');
        this.appEl = document.getElementById('app');

        document.getElementById('btn-new-session').addEventListener('click', () => this.createSession());
        document.getElementById('btn-add-server').addEventListener('click', () => this.addServer());
        document.getElementById('btn-settings').addEventListener('click', () => this.openSettings());
        document.getElementById('btn-palette').addEventListener('click', () => this.openPalette());
        document.getElementById('btn-sidebar-toggle').addEventListener('click', () => this.toggleSidebar());
        document.getElementById('sidebar-scrim').addEventListener('click', () => this.toggleSidebar(false));
        window.addEventListener('resize', () => this.handleResize());
        // Capture phase so our shortcuts win before xterm consumes the key.
        document.addEventListener('keydown', (e) => this.handleGlobalKeys(e), true);

        // Mobile on-screen modifier / navigation keys.
        document.getElementById('mobile-keybar').querySelectorAll('button').forEach((btn) => {
            btn.addEventListener('click', () => {
                if (btn.dataset.action === 'ctrl') {
                    this.setCtrlArmed(!this.ctrlArmed);
                } else if (btn.dataset.seq != null) {
                    this.sendInput(btn.dataset.seq);
                    if (this.term) this.term.focus();
                }
            });
        });

        // Registered once: the container element is reused across sessions, so
        // attaching per-connect would stack duplicate handlers.
        this.containerEl.addEventListener('paste', (e) => this.handlePaste(e), true);

        // Drag-and-drop a file onto the terminal to upload it into the session's CWD.
        this.containerEl.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.containerEl.classList.add('drag-over');
        });
        this.containerEl.addEventListener('dragleave', (e) => {
            if (e.target === this.containerEl) this.containerEl.classList.remove('drag-over');
        });
        this.containerEl.addEventListener('drop', (e) => {
            e.preventDefault();
            this.containerEl.classList.remove('drag-over');
            const files = e.dataTransfer && e.dataTransfer.files;
            if (files) for (const f of files) this.uploadFile(f);
        });

        this.applyThemeToPage();
        this.loadAllSessions();
        // Poll so activity dots / status reflect background sessions.
        this.pollTimer = setInterval(() => this.loadAllSessions(), 5000);
    }

    // --- Preferences ---

    loadPrefs() {
        const defaults = { theme: 'tokyonight', fontSize: 14 };
        try {
            return { ...defaults, ...JSON.parse(localStorage.getItem('ai_conductor_prefs') || '{}') };
        } catch {
            return defaults;
        }
    }

    savePrefs() {
        localStorage.setItem('ai_conductor_prefs', JSON.stringify(this.prefs));
    }

    theme() {
        return THEMES[this.prefs.theme] || THEMES.tokyonight;
    }

    // Push theme colors into CSS custom properties so the chrome matches the terminal.
    applyThemeToPage() {
        const t = this.theme();
        const root = document.documentElement.style;
        root.setProperty('--bg', t.bg);
        root.setProperty('--panel', t.panel);
        root.setProperty('--border', t.border);
        root.setProperty('--accent', t.accent);
        root.setProperty('--text', t.text);
    }

    applyPrefs() {
        this.applyThemeToPage();
        if (this.term) {
            this.term.options.theme = this.theme().xterm;
            this.term.options.fontSize = this.prefs.fontSize;
            if (this.fitAddon) this.fitAddon.fit();
            this.sendResize();
        }
    }

    // --- Server Management ---

    loadServers() {
        const stored = localStorage.getItem('ai_conductor_servers');
        if (stored) {
            const servers = JSON.parse(stored);
            if (!servers.find(s => s.isLocal)) {
                servers.unshift({ id: 'local', name: 'Local', url: '', token: null, isLocal: true, connected: true });
            }
            return servers;
        }
        return [{ id: 'local', name: 'Local', url: '', token: null, isLocal: true, connected: true }];
    }

    saveServers() {
        localStorage.setItem('ai_conductor_servers', JSON.stringify(this.servers));
    }

    getServerBaseUrl(server) {
        // Local server requests are same-origin but must carry the app's base path
        // (e.g. /terminaltest) when it's served under a reverse-proxy subpath.
        if (server.isLocal || !server.url) return window.BASE_PATH || '';
        return server.url.replace(/\/$/, '');
    }

    getServerById(serverId) {
        return this.servers.find(s => s.id === serverId);
    }

    async fetchFromServer(server, path, options = {}) {
        const baseUrl = this.getServerBaseUrl(server);
        const url = baseUrl + path;

        if (server.isLocal) {
            return fetch(url, options);
        }

        const headers = { ...(options.headers || {}) };
        if (server.token) {
            headers['X-Session-Token'] = server.token;
        }
        return fetch(url, { ...options, headers, credentials: 'omit' });
    }

    async addServer() {
        const name = prompt('Server name:');
        if (!name) return;
        const url = prompt('Server URL (e.g. http://192.168.1.50:8080):');
        if (!url) return;

        const server = {
            id: Math.random().toString(36).slice(2, 10),
            name: name.trim(),
            url: url.trim().replace(/\/$/, ''),
            token: null,
            isLocal: false,
            connected: false,
        };

        const authenticated = await this.authenticateServer(server);
        if (!authenticated) return;

        this.servers.push(server);
        this.saveServers();
        await this.loadAllSessions();
    }

    async authenticateServer(server) {
        const password = prompt(`Password for ${server.name}:`);
        if (password === null) return false;

        try {
            const res = await fetch(server.url + '/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password }),
                credentials: 'omit',
            });
            if (res.ok) {
                const data = await res.json();
                server.token = data.token;
                server.connected = true;
                this.saveServers();
                return true;
            } else {
                alert('Authentication failed');
                return false;
            }
        } catch (err) {
            alert('Cannot connect to ' + server.name + ': ' + err.message);
            return false;
        }
    }

    removeServer(serverId) {
        // Disconnect if currently connected to a session on this server
        if (this.currentServerId === serverId) {
            this.disconnect();
            this.showPlaceholder();
        }
        this.servers = this.servers.filter(s => s.id !== serverId);
        this.saveServers();
        this.loadAllSessions();
    }

    // --- Session Loading ---

    async loadAllSessions() {
        const results = await Promise.allSettled(
            this.servers.map(async (server) => {
                try {
                    const res = await this.fetchFromServer(server, '/api/sessions');
                    if (res.status === 401) {
                        if (server.isLocal) {
                            window.location.href = (window.BASE_PATH || '') + '/';
                            return [];
                        }
                        server.connected = false;
                        this.saveServers();
                        return [];
                    }
                    const sessions = await res.json();
                    server.connected = true;
                    return sessions.map(s => ({ ...s, serverId: server.id }));
                } catch {
                    server.connected = false;
                    return [];
                }
            })
        );

        const allSessions = results.flatMap(r => r.status === 'fulfilled' ? r.value : []);
        this.renderSessionList(allSessions);
    }

    // --- Rendering ---

    renderSessionList(sessions) {
        this.sessionListEl.innerHTML = '';

        // Group sessions by server
        const grouped = {};
        this.servers.forEach(s => { grouped[s.id] = { server: s, sessions: [] }; });
        sessions.forEach(s => {
            if (grouped[s.serverId]) {
                grouped[s.serverId].sessions.push(s);
            }
        });

        for (const [serverId, group] of Object.entries(grouped)) {
            const server = group.server;

            // Server group header
            const header = document.createElement('div');
            header.className = 'server-group-header';
            const statusClass = server.connected !== false ? 'connected' : 'disconnected';
            header.innerHTML =
                '<span class="server-status ' + statusClass + '"></span>' +
                '<span class="server-name">' + this.escapeHtml(server.name) + '</span>';

            if (!server.isLocal) {
                const menuBtn = document.createElement('button');
                menuBtn.className = 'btn-server-menu';
                menuBtn.title = 'Server options';
                menuBtn.innerHTML = '&#8942;';
                menuBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.showServerMenu(server, menuBtn);
                });
                header.appendChild(menuBtn);
            }

            this.sessionListEl.appendChild(header);

            // Sessions under this server
            group.sessions.forEach(s => {
                const isActive = this.currentServerId === serverId && this.currentSessionId === s.id;
                const key = serverId + ':' + s.id;
                const activity = s.lastActivityAt || 0;

                // Establish a baseline the first time we see a session, and keep the
                // focused session marked as read. Otherwise flag fresh output.
                if (isActive) {
                    this.activitySeen[key] = activity;
                } else if (this.activitySeen[key] === undefined) {
                    this.activitySeen[key] = activity;
                }
                const unread = !isActive && activity > (this.activitySeen[key] || 0);
                const detached = s.status === 'detached' || s.status === 'dead';

                if (isActive) {
                    document.getElementById('topbar-title').textContent = s.name || s.id;
                }

                const item = document.createElement('div');
                item.className = 'session-item' + (isActive ? ' active' : '') + (detached ? ' detached' : '');
                item.dataset.serverId = serverId;
                item.dataset.sessionId = s.id;

                const dot = document.createElement('span');
                dot.className = 'activity-dot' + (unread ? ' unread' : '');
                item.appendChild(dot);

                const nameSpan = document.createElement('span');
                nameSpan.className = 'session-name';
                nameSpan.title = s.createdAt + (detached ? ' (detached — shell not running)' : '');
                nameSpan.textContent = s.name || s.id;
                nameSpan.addEventListener('click', () => this.connectToSession(serverId, s.id));

                const renameBtn = document.createElement('button');
                renameBtn.className = 'btn-rename';
                renameBtn.title = 'Rename session';
                renameBtn.innerHTML = '&#9998;';
                renameBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.renameSession(serverId, s.id, s.name || s.id);
                });

                const shareBtn = document.createElement('button');
                shareBtn.className = 'btn-share';
                shareBtn.title = 'Create read-only share link';
                shareBtn.innerHTML = '&#128279;'; // 🔗
                shareBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.shareSession(serverId, s.id);
                });

                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'btn-delete';
                deleteBtn.title = 'Delete session';
                deleteBtn.innerHTML = '&times;';
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.deleteSession(serverId, s.id);
                });

                item.appendChild(nameSpan);
                item.appendChild(shareBtn);
                item.appendChild(renameBtn);
                item.appendChild(deleteBtn);
                this.sessionListEl.appendChild(item);
            });
        }
    }

    showServerMenu(server, anchorEl) {
        document.querySelectorAll('.server-menu').forEach(el => el.remove());

        const menu = document.createElement('div');
        menu.className = 'server-menu';

        const reconnectOpt = document.createElement('div');
        reconnectOpt.className = 'server-menu-item';
        reconnectOpt.textContent = 'Reconnect';
        reconnectOpt.addEventListener('click', async () => {
            menu.remove();
            const ok = await this.authenticateServer(server);
            if (ok) await this.loadAllSessions();
        });

        const removeOpt = document.createElement('div');
        removeOpt.className = 'server-menu-item danger';
        removeOpt.textContent = 'Remove';
        removeOpt.addEventListener('click', () => {
            menu.remove();
            this.removeServer(server.id);
        });

        menu.appendChild(reconnectOpt);
        menu.appendChild(removeOpt);

        // Position near the anchor
        anchorEl.style.position = 'relative';
        anchorEl.parentElement.style.position = 'relative';
        anchorEl.parentElement.appendChild(menu);

        const closeHandler = (e) => {
            if (!menu.contains(e.target)) {
                menu.remove();
                document.removeEventListener('click', closeHandler);
            }
        };
        setTimeout(() => document.addEventListener('click', closeHandler), 0);
    }

    // --- Session CRUD ---

    async createSession() {
        // Guard against duplicate triggers for a single intent — mobile "ghost
        // clicks" (a tap firing click twice), impatient double-clicks, or a click
        // landing while a previous create is still in flight would otherwise each
        // POST a new session, spawning several from one action.
        if (this.creatingSession) return;
        this.creatingSession = true;
        const newSessionBtn = document.getElementById('btn-new-session');
        if (newSessionBtn) newSessionBtn.disabled = true;

        try {
            const connectedServers = this.servers.filter(s => s.connected !== false);

            let targetServer;
            if (connectedServers.length === 0) {
                alert('No servers connected');
                return;
            } else if (connectedServers.length === 1) {
                targetServer = connectedServers[0];
            } else {
                targetServer = await this.showServerPicker(connectedServers);
                if (!targetServer) return;
            }

            const res = await this.fetchFromServer(targetServer, '/api/sessions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });
            if (res.status === 401) {
                if (targetServer.isLocal) {
                    window.location.href = (window.BASE_PATH || '') + '/';
                } else {
                    await this.authenticateServer(targetServer);
                }
                return;
            }
            const data = await res.json();
            await this.loadAllSessions();
            this.connectToSession(targetServer.id, data.id);
        } catch (err) {
            console.error('Failed to create session:', err);
        } finally {
            this.creatingSession = false;
            if (newSessionBtn) newSessionBtn.disabled = false;
        }
    }

    showServerPicker(servers) {
        return new Promise((resolve) => {
            document.querySelectorAll('.server-picker').forEach(el => el.remove());

            const picker = document.createElement('div');
            picker.className = 'server-picker';
            servers.forEach(s => {
                const opt = document.createElement('div');
                opt.className = 'server-picker-item';
                opt.textContent = s.name;
                opt.addEventListener('click', () => {
                    picker.remove();
                    resolve(s);
                });
                picker.appendChild(opt);
            });

            const btn = document.getElementById('btn-new-session');
            btn.parentElement.style.position = 'relative';
            btn.parentElement.appendChild(picker);

            const closeHandler = (e) => {
                if (!picker.contains(e.target) && e.target !== btn) {
                    picker.remove();
                    document.removeEventListener('click', closeHandler);
                    resolve(null);
                }
            };
            setTimeout(() => document.addEventListener('click', closeHandler), 0);
        });
    }

    async renameSession(serverId, sessionId, currentName) {
        const newName = prompt('Rename session:', currentName);
        if (newName === null || newName.trim() === '') return;

        const server = this.getServerById(serverId);
        if (!server) return;

        try {
            const res = await this.fetchFromServer(server, '/api/sessions/' + sessionId, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: newName.trim() }),
            });
            if (res.ok) {
                await this.loadAllSessions();
            }
        } catch (err) {
            console.error('Failed to rename session:', err);
        }
    }

    async deleteSession(serverId, sessionId) {
        const server = this.getServerById(serverId);
        if (!server) return;

        try {
            await this.fetchFromServer(server, '/api/sessions/' + sessionId, { method: 'DELETE' });
            if (this.currentServerId === serverId && this.currentSessionId === sessionId) {
                this.disconnect();
                this.showPlaceholder();
            }
            await this.loadAllSessions();
        } catch (err) {
            console.error('Failed to delete session:', err);
        }
    }

    async shareSession(serverId, sessionId) {
        const server = this.getServerById(serverId);
        if (!server) return;

        try {
            const res = await this.fetchFromServer(server, '/api/sessions/' + sessionId + '/share', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                alert('Could not create share link: ' + (err.error || res.status));
                return;
            }
            const data = await res.json();

            // The server returns an absolute URL only when AI_CONDUCTOR_PUBLIC_URL
            // is set; otherwise it's a path we resolve against the server's origin.
            let link = data.url || data.path;
            if (link && !/^https?:\/\//i.test(link)) {
                const base = server.isLocal ? window.location.origin + (window.BASE_PATH || '') : this.getServerBaseUrl(server);
                link = base + link;
            }
            this.showShareLink(link, data.expiresAt);
        } catch (err) {
            console.error('Failed to create share link:', err);
            alert('Could not create share link: ' + err.message);
        }
    }

    // Read-only links are shown once; the raw token is never recoverable later.
    showShareLink(link, expiresAt) {
        this.closeOverlays();

        const overlay = document.createElement('div');
        overlay.className = 'overlay';
        overlay.addEventListener('click', (e) => { if (e.target === overlay) this.closeOverlays(); });

        const modal = document.createElement('div');
        modal.className = 'overlay-panel';

        const title = document.createElement('h2');
        title.textContent = 'Read-only share link';

        const desc = document.createElement('p');
        desc.className = 'modal-desc';
        const when = expiresAt ? new Date(expiresAt * 1000).toLocaleString() : 'a set time';
        desc.textContent = 'Anyone with this link can watch (not control) the session until ' + when + '. Copy it now — it is shown only once.';

        const row = document.createElement('div');
        row.className = 'share-link-row';

        const input = document.createElement('input');
        input.type = 'text';
        input.readOnly = true;
        input.value = link;
        input.className = 'share-link-input';
        input.addEventListener('focus', () => input.select());

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn-copy';
        copyBtn.textContent = 'Copy';
        copyBtn.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(link);
                copyBtn.textContent = 'Copied!';
            } catch {
                input.focus();
                input.select();
                copyBtn.textContent = 'Press Ctrl+C';
            }
            setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
        });

        const closeBtn = document.createElement('button');
        closeBtn.className = 'overlay-close';
        closeBtn.textContent = 'Done';
        closeBtn.addEventListener('click', () => this.closeOverlays());

        row.appendChild(input);
        row.appendChild(copyBtn);
        modal.appendChild(title);
        modal.appendChild(desc);
        modal.appendChild(row);
        modal.appendChild(closeBtn);
        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        input.focus();
        input.select();
    }

    // --- Terminal Connection ---

    connectToSession(serverId, sessionId) {
        this.disconnect();
        this.currentServerId = serverId;
        this.currentSessionId = sessionId;
        this.manualDisconnect = false;
        this.reconnectAttempts = 0;
        this.activitySeen[serverId + ':' + sessionId] = Math.floor(Date.now() / 1000);
        this.toggleSidebar(false); // collapse the overlay sidebar on mobile

        // Show terminal container
        this.placeholderEl.style.display = 'none';
        this.containerEl.style.display = 'block';
        this.containerEl.innerHTML = '';

        // Update active state in sidebar
        this.sessionListEl.querySelectorAll('.session-item').forEach(el => {
            const isActive = el.dataset.serverId === serverId && el.dataset.sessionId === sessionId;
            el.classList.toggle('active', isActive);
        });

        // Create terminal
        this.term = new Terminal({
            cursorBlink: true,
            fontSize: this.prefs.fontSize,
            fontFamily: FONT_FAMILY,
            theme: this.theme().xterm,
        });

        this.fitAddon = new FitAddon.FitAddon();
        this.term.loadAddon(this.fitAddon);
        this.term.loadAddon(new WebLinksAddon.WebLinksAddon());

        this.term.open(this.containerEl);
        this.fitAddon.fit();

        // Send terminal input to server (via sendInput so the mobile Ctrl modifier applies).
        this.term.onData((data) => this.sendInput(data));

        // Terminal bell -> notify + mark unread if not focused.
        this.term.onBell(() => this.handleBell(serverId, sessionId));

        // Handle terminal-generated binary reports (DSR, etc.) as raw PTY input.
        this.term.onBinary((data) => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                const buffer = new Uint8Array(data.length);
                for (let i = 0; i < data.length; i++) {
                    buffer[i] = data.charCodeAt(i) & 0xff;
                }
                this.ws.send(buffer);
            }
        });

        // Clipboard image paste is intercepted by the document-level handler
        // registered in the constructor (xterm.js only pastes text/plain, so an
        // image never reaches the PTY on its own).

        this.openWebSocket(serverId, sessionId);
    }

    openWebSocket(serverId, sessionId) {
        const server = this.getServerById(serverId);
        if (!server) return;

        // Tear down any existing socket first. A reconnect race could otherwise
        // leave the previous socket open with its onmessage closure still live;
        // both sockets then write to the same terminal, doubling every byte of
        // output (e.g. a pasted image path appears twice).
        if (this.ws) {
            const stale = this.ws;
            stale.onopen = stale.onmessage = stale.onclose = stale.onerror = null;
            try { stale.close(); } catch (_) { /* already closing */ }
            this.ws = null;
        }

        // A reconnect makes the server re-seed the full scrollback snapshot. Clear
        // the stale buffer once the new socket opens so that snapshot replaces the
        // existing content instead of stacking a duplicate copy on top of it.
        const isReconnect = this.reconnectAttempts > 0;

        let wsUrl;
        if (server.isLocal) {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            wsUrl = protocol + '//' + window.location.host + (window.BASE_PATH || '') + '/ws/' + sessionId;
        } else {
            const url = new URL(server.url);
            const protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
            wsUrl = protocol + '//' + url.host + '/ws/' + sessionId + '?token=' + encodeURIComponent(server.token || '');
        }

        const ws = new WebSocket(wsUrl);
        this.ws = ws;

        ws.onopen = () => {
            if (this.ws !== ws) return; // superseded by a newer socket
            // Reset only on a successful reconnect (the initial connect already has
            // a fresh terminal). Done here, not in attemptReconnect, so the
            // "[Reconnecting…]" notices stay visible until the attach actually lands.
            if (isReconnect && this.term) {
                this.term.reset();
            }
            this.reconnectAttempts = 0;
            this.sendResize();
        };

        ws.onmessage = (event) => {
            if (this.ws !== ws) return; // ignore output from a stale socket
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'output') {
                    this.term.write(msg.data);
                }
            } catch {
                // Ignore malformed messages
            }
        };

        ws.onclose = () => {
            if (this.ws !== ws) return; // a newer socket already owns the session
            if (this.manualDisconnect || this.currentSessionId !== sessionId || this.currentServerId !== serverId) {
                return;
            }
            this.attemptReconnect(serverId, sessionId);
        };

        ws.onerror = () => {
            // onclose will fire after this, reconnect handled there
        };
    }

    attemptReconnect(serverId, sessionId) {
        if (this.manualDisconnect || this.currentSessionId !== sessionId || this.currentServerId !== serverId) {
            return;
        }

        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            if (this.term) {
                this.term.write('\r\n\x1b[31m[Connection lost. Click to reconnect.]\x1b[0m\r\n');
                const disposable = this.term.onData(() => {
                    disposable.dispose();
                    this.reconnectAttempts = 0;
                    this.attemptReconnect(serverId, sessionId);
                });
            }
            return;
        }

        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
        this.reconnectAttempts++;

        if (this.term) {
            this.term.write('\r\n\x1b[33m[Reconnecting (' + this.reconnectAttempts + '/' + this.maxReconnectAttempts + ')...]\x1b[0m\r\n');
        }

        this.reconnectTimer = setTimeout(() => {
            if (this.manualDisconnect || this.currentSessionId !== sessionId || this.currentServerId !== serverId) {
                return;
            }
            this.openWebSocket(serverId, sessionId);
        }, delay);
    }

    disconnect() {
        this.manualDisconnect = true;
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        if (this.term) {
            this.term.dispose();
            this.term = null;
            this.fitAddon = null;
        }
        this.currentSessionId = null;
        this.currentServerId = null;
    }

    showPlaceholder() {
        this.containerEl.style.display = 'none';
        this.containerEl.innerHTML = '';
        this.placeholderEl.style.display = 'flex';
        this.currentSessionId = null;
        this.currentServerId = null;
        const title = document.getElementById('topbar-title');
        if (title) title.textContent = 'AI Dev Conductor';
    }

    handleResize() {
        if (this.fitAddon && this.term) {
            this.fitAddon.fit();
            this.sendResize();
        }
    }

    sendResize() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN && this.term) {
            this.ws.send(JSON.stringify({
                type: 'resize',
                cols: this.term.cols,
                rows: this.term.rows,
            }));
        }
    }

    // Capture-phase paste handler. Image clipboard content is sent to the
    // server; text paste is left for xterm.js to handle normally.
    handlePaste(e) {
        const items = e.clipboardData && e.clipboardData.items;
        if (!items) return;

        for (const item of items) {
            if (item.kind === 'file' && item.type && item.type.startsWith('image/')) {
                e.preventDefault();
                e.stopPropagation();

                const blob = item.getAsFile();
                if (!blob) return;

                const reader = new FileReader();
                reader.onload = () => {
                    // reader.result is "data:<mime>;base64,<payload>"
                    const base64 = String(reader.result).split(',')[1] || '';
                    if (base64 && this.ws && this.ws.readyState === WebSocket.OPEN) {
                        this.ws.send(JSON.stringify({
                            type: 'paste-image',
                            mime: blob.type || item.type,
                            data: base64,
                        }));
                    }
                };
                reader.readAsDataURL(blob);
                return; // only the first image
            }
        }
        // No image present: let the event continue to xterm's text paste.
    }

    // --- File transfer ---

    // pickAndUpload opens a native file picker and uploads the chosen file(s).
    pickAndUpload() {
        const input = document.createElement('input');
        input.type = 'file';
        input.multiple = true;
        input.addEventListener('change', () => {
            for (const f of input.files) this.uploadFile(f);
        });
        input.click();
    }

    // uploadFile POSTs a File to the current session's working directory.
    async uploadFile(file) {
        if (!this.currentSessionId) {
            this.toast('No active session', 'error');
            return;
        }
        const server = this.getServerById(this.currentServerId);
        const form = new FormData();
        form.append('file', file);
        this.toast('Uploading ' + file.name + '…');
        try {
            const res = await this.fetchFromServer(
                server, '/api/sessions/' + this.currentSessionId + '/upload',
                { method: 'POST', body: form });
            if (res.ok) {
                this.toast('Uploaded ' + file.name, 'success');
            } else {
                const body = await res.json().catch(() => ({}));
                this.toast('Upload failed: ' + (body.error || res.status), 'error');
            }
        } catch (err) {
            this.toast('Upload failed: ' + err.message, 'error');
        }
    }

    // promptAndDownload asks for a path (relative to the session CWD) and downloads it.
    promptAndDownload() {
        if (!this.currentSessionId) return;
        const path = prompt('File to download (relative to the session directory):');
        if (!path) return;
        this.downloadFile(path);
    }

    // downloadFile navigates to the download endpoint, triggering a browser download.
    // Confinement to the session CWD is enforced server-side.
    downloadFile(path) {
        const server = this.getServerById(this.currentServerId);
        const base = this.getServerBaseUrl(server);
        const url = base + '/api/sessions/' + this.currentSessionId +
            '/download?path=' + encodeURIComponent(path);
        // For local (cookie-auth) servers a plain navigation carries credentials and
        // lets the browser handle the Content-Disposition download natively.
        if (server.isLocal || !server.url) {
            window.open(url, '_blank');
            return;
        }
        // Remote servers authenticate via header, so fetch + object URL instead.
        this.fetchFromServer(server, '/api/sessions/' + this.currentSessionId +
            '/download?path=' + encodeURIComponent(path))
            .then(res => res.ok ? res.blob() : Promise.reject(new Error('HTTP ' + res.status)))
            .then(blob => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = path.split('/').pop();
                a.click();
                URL.revokeObjectURL(a.href);
            })
            .catch(err => this.toast('Download failed: ' + err.message, 'error'));
    }

    // toast shows a transient status message in the corner.
    toast(message, kind = 'info') {
        let host = document.getElementById('toast-host');
        if (!host) {
            host = document.createElement('div');
            host.id = 'toast-host';
            document.body.appendChild(host);
        }
        const el = document.createElement('div');
        el.className = 'toast toast-' + kind;
        el.textContent = message;
        host.appendChild(el);
        setTimeout(() => el.remove(), 4000);
    }

    // --- Input (with mobile Ctrl modifier) ---

    sendInput(data) {
        if (this.ctrlArmed) {
            data = this.applyCtrl(data);
            this.setCtrlArmed(false);
        }
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ type: 'input', data }));
        }
    }

    applyCtrl(data) {
        if (data.length !== 1) return data;
        const code = data.toLowerCase().charCodeAt(0);
        if (code >= 97 && code <= 122) return String.fromCharCode(code - 96); // a..z -> ^A..^Z
        if (data === ' ') return '\x00';
        return data;
    }

    setCtrlArmed(on) {
        this.ctrlArmed = on;
        const btn = document.getElementById('key-ctrl');
        if (btn) btn.classList.toggle('armed', on);
    }

    // --- Bell / notifications ---

    handleBell(serverId, sessionId) {
        const focused = this.currentServerId === serverId &&
            this.currentSessionId === sessionId && !document.hidden;
        if (!focused) {
            this.activitySeen[serverId + ':' + sessionId] = 0; // force unread dot
            this.loadAllSessions();
            this.notify('Terminal bell', this.sessionLabel(serverId, sessionId));
        }
    }

    notify(title, body) {
        if (!('Notification' in window)) return;
        if (Notification.permission === 'granted') {
            new Notification(title, { body });
        } else if (Notification.permission !== 'denied') {
            Notification.requestPermission();
        }
    }

    sessionLabel(serverId, sessionId) {
        const el = this.sessionListEl.querySelector(
            '.session-item[data-server-id="' + serverId + '"][data-session-id="' + sessionId + '"] .session-name');
        return el ? el.textContent : sessionId;
    }

    // --- Sidebar (mobile overlay) ---

    toggleSidebar(force) {
        const open = force === undefined ? !this.appEl.classList.contains('sidebar-open') : force;
        this.appEl.classList.toggle('sidebar-open', open);
    }

    // --- Overlays ---

    makeOverlay(cls) {
        const overlay = document.createElement('div');
        overlay.className = 'overlay ' + cls;
        overlay.addEventListener('click', (e) => { if (e.target === overlay) this.closeOverlays(); });
        document.body.appendChild(overlay);
        return overlay;
    }

    closeOverlays() {
        document.querySelectorAll('.overlay').forEach(el => el.remove());
    }

    openSettings() {
        this.closeOverlays();
        const overlay = this.makeOverlay('settings-overlay');
        const panel = document.createElement('div');
        panel.className = 'overlay-panel';
        panel.innerHTML = '<h2>Settings</h2>';

        const themeRow = document.createElement('div');
        themeRow.className = 'settings-row';
        themeRow.innerHTML = '<label>Theme</label>';
        const sel = document.createElement('select');
        Object.entries(THEMES).forEach(([k, v]) => {
            const o = document.createElement('option');
            o.value = k; o.textContent = v.label;
            if (k === this.prefs.theme) o.selected = true;
            sel.appendChild(o);
        });
        sel.addEventListener('change', () => {
            this.prefs.theme = sel.value; this.savePrefs(); this.applyPrefs();
        });
        themeRow.appendChild(sel);

        const fontRow = document.createElement('div');
        fontRow.className = 'settings-row';
        fontRow.innerHTML = '<label>Font size</label>';
        const range = document.createElement('input');
        range.type = 'range'; range.min = 10; range.max = 24; range.value = this.prefs.fontSize;
        const val = document.createElement('span');
        val.className = 'settings-val'; val.textContent = this.prefs.fontSize + 'px';
        range.addEventListener('input', () => {
            this.prefs.fontSize = parseInt(range.value, 10);
            val.textContent = range.value + 'px';
            this.savePrefs(); this.applyPrefs();
        });
        fontRow.appendChild(range); fontRow.appendChild(val);

        const close = document.createElement('button');
        close.className = 'overlay-close'; close.textContent = 'Done';
        close.addEventListener('click', () => this.closeOverlays());

        panel.appendChild(themeRow);
        panel.appendChild(fontRow);
        panel.appendChild(close);
        overlay.appendChild(panel);
    }

    // --- Command palette ---

    openPalette() {
        this.closeOverlays();
        const overlay = this.makeOverlay('palette-overlay');
        const panel = document.createElement('div');
        panel.className = 'palette-panel';
        const input = document.createElement('input');
        input.className = 'palette-input';
        input.placeholder = 'Type a command or session…';
        const list = document.createElement('div');
        list.className = 'palette-list';
        panel.appendChild(input);
        panel.appendChild(list);
        overlay.appendChild(panel);

        const commands = this.paletteCommands();
        let filtered = commands;
        let active = 0;

        const render = () => {
            list.innerHTML = '';
            filtered.forEach((cmd, i) => {
                const row = document.createElement('div');
                row.className = 'palette-item' + (i === active ? ' active' : '');
                row.textContent = cmd.label;
                row.addEventListener('click', () => { this.closeOverlays(); cmd.run(); });
                list.appendChild(row);
            });
        };
        input.addEventListener('input', () => {
            const q = input.value.toLowerCase();
            filtered = commands.filter(c => c.label.toLowerCase().includes(q));
            active = 0;
            render();
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') { active = Math.min(active + 1, filtered.length - 1); render(); e.preventDefault(); }
            else if (e.key === 'ArrowUp') { active = Math.max(active - 1, 0); render(); e.preventDefault(); }
            else if (e.key === 'Enter') { if (filtered[active]) { this.closeOverlays(); filtered[active].run(); } }
            else if (e.key === 'Escape') { this.closeOverlays(); }
            e.stopPropagation();
        });
        render();
        setTimeout(() => input.focus(), 0);
    }

    paletteCommands() {
        const cmds = [
            { label: 'New session', run: () => this.createSession() },
            { label: 'Settings', run: () => this.openSettings() },
            { label: 'Add server', run: () => this.addServer() },
            { label: 'Next session', run: () => this.cycleSession(1) },
            { label: 'Previous session', run: () => this.cycleSession(-1) },
        ];
        if (this.currentSessionId) {
            cmds.push({ label: 'Upload file to session…', run: () => this.pickAndUpload() });
            cmds.push({ label: 'Download file from session…', run: () => this.promptAndDownload() });
        }
        Object.keys(THEMES).forEach(k => cmds.push({
            label: 'Theme: ' + THEMES[k].label,
            run: () => { this.prefs.theme = k; this.savePrefs(); this.applyPrefs(); },
        }));
        this.sessionListEl.querySelectorAll('.session-item').forEach(el => {
            const nameEl = el.querySelector('.session-name');
            const sid = el.dataset.sessionId, srv = el.dataset.serverId;
            cmds.push({ label: 'Go to: ' + (nameEl ? nameEl.textContent : sid), run: () => this.connectToSession(srv, sid) });
        });
        return cmds;
    }

    cycleSession(dir) {
        const items = Array.from(this.sessionListEl.querySelectorAll('.session-item'));
        if (!items.length) return;
        let idx = items.findIndex(el =>
            el.dataset.serverId === this.currentServerId && el.dataset.sessionId === this.currentSessionId);
        if (idx < 0) idx = dir > 0 ? 0 : items.length - 1;
        else idx = (idx + dir + items.length) % items.length;
        const el = items[idx];
        this.connectToSession(el.dataset.serverId, el.dataset.sessionId);
    }

    handleGlobalKeys(e) {
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
            e.preventDefault(); e.stopPropagation();
            this.openPalette();
            return;
        }
        if (e.ctrlKey && e.shiftKey) {
            if (e.code === 'BracketRight') { e.preventDefault(); e.stopPropagation(); this.cycleSession(1); }
            else if (e.code === 'BracketLeft') { e.preventDefault(); e.stopPropagation(); this.cycleSession(-1); }
            else if (e.code === 'KeyN') { e.preventDefault(); e.stopPropagation(); this.createSession(); }
        }
    }

    // --- Utilities ---

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize
const manager = new TerminalManager();
