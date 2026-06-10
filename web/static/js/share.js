// Read-only viewer for a shared session. The page is served at /s/{token};
// it attaches to the public, read-only WebSocket at /ws/share/{token}.
// Input is never sent — the server also enforces read-only, so this is just UX.
(function () {
    const token = window.location.pathname.split('/').filter(Boolean).pop();
    const statusEl = document.getElementById('share-status');

    const term = new Terminal({
        cursorBlink: false,
        disableStdin: true,        // no local input
        fontSize: 14,
        fontFamily: "'JetBrains Mono', 'Fira Code', Menlo, monospace",
        theme: { background: '#1a1b26', foreground: '#c0caf5' },
    });
    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(new WebLinksAddon.WebLinksAddon());
    term.open(document.getElementById('share-terminal'));
    fitAddon.fit();
    window.addEventListener('resize', () => fitAddon.fit());

    let ws = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 20;

    function setStatus(text) { if (statusEl) statusEl.textContent = text; }

    function connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(protocol + '//' + window.location.host + (window.BASE_PATH || '') + '/ws/share/' + token);

        ws.onopen = () => { reconnectAttempts = 0; setStatus('live'); };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'output') term.write(msg.data);
            } catch { /* ignore malformed frames */ }
        };

        ws.onclose = () => {
            setStatus('disconnected');
            attemptReconnect();
        };

        ws.onerror = () => { /* onclose handles reconnect */ };
    }

    function attemptReconnect() {
        if (reconnectAttempts >= maxReconnectAttempts) {
            setStatus('link closed');
            term.write('\r\n\x1b[33m[Viewer disconnected. The link may have expired or the session ended.]\x1b[0m\r\n');
            return;
        }
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        reconnectAttempts++;
        setStatus('reconnecting…');
        setTimeout(connect, delay);
    }

    connect();
})();
