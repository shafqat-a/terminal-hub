const term = new Terminal({
  cursorBlink: true,
  fontFamily: "Menlo, monospace",
  fontSize: 13,
  scrollback: 5000,
});
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
    kill.textContent = "×";
    kill.title = "kill session";
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

function detach() {
  if (activeWs) activeWs.close();
  activeWs = null;
  activeId = null;
  term.reset();
}

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

term.onData((d) => {
  if (activeWs?.readyState === WebSocket.OPEN) activeWs.send(d);
});

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
