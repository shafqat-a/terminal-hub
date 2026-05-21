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
let me = null; // { email, role } — populated on first refresh

async function loadMe() {
  if (me) return me;
  try {
    const r = await fetch("/api/me");
    if (!r.ok) return null;
    me = await r.json();
    return me;
  } catch {
    return null;
  }
}

async function refreshSessions() {
  const r = await fetch("/api/sessions");
  const { sessions } = await r.json();
  await loadMe();
  const ul = document.getElementById("session-list");
  ul.innerHTML = "";
  for (const s of sessions) {
    const li = document.createElement("li");
    if (s.id === activeId) li.classList.add("active");
    const label = document.createElement("span");
    label.textContent = s.display_name;
    label.style.cursor = "pointer";
    label.addEventListener("click", () => attach(s.id));
    const buttons = [label];
    if (me && me.role === "primary") {
      const share = document.createElement("button");
      share.className = "share-btn";
      share.textContent = "↪"; // ↪ share arrow
      share.title = "share session";
      share.addEventListener("click", (ev) => {
        ev.stopPropagation();
        openShareModal(s);
      });
      buttons.push(share);
    }
    const kill = document.createElement("button");
    kill.textContent = "×"; // ×
    kill.title = "kill session";
    kill.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      if (!confirm(`Kill "${s.display_name}"?`)) return;
      await fetch(`/api/sessions/${s.id}`, { method: "DELETE" });
      if (activeId === s.id) detach();
      refreshSessions();
    });
    buttons.push(kill);
    li.append(...buttons);
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

// ---- Share / grants UI (M4, primary-only) -------------------------------

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

async function openShareModal(session) {
  const [grantsRes, usersRes] = await Promise.all([
    fetch(`/api/permissions/session/${session.id}`),
    fetch(`/api/users`),
  ]);
  if (!grantsRes.ok || !usersRes.ok) {
    alert("Failed to load grants (are you the primary?)");
    return;
  }
  const { grants } = await grantsRes.json();
  const { users } = await usersRes.json();
  const grantsByEmail = new Map(grants.map((g) => [g.user_email, g.capabilities]));
  const secondaries = users.filter((u) => u.role !== "primary");

  const backdrop = document.createElement("div");
  backdrop.className = "share-modal__backdrop share-modal";
  backdrop.setAttribute("role", "dialog");
  backdrop.setAttribute("aria-labelledby", "share-title");

  const panel = document.createElement("div");
  panel.className = "share-modal__panel";
  panel.innerHTML = `
    <h2 id="share-title">Share &ldquo;${escapeHtml(session.display_name)}&rdquo;</h2>
    ${secondaries.length === 0
      ? `<p class="share-modal__empty">No secondary users yet. Add one in
         <a href="/admin/users.html" style="color:#6cf">/admin/users.html</a>.</p>`
      : `<table>
           <thead>
             <tr><th>User</th><th>Attach</th><th>Write</th><th>Manage</th></tr>
           </thead>
           <tbody></tbody>
         </table>`}
    <div class="share-modal__actions">
      <button type="button" data-act="cancel">Close</button>
      ${secondaries.length === 0
        ? ""
        : `<button type="button" class="primary" data-act="save">Save</button>`}
    </div>`;
  backdrop.append(panel);

  const tbody = panel.querySelector("tbody");
  if (tbody) {
    for (const u of secondaries) {
      const caps = grantsByEmail.get(u.email) ?? 0;
      const tr = document.createElement("tr");
      tr.dataset.email = u.email;
      tr.innerHTML = `
        <td>${escapeHtml(u.email)}</td>
        <td class="cap"><input type="checkbox" data-cap="1" ${caps & 1 ? "checked" : ""} aria-label="attach"></td>
        <td class="cap"><input type="checkbox" data-cap="2" ${caps & 2 ? "checked" : ""} aria-label="write"></td>
        <td class="cap"><input type="checkbox" data-cap="4" ${caps & 4 ? "checked" : ""} aria-label="manage"></td>`;
      tbody.append(tr);
    }
  }

  const close = () => backdrop.remove();
  panel.querySelector("[data-act=cancel]").addEventListener("click", close);
  backdrop.addEventListener("click", (ev) => { if (ev.target === backdrop) close(); });

  const saveBtn = panel.querySelector("[data-act=save]");
  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      saveBtn.disabled = true;
      try {
        for (const tr of tbody.querySelectorAll("tr")) {
          const email = tr.dataset.email;
          let mask = 0;
          for (const cb of tr.querySelectorAll("input[data-cap]")) {
            if (cb.checked) mask |= Number(cb.dataset.cap);
          }
          const prior = grantsByEmail.get(email) ?? 0;
          if (mask === prior) continue;
          if (mask === 0) {
            await fetch(
              `/api/permissions/session/${session.id}/${encodeURIComponent(email)}`,
              { method: "DELETE" }
            );
          } else {
            await fetch(`/api/permissions/session/${session.id}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ user_email: email, capabilities: mask }),
            });
          }
        }
        close();
      } finally {
        saveBtn.disabled = false;
      }
    });
  }

  document.body.append(backdrop);
}
