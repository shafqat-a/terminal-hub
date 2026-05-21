// Admin: user management. Primary-only by virtue of the underlying
// /api/users routes being RequirePrimary-gated; on 403 we render a friendly
// "Primary user only" message instead of the table.

const errEl = document.getElementById("err");
const okEl = document.getElementById("ok");
const tableEl = document.getElementById("user-table");
const rowsEl = document.getElementById("user-rows");
const formEl = document.getElementById("add-form");

function showError(msg) {
  errEl.textContent = msg || "";
  if (msg) okEl.textContent = "";
}
function showOk(msg) {
  okEl.textContent = msg || "";
  if (msg) errEl.textContent = "";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

async function refresh() {
  showError("");
  showOk("");
  const r = await fetch("/api/users");
  if (r.status === 401) {
    window.location = "/login.html";
    return;
  }
  if (r.status === 403) {
    tableEl.style.display = "none";
    formEl.style.display = "none";
    showError("Primary user only. Sign in as the primary user to manage users.");
    return;
  }
  if (!r.ok) {
    showError(`Failed: ${r.status}`);
    return;
  }
  tableEl.style.display = "";
  formEl.style.display = "";
  const { users } = await r.json();
  rowsEl.innerHTML = "";
  for (const u of users) {
    const tr = document.createElement("tr");
    const removeCell =
      u.role === "primary"
        ? "<td></td>"
        : `<td><button class="admin-btn admin-btn--danger" data-email="${escapeHtml(
            u.email,
          )}">Remove</button></td>`;
    tr.innerHTML = `
      <td>${escapeHtml(u.email)}</td>
      <td>${escapeHtml(u.role)}</td>
      <td>${u.passkey_registered ? "yes" : "no"}</td>
      ${removeCell}`;
    rowsEl.append(tr);
  }
  for (const btn of rowsEl.querySelectorAll("button[data-email]")) {
    btn.addEventListener("click", async () => {
      const email = btn.dataset.email;
      if (
        !confirm(
          `Remove ${email}? Their session cookies and per-session grants will be deleted immediately.`,
        )
      ) {
        return;
      }
      const r = await fetch(`/api/users/${encodeURIComponent(email)}`, {
        method: "DELETE",
      });
      if (!r.ok) {
        showError(`Remove failed: ${r.status} ${await r.text()}`);
        return;
      }
      showOk(`Removed ${email}.`);
      refresh();
    });
  }
}

formEl.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  showError("");
  showOk("");
  const email = document.getElementById("add-email").value.trim();
  const pubkey = document.getElementById("add-pubkey").value.trim();
  if (!pubkey.startsWith("ssh-") && !pubkey.startsWith("ecdsa-")) {
    showError("Public key must be in OpenSSH single-line format (e.g. ssh-ed25519 AAAA...).");
    return;
  }
  const r = await fetch("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, pubkey }),
  });
  if (!r.ok) {
    showError(`Add failed: ${r.status} ${await r.text()}`);
    return;
  }
  document.getElementById("add-email").value = "";
  document.getElementById("add-pubkey").value = "";
  showOk(`Added ${email}. Have them enroll a passkey from their laptop via the M3 CLI.`);
  refresh();
});

refresh();
