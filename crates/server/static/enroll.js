const b64u = {
  decode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  },
  encode(buf) {
    const s = btoa(String.fromCharCode(...new Uint8Array(buf)));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

function prepCreate(ccr) {
  const o = ccr.publicKey;
  o.challenge = b64u.decode(o.challenge);
  o.user.id = b64u.decode(o.user.id);
  if (o.excludeCredentials) {
    o.excludeCredentials = o.excludeCredentials.map(c => ({ ...c, id: b64u.decode(c.id) }));
  }
  return o;
}

function serializeAttestation(cred) {
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64u.encode(cred.response.clientDataJSON),
      attestationObject: b64u.encode(cred.response.attestationObject),
    },
    extensions: cred.getClientExtensionResults(),
  };
}

const params = new URLSearchParams(location.search);
const token = params.get("t");
const msg = document.getElementById("msg");
const btn = document.getElementById("register");

if (!token) {
  msg.textContent = "Missing bootstrap token. Run `terminal-hub-cli enroll` again.";
  btn.disabled = true;
}

btn.addEventListener("click", async () => {
  msg.textContent = "";
  btn.disabled = true;
  try {
    const startRes = await fetch(`/auth/passkey/register/start?t=${encodeURIComponent(token)}`);
    if (!startRes.ok) throw new Error(await startRes.text());
    const { registration_id, ccr } = await startRes.json();

    const cred = await navigator.credentials.create({ publicKey: prepCreate(ccr) });
    if (!cred) throw new Error("user cancelled");

    const finishRes = await fetch("/auth/passkey/register/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ registration_id, credential: serializeAttestation(cred) }),
    });
    if (!finishRes.ok) throw new Error(await finishRes.text());
    msg.className = "ok";
    msg.textContent = "Passkey registered. Redirecting to sign-in…";
    setTimeout(() => { location.href = "/login.html"; }, 1500);
  } catch (e) {
    btn.disabled = false;
    msg.className = "err";
    msg.textContent = e.message || String(e);
  }
});
