// Base64URL helpers — WebAuthn passes raw bytes as base64url-without-padding.
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

// webauthn-rs serializes ArrayBuffers as base64url strings inside JSON.
// We need to walk known keys and convert them to actual ArrayBuffers before
// handing the structure to navigator.credentials.get().
function prepRequest(rcr) {
  const o = rcr.publicKey;
  o.challenge = b64u.decode(o.challenge);
  if (o.allowCredentials) {
    o.allowCredentials = o.allowCredentials.map(c => ({ ...c, id: b64u.decode(c.id) }));
  }
  return o;
}

function serializeAssertion(cred) {
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64u.encode(cred.response.clientDataJSON),
      authenticatorData: b64u.encode(cred.response.authenticatorData),
      signature: b64u.encode(cred.response.signature),
      userHandle: cred.response.userHandle ? b64u.encode(cred.response.userHandle) : null,
    },
    extensions: cred.getClientExtensionResults(),
  };
}

const form = document.getElementById("login-form");
const msg = document.getElementById("msg");

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  msg.textContent = "";
  const email = document.getElementById("email").value.trim();
  try {
    const startRes = await fetch("/auth/passkey/login/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (!startRes.ok) throw new Error(await startRes.text());
    const { auth_id, rcr } = await startRes.json();

    const assertion = await navigator.credentials.get({ publicKey: prepRequest(rcr) });
    if (!assertion) throw new Error("no credential returned");

    const finishRes = await fetch("/auth/passkey/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auth_id, credential: serializeAssertion(assertion) }),
    });
    if (!finishRes.ok) throw new Error(await finishRes.text());
    location.href = "/";
  } catch (e) {
    msg.textContent = e.message || String(e);
  }
});
