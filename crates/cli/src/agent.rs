//! Tiny wrapper over `ssh-agent-client-rs`. Connects via `$SSH_AUTH_SOCK`,
//! lists identities, asks the agent to sign `payload` with the public key
//! whose openssh wire form matches `wanted_openssh`.
//!
//! Fallback (reading a private key file) is documented as "later enhancement"
//! per the M3 plan; we hard-fail with a clear message if the agent has no
//! matching key.

use anyhow::{anyhow, bail, Context, Result};
use ssh_agent_client_rs::Client;
use std::path::PathBuf;

/// Sign `payload` with the identity in `ssh-agent` whose OpenSSH-encoded public
/// key matches `wanted_openssh`. Returns the raw 64-byte ed25519 signature.
pub fn sign_with_agent(wanted_openssh: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let sock = std::env::var("SSH_AUTH_SOCK")
        .map_err(|_| anyhow!("SSH_AUTH_SOCK is not set; start ssh-agent or `ssh-add` your key"))?;
    let mut client = Client::connect(PathBuf::from(sock).as_path())
        .context("connecting to ssh-agent")?;
    let want = ssh_key::PublicKey::from_openssh(wanted_openssh).context("parsing target pubkey")?;
    let identities = client
        .list_identities()
        .context("ssh-agent list identities")?;
    let matched = identities
        .into_iter()
        .find(|id| id.key_data() == want.key_data())
        .ok_or_else(|| {
            anyhow!(
                "ssh-agent has no key matching the pubkey on file. \
                 Try `ssh-add ~/.ssh/id_ed25519` and re-run."
            )
        })?;
    let sig = client.sign(&matched, payload).context("ssh-agent sign")?;
    extract_ed25519_raw(&sig)
}

/// `ssh-key` 0.6 `Signature::as_bytes()` returns the raw algorithm-specific bytes.
/// For ed25519 that's exactly 64 bytes; reject anything else.
fn extract_ed25519_raw(sig: &ssh_key::Signature) -> Result<Vec<u8>> {
    let algo = sig.algorithm();
    if algo != ssh_key::Algorithm::Ed25519 {
        bail!("unsupported signature algorithm: {algo:?}");
    }
    let bytes = sig.as_bytes();
    if bytes.len() != 64 {
        bail!("expected 64-byte ed25519 signature, got {}", bytes.len());
    }
    Ok(bytes.to_vec())
}
