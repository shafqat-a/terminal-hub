//! Verifies SSH-key signatures over an opaque challenge bytestring.
//!
//! Used by:
//!   - server: parses stored OpenSSH pubkey, verifies signature on POST /auth/enroll/initiate
//!   - CLI:    parses local OpenSSH privkey or asks ssh-agent to sign
//!
//! The "challenge" is 32 random bytes. The signed payload is
//! `b"terminal-hub-enroll\0" || challenge` to prevent the signature from being
//! usable as proof-of-possession for a different protocol.

use base64::Engine;
use sha2::{Digest, Sha256};
use ssh_key::PublicKey;

pub const SIG_DOMAIN: &[u8] = b"terminal-hub-enroll\0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh-key parse: {0}")]
    Parse(#[from] ssh_key::Error),
    #[error("unsupported key algorithm: {0}")]
    UnsupportedAlgo(String),
    #[error("signature verification failed")]
    BadSig,
    #[error("base64: {0}")]
    B64(#[from] base64::DecodeError),
    #[error("ed25519: {0}")]
    Ed(#[from] ed25519_dalek::SignatureError),
}

/// `payload(challenge)` is what gets signed. Exposed so the CLI signs the same bytes.
pub fn payload(challenge: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_DOMAIN.len() + challenge.len());
    v.extend_from_slice(SIG_DOMAIN);
    v.extend_from_slice(challenge);
    v
}

/// SHA-256 fingerprint of the OpenSSH pubkey wire encoding, b64-no-pad. Audit/debug only.
pub fn pubkey_fingerprint(openssh: &str) -> Result<String, Error> {
    let pk = PublicKey::from_openssh(openssh)?;
    // Hash the SSH wire-format encoding of the public key. We use
    // `to_openssh` to get the canonical "ssh-ed25519 <b64> ..." string,
    // then re-decode the b64 chunk; ssh-key 0.6 doesn't expose a
    // public `to_bytes()` on `KeyData` for all variants.
    let openssh_line = pk.to_openssh()?;
    let b64_chunk = openssh_line.split_whitespace().nth(1).unwrap_or_default();
    let wire = base64::engine::general_purpose::STANDARD
        .decode(b64_chunk.as_bytes())
        .map_err(Error::B64)?;
    let mut h = Sha256::new();
    h.update(&wire);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize()))
}

/// Verify a raw signature blob (algorithm-specific encoding) against `payload(challenge)`.
///
/// We only support ssh-ed25519 in M3. RSA support is a fast follow.
pub fn verify(openssh_pubkey: &str, challenge: &[u8], signature: &[u8]) -> Result<(), Error> {
    let pk = PublicKey::from_openssh(openssh_pubkey)?;
    match pk.key_data() {
        ssh_key::public::KeyData::Ed25519(ed) => {
            let bytes: [u8; 32] = ed.0.as_ref().try_into().map_err(|_| Error::BadSig)?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
            let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::BadSig)?;
            vk.verify_strict(&payload(challenge), &sig)
                .map_err(|_| Error::BadSig)?;
            Ok(())
        }
        other => Err(Error::UnsupportedAlgo(format!("{:?}", other.algorithm()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::RngCore;

    fn make_ed25519_keypair() -> (ed25519_dalek::SigningKey, String) {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk_bytes = sk.verifying_key().to_bytes();
        let ssh_pub = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(vk_bytes));
        let openssh = ssh_pub.to_openssh().unwrap();
        (sk, openssh)
    }

    #[test]
    fn roundtrip_ed25519() {
        let (sk, openssh) = make_ed25519_keypair();
        let challenge = [7u8; 32];
        let sig = sk.sign(&payload(&challenge));
        verify(&openssh, &challenge, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn rejects_wrong_challenge() {
        let (sk, openssh) = make_ed25519_keypair();
        let sig = sk.sign(&payload(&[1u8; 32]));
        assert!(verify(&openssh, &[2u8; 32], &sig.to_bytes()).is_err());
    }

    #[test]
    fn fingerprint_is_stable() {
        let (_sk, openssh) = make_ed25519_keypair();
        assert_eq!(
            pubkey_fingerprint(&openssh).unwrap(),
            pubkey_fingerprint(&openssh).unwrap()
        );
    }
}
