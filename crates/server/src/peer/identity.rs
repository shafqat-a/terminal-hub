//! Per-instance ed25519 peer identity.
//!
//! On first boot, generate a fresh keypair and write `peer_id` (mode 0600) and
//! `peer_id.pub` (base64-encoded raw pubkey bytes) into the config dir. On
//! subsequent boots, load the existing keys. Refuse to start if `peer_id` is
//! group/world-readable.
//!
//! The pubkey file format is the bare 32-byte ed25519 public key, base64
//! (standard alphabet, with padding) on a single line. This is *not* the
//! OpenSSH pubkey format that `auth-core` consumes — the federation identity
//! is intentionally distinct from any user SSH identity.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::OsRng;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid base64: {0}")]
    B64(#[from] base64::DecodeError),
    #[error("malformed peer_id file (expected 32 bytes, got {0})")]
    KeyLen(usize),
    #[error("malformed peer_id.pub (expected 32 bytes, got {0})")]
    PubLen(usize),
    #[error("ed25519: {0}")]
    Ed(#[from] ed25519_dalek::SignatureError),
    #[error("refusing to start: {0} has insecure permissions (mode {1:o}); chmod 600 it")]
    Perms(PathBuf, u32),
}

/// In-memory representation of the loaded (or freshly generated) peer identity.
#[derive(Clone)]
pub struct PeerIdentity {
    signing: SigningKey,
    verifying: VerifyingKey,
    pub_b64: String,
}

impl PeerIdentity {
    /// Load `peer_id` + `peer_id.pub` from `config_dir`, or generate and write
    /// them on first boot. Idempotent: re-running with the same directory
    /// returns the same keypair.
    pub fn ensure(config_dir: &Path) -> Result<Self, Error> {
        let priv_path = config_dir.join("peer_id");
        let pub_path = config_dir.join("peer_id.pub");

        let signing = match fs::read_to_string(&priv_path) {
            Ok(text) => {
                check_secure_perms(&priv_path)?;
                let bytes = B64.decode(text.trim())?;
                if bytes.len() != 32 {
                    return Err(Error::KeyLen(bytes.len()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                SigningKey::from_bytes(&arr)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let sk = SigningKey::generate(&mut OsRng);
                let encoded = B64.encode(sk.to_bytes());
                fs::create_dir_all(config_dir)?;
                fs::write(&priv_path, encoded)?;
                set_owner_only(&priv_path)?;
                sk
            }
            Err(e) => return Err(Error::Io(e)),
        };

        let verifying = signing.verifying_key();
        let pub_bytes = verifying.to_bytes();
        let pub_b64 = B64.encode(pub_bytes);

        // Re-write the pubkey file unconditionally — it's derivable from the
        // private key, and harmless if it had drifted.
        fs::write(&pub_path, &pub_b64)?;

        Ok(Self {
            signing,
            verifying,
            pub_b64,
        })
    }

    /// Base64 (standard, padded) encoding of the 32-byte ed25519 public key.
    pub fn pub_b64(&self) -> &str {
        &self.pub_b64
    }

    /// Raw 32 bytes of the public key.
    pub fn pub_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    pub fn verifying(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// Sign an arbitrary challenge with this peer's private key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    /// Verify a signature produced by some other peer.
    pub fn verify(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        if pub_bytes.len() != 32 {
            return Err(Error::PubLen(pub_bytes.len()));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(pub_bytes);
        let vk = VerifyingKey::from_bytes(&k)?;
        let s = Signature::from_slice(sig)?;
        vk.verify(msg, &s)?;
        Ok(())
    }
}

#[cfg(unix)]
fn check_secure_perms(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Perms(path.to_path_buf(), mode));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secure_perms(_: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_and_reloads_same_key() {
        let dir = tempdir().unwrap();
        let a = PeerIdentity::ensure(dir.path()).unwrap();
        let b = PeerIdentity::ensure(dir.path()).unwrap();
        assert_eq!(a.pub_b64(), b.pub_b64());
        assert_eq!(a.pub_bytes(), b.pub_bytes());
    }

    #[test]
    fn sign_round_trip() {
        let dir = tempdir().unwrap();
        let id = PeerIdentity::ensure(dir.path()).unwrap();
        let msg = b"hello federation";
        let sig = id.sign(msg);
        assert!(PeerIdentity::verify(id.verifying().as_bytes(), msg, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn rejects_wrong_signature() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = PeerIdentity::ensure(dir_a.path()).unwrap();
        let id_b = PeerIdentity::ensure(dir_b.path()).unwrap();
        let msg = b"federation message";
        // Sign with A's key, attempt to verify against B's pubkey.
        let sig = id_a.sign(msg);
        assert!(PeerIdentity::verify(id_b.verifying().as_bytes(), msg, &sig.to_bytes()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        PeerIdentity::ensure(dir.path()).unwrap();
        std::fs::set_permissions(
            dir.path().join("peer_id"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let res = PeerIdentity::ensure(dir.path());
        match res {
            Err(Error::Perms(_, 0o644)) => {}
            Err(other) => panic!("expected Error::Perms(_, 0o644), got {other}"),
            Ok(_) => panic!("expected ensure() to fail on world-readable key"),
        }
    }
}
