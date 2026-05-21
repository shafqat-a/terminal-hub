pub mod bootstrap;
pub mod challenge;

/// Hash a cookie value (or any opaque secret) with SHA-256 for storage in the DB.
/// We don't need argon2 here because the secret is full-entropy (32 random bytes
/// b64-encoded); salting buys nothing.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}
