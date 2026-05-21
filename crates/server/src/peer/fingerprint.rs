//! Peer pubkey / TLS cert fingerprint helper.
//!
//! Format: 12-char SHA-256 truncated to three 4-char hex groups, lowercase,
//! separated by colons: `xxxx:xxxx:xxxx`. Short enough to read out over the
//! phone when verifying a new peer out-of-band (per spec §9.1).
//!
//! This is distinct from `auth_core::pubkey_fingerprint` which emits the full
//! 256-bit hash as base64 — that one is for audit logging of SSH-style user
//! identities, not human-eyeball verification of federation peers.

use sha2::{Digest, Sha256};

/// SHA-256 of `bytes`, truncated to 12 hex chars, formatted `xxxx:xxxx:xxxx`.
pub fn fingerprint_b64(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().take(6).map(|b| format!("{:02x}", b)).collect();
    format!("{}:{}:{}", &hex[0..4], &hex[4..8], &hex[8..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_across_calls() {
        let bytes = b"some-pubkey-bytes";
        assert_eq!(fingerprint_b64(bytes), fingerprint_b64(bytes));
    }

    #[test]
    fn differs_for_different_inputs() {
        assert_ne!(fingerprint_b64(b"alpha"), fingerprint_b64(b"beta"));
    }

    #[test]
    fn formatted_as_three_4char_hex_groups() {
        let fp = fingerprint_b64(b"any input");
        // 12 hex chars + 2 colons = 14 total
        assert_eq!(fp.len(), 14);
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 3);
        for p in parts {
            assert_eq!(p.len(), 4);
            assert!(p.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn matches_known_vector() {
        // SHA-256 of "" starts e3b0c44298fc...; first 12 hex chars = "e3b0c44298fc".
        assert_eq!(fingerprint_b64(b""), "e3b0:c442:98fc");
    }
}
