//! Outbound HTTP client for talking to a federated peer.
//!
//! Security posture (MVP, M5):
//!
//! Peer identity is established cryptographically via the `/peer/challenge`
//! and `/peer/auth` handshake (ed25519 signature on a fresh challenge). That
//! handshake is forge-proof regardless of what TLS does.
//!
//! The TLS cert presented by the peer is currently NOT pinned — the client
//! accepts any self-signed cert via `danger_accept_invalid_certs(true)`. An
//! active network MitM on the peer's LAN can still observe and modify the
//! bytes flowing between A and B, even though they can't impersonate B's
//! peer key.
//!
//! For the M5 small-fleet homelab scenario this tradeoff is accepted; the
//! spec's §10 cert pinning requirement is tracked as a security follow-up.
//! When wired, the pinning will use `rustls::client::danger::ServerCertVerifier`
//! to match SHA-256(leaf_der) against `tls_cert_fp` from `peers.toml`.

use std::time::Duration;

/// Build a `reqwest::Client` configured for talking to a federated peer.
///
/// `_peer_pubkey` and `_tls_cert_fp` are accepted so callers can pass them
/// today; once true pinning lands they will be consumed inside a custom
/// rustls verifier. Until then we log a warning so the deferred posture
/// is visible in operator logs.
pub fn build_client(_peer_pubkey: &str, tls_cert_fp: &str) -> reqwest::Client {
    if !tls_cert_fp.is_empty() {
        tracing::warn!(
            tls_cert_fp = tls_cert_fp,
            "TLS cert pinning NOT enforced in MVP — peer-key handshake provides identity"
        );
    }
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_without_panicking() {
        let _c = build_client("ignored-pubkey", "aaaa:bbbb:cccc");
    }
}
