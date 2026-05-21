//! Peer federation: identity, fingerprints, and inbound/outbound config.
//!
//! M5 Task 1-4 scope. Subsequent tasks add the inbound `/peer/challenge` and
//! `/peer/auth` handlers and the outbound TLS-pinned `PeerClient`.

pub mod fingerprint;
pub mod identity;
