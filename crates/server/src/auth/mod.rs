pub mod middleware;
pub mod ratelimit;

use bcrypt::{hash, verify};
use rand::RngCore;

pub const COOKIE_NAME: &str = "ai_conductor_session";

/// Go parity: golang.org/x/crypto/bcrypt DefaultCost is 10 (Rust crate default
/// is 12, ~4x slower per login).
const BCRYPT_COST: u32 = 10;

/// Bcrypt-hashes the configured password once at startup; verification
/// thereafter (Go parity: bcrypt password hashing).
pub struct AuthService {
    password_hash: String,
}

impl AuthService {
    pub fn new(password: &str) -> Self {
        AuthService {
            password_hash: hash(password, BCRYPT_COST).expect(
                "bcrypt hash failed (password longer than 72 bytes, or OS entropy unavailable)",
            ),
        }
    }

    pub fn verify_password(&self, candidate: &str) -> bool {
        verify(candidate, &self.password_hash).unwrap_or(false)
    }

    /// Async wrapper: bcrypt verify takes ~100ms at cost 10 — offload to the
    /// blocking pool so login storms can't starve the async runtime.
    pub async fn verify_password_async(&self, candidate: &str) -> bool {
        let hash = self.password_hash.clone();
        let candidate = candidate.to_string();
        tokio::task::spawn_blocking(move || verify(&candidate, &hash).unwrap_or(false))
            .await
            .unwrap_or(false)
    }
}

/// 32 random bytes, lowercase hex -- identical to Go GenerateSessionToken.
pub fn generate_session_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_password_verifies() {
        let svc = AuthService::new("hunter2");
        assert!(svc.verify_password("hunter2"));
    }

    #[test]
    fn wrong_password_fails() {
        let svc = AuthService::new("hunter2");
        assert!(!svc.verify_password("hunter3"));
        assert!(!svc.verify_password(""));
    }

    #[test]
    fn tokens_are_64_hex_chars_and_unique() {
        let a = generate_session_token();
        let b = generate_session_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
