pub mod ratelimit;

use bcrypt::{hash, verify, DEFAULT_COST};
use rand::RngCore;

pub const COOKIE_NAME: &str = "ai_conductor_session";

/// Bcrypt-hashes the configured password once at startup; verification
/// thereafter (Go parity: bcrypt password hashing).
pub struct AuthService {
    password_hash: String,
}

impl AuthService {
    pub fn new(password: &str) -> Self {
        AuthService {
            password_hash: hash(password, DEFAULT_COST).expect("bcrypt hash cannot fail"),
        }
    }

    pub fn verify_password(&self, candidate: &str) -> bool {
        verify(candidate, &self.password_hash).unwrap_or(false)
    }
}

/// 32 random bytes, lowercase hex — identical to Go GenerateSessionToken.
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
