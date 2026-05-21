//! In-memory store of "we issued challenge X for email Y at time Z".
//! 5-min TTL. Single-process; if we ever shard the server, move to SQLite.

use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Default)]
pub struct ChallengeStore {
    inner: Arc<Mutex<HashMap<String, Entry>>>, // key = b64(challenge); value = (email, issued)
}

struct Entry {
    email: String,
    issued: Instant,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn issue(&self, email: &str) -> (Vec<u8>, String) {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let mut g = self.inner.lock().await;
        Self::gc_locked(&mut g);
        g.insert(
            b64.clone(),
            Entry {
                email: email.to_string(),
                issued: Instant::now(),
            },
        );
        (bytes.to_vec(), b64)
    }

    /// Returns the email the challenge was issued for, if valid and unconsumed.
    pub async fn consume(&self, challenge_b64: &str) -> Option<String> {
        let mut g = self.inner.lock().await;
        Self::gc_locked(&mut g);
        let entry = g.remove(challenge_b64)?;
        if entry.issued.elapsed() > TTL {
            return None;
        }
        Some(entry.email)
    }

    fn gc_locked(g: &mut HashMap<String, Entry>) {
        g.retain(|_, e| e.issued.elapsed() <= TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issue_and_consume_once() {
        let s = ChallengeStore::new();
        let (_raw, b64) = s.issue("a@b").await;
        assert_eq!(s.consume(&b64).await.as_deref(), Some("a@b"));
        assert_eq!(s.consume(&b64).await, None, "single-use only");
    }

    #[tokio::test]
    async fn unknown_returns_none() {
        let s = ChallengeStore::new();
        assert_eq!(s.consume("never-issued").await, None);
    }
}
