//! Per-key (client IP) login throttling. Go parity: after `max_attempts`
//! failures within `window`, lock out for base * 2^offence, capped at
//! 16 * base. Success resets everything. max_attempts == 0 disables.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_LOCKOUT_MULTIPLIER: u32 = 16;

#[derive(Default)]
struct Entry {
    failures: Vec<Instant>,
    offences: u32,
    locked_until: Option<Instant>,
}

pub struct RateLimiter {
    max_attempts: u32,
    window: Duration,
    base_lockout: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window: Duration, base_lockout: Duration) -> Self {
        RateLimiter {
            max_attempts,
            window,
            base_lockout,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn enabled(&self) -> bool {
        self.max_attempts > 0
    }

    pub fn allowed(&self, key: &str) -> (bool, Duration) {
        self.allowed_at(key, Instant::now())
    }

    pub fn allowed_at(&self, key: &str, now: Instant) -> (bool, Duration) {
        if !self.enabled() {
            return (true, Duration::ZERO);
        }
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(key).and_then(|e| e.locked_until) {
            Some(until) if until > now => (false, until - now),
            _ => (true, Duration::ZERO),
        }
    }

    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now())
    }

    pub fn record_failure_at(&self, key: &str, now: Instant) {
        if !self.enabled() {
            return;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        const SWEEP_THRESHOLD: usize = 1024;
        if entries.len() >= SWEEP_THRESHOLD {
            Self::sweep(&mut entries, self.window, now);
        }

        let entry = entries.entry(key.to_string()).or_default();

        // Failures during an active lockout do not count -- prevents offence
        // ratcheting if a caller records without checking allowed() first.
        if let Some(until) = entry.locked_until {
            if until > now {
                return;
            }
        }

        entry
            .failures
            .retain(|t| now.duration_since(*t) < self.window);
        entry.failures.push(now);
        if entry.failures.len() as u32 >= self.max_attempts {
            let multiplier = 1u32
                .checked_shl(entry.offences)
                .unwrap_or(MAX_LOCKOUT_MULTIPLIER)
                .min(MAX_LOCKOUT_MULTIPLIER);
            entry.locked_until = Some(now + self.base_lockout * multiplier);
            entry.offences += 1;
            entry.failures.clear();
        }
    }

    pub fn reset(&self, key: &str) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    /// Drop entries with no recent failures and no active lockout. Called
    /// opportunistically so the map cannot grow unboundedly under IP-rotation
    /// attacks.
    fn sweep(entries: &mut HashMap<String, Entry>, window: Duration, now: Instant) {
        entries.retain(|_, e| {
            let locked = e.locked_until.is_some_and(|until| until > now);
            let recent = e.failures.iter().any(|t| now.duration_since(*t) < window);
            locked || recent
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const WINDOW: Duration = Duration::from_secs(60);
    const BASE: Duration = Duration::from_secs(60);

    fn limiter() -> RateLimiter {
        RateLimiter::new(3, WINDOW, BASE)
    }

    #[test]
    fn allowed_until_max_attempts_reached() {
        let rl = limiter();
        let t0 = Instant::now();
        for _ in 0..2 {
            assert!(rl.allowed_at("ip1", t0).0);
            rl.record_failure_at("ip1", t0);
        }
        assert!(rl.allowed_at("ip1", t0).0); // 2 failures < 3
        rl.record_failure_at("ip1", t0); // 3rd failure triggers lockout
        let (ok, retry) = rl.allowed_at("ip1", t0);
        assert!(!ok);
        assert_eq!(retry, BASE);
    }

    #[test]
    fn lockout_doubles_per_offence_capped_at_16x() {
        let rl = limiter();
        let mut t = Instant::now();
        for mult in [1u32, 2, 4, 8, 16, 16] {
            for _ in 0..3 {
                rl.record_failure_at("ip1", t);
            }
            let (ok, retry) = rl.allowed_at("ip1", t);
            assert!(!ok);
            assert_eq!(retry, BASE * mult, "offence multiplier {mult}");
            t += retry; // wait out the lockout
            assert!(rl.allowed_at("ip1", t).0);
        }
    }

    #[test]
    fn failures_outside_window_do_not_count() {
        let rl = limiter();
        let t0 = Instant::now();
        rl.record_failure_at("ip1", t0);
        rl.record_failure_at("ip1", t0);
        // Third failure arrives after the window has passed -- no lockout.
        let later = t0 + WINDOW + Duration::from_secs(1);
        rl.record_failure_at("ip1", later);
        assert!(rl.allowed_at("ip1", later).0);
    }

    #[test]
    fn reset_clears_failures_and_offences() {
        let rl = limiter();
        let t0 = Instant::now();
        for _ in 0..3 {
            rl.record_failure_at("ip1", t0);
        }
        assert!(!rl.allowed_at("ip1", t0).0);
        rl.reset("ip1");
        assert!(rl.allowed_at("ip1", t0).0);
        // Offence count also cleared: next lockout is base again.
        for _ in 0..3 {
            rl.record_failure_at("ip1", t0);
        }
        assert_eq!(rl.allowed_at("ip1", t0).1, BASE);
    }

    #[test]
    fn keys_are_independent() {
        let rl = limiter();
        let t0 = Instant::now();
        for _ in 0..3 {
            rl.record_failure_at("ip1", t0);
        }
        assert!(rl.allowed_at("ip2", t0).0);
    }

    #[test]
    fn zero_max_attempts_disables_limiting() {
        let rl = RateLimiter::new(0, WINDOW, BASE);
        let t0 = Instant::now();
        for _ in 0..100 {
            rl.record_failure_at("ip1", t0);
        }
        assert!(rl.allowed_at("ip1", t0).0);
    }

    #[test]
    fn stale_entries_are_swept_when_map_grows() {
        let rl = limiter();
        let t0 = Instant::now();
        // 1024 distinct stale keys (single failure each, then window passes)
        for i in 0..1024 {
            rl.record_failure_at(&format!("ip-{i}"), t0);
        }
        let later = t0 + WINDOW + Duration::from_secs(1);
        // Next failure triggers the sweep; stale entries vanish.
        rl.record_failure_at("fresh", later);
        assert!(rl.entries.lock().unwrap().len() <= 2);
    }

    #[test]
    fn failures_during_lockout_do_not_ratchet_offences() {
        let rl = limiter();
        let t0 = Instant::now();
        for _ in 0..3 {
            rl.record_failure_at("ip1", t0);
        }
        assert!(!rl.allowed_at("ip1", t0).0); // locked, base lockout
                                              // Hammering during the lockout must not escalate the offence level.
        for _ in 0..10 {
            rl.record_failure_at("ip1", t0);
        }
        let after_first = t0 + BASE + Duration::from_secs(1);
        assert!(rl.allowed_at("ip1", after_first).0); // lockout over, not extended
                                                      // Next lockout doubles exactly once (offence 1 -> 2x), proving no ratcheting happened.
        for _ in 0..3 {
            rl.record_failure_at("ip1", after_first);
        }
        assert_eq!(rl.allowed_at("ip1", after_first).1, BASE * 2);
    }
}
