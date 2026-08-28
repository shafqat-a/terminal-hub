//! Small shared helpers with no better home.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in whole seconds.
pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_secs() as i64
}

/// Current unix time in whole milliseconds (chat turns need sub-second order).
pub(crate) fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_millis() as i64
}
