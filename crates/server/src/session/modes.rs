//! DEC private mode tracking for reconnect replay (spec §4.3).
//!
//! The PTY output stream carries `CSI ? Pm h` (set) and `CSI ? Pm l` (reset)
//! sequences that put the client terminal into modes xterm.js must re-enter
//! after a reconnect or lag-resync (bracketed paste, mouse reporting, alt
//! screen, ...). The scanner is a byte state machine fed from the PTY read
//! loop; sequences may be split across read chunks, so all parser state
//! persists between `feed` calls.
//!
//! Only DEC *private* set/reset (`CSI ?`) is interpreted. Non-private CSI,
//! untracked private modes, and malformed sequences are consumed without
//! effect.

use std::fmt::Write as _;

/// Modes replayed on attach/resync, in replay order: DECCKM, alt screen
/// variants, mouse reporting, focus reporting, bracketed paste, sync output.
/// `CSI ? 1049 h` itself performs cursor-save + alt-screen + clear, so
/// replaying the set sequence as-is reproduces the full effect.
const TRACKED_MODES: [u16; 12] = [
    1, 47, 1047, 1049, 1000, 1002, 1003, 1005, 1006, 1004, 2004, 2026,
];

/// Parameter list bound: real mode sequences carry a handful of params;
/// anything longer is hostile output and extra params are dropped.
const MAX_PARAMS: usize = 16;

const ESC: u8 = 0x1b;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanState {
    /// Plain output; waiting for ESC.
    Ground,
    /// Saw ESC; `[` starts a CSI sequence.
    Esc,
    /// Saw CSI; `?` selects private params, anything else is not ours.
    Csi,
    /// Inside `CSI ?`; accumulating digit/`;` params until `h`/`l`.
    PrivateParam,
    /// Inside a CSI sequence we don't interpret; consume until the final byte.
    SkipToFinal,
}

/// Per-session mode tracker: scanner state + the set of active tracked modes.
pub struct ModeState {
    state: ScanState,
    params: Vec<u32>,
    cur: u32,
    has_cur: bool,
    active: [bool; TRACKED_MODES.len()],
}

impl Default for ModeState {
    fn default() -> Self {
        ModeState {
            state: ScanState::Ground,
            params: Vec::new(),
            cur: 0,
            has_cur: false,
            active: [false; TRACKED_MODES.len()],
        }
    }
}

impl ModeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan a chunk of PTY output. Chunk boundaries are arbitrary; partial
    /// sequences resume on the next call.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.step(b);
        }
    }

    /// Concatenated `CSI ? Pm h` re-asserts for every active mode, in
    /// TRACKED_MODES order. Empty string when no mode is active.
    pub fn reassert_sequence(&self) -> String {
        let mut out = String::new();
        for (i, &m) in TRACKED_MODES.iter().enumerate() {
            if self.active[i] {
                write!(out, "\x1b[?{m}h").expect("write to String cannot fail");
            }
        }
        out
    }

    fn step(&mut self, b: u8) {
        // ESC always restarts sequence recognition (a real terminal treats it
        // as cancelling whatever was in flight).
        if b == ESC {
            self.state = ScanState::Esc;
            return;
        }
        match self.state {
            ScanState::Ground => {}
            ScanState::Esc => {
                self.state = if b == b'[' {
                    self.params.clear();
                    self.cur = 0;
                    self.has_cur = false;
                    ScanState::Csi
                } else {
                    ScanState::Ground
                };
            }
            ScanState::Csi => {
                self.state = match b {
                    b'?' => ScanState::PrivateParam,
                    // Final byte right away (e.g. `CSI H`) — not private, done.
                    0x40..=0x7e => ScanState::Ground,
                    // Non-private params/intermediates — ignore the body.
                    _ => ScanState::SkipToFinal,
                };
            }
            ScanState::PrivateParam => match b {
                b'0'..=b'9' => {
                    self.cur = self
                        .cur
                        .saturating_mul(10)
                        .saturating_add(u32::from(b - b'0'));
                    self.has_cur = true;
                }
                b';' => self.push_param(),
                b'h' => {
                    self.push_param();
                    self.apply(true);
                    self.state = ScanState::Ground;
                }
                b'l' => {
                    self.push_param();
                    self.apply(false);
                    self.state = ScanState::Ground;
                }
                // Other final byte (`CSI ? Pm r`, `s`, ...) — not set/reset.
                0x40..=0x7e => self.state = ScanState::Ground,
                // Garbage inside the params (intermediates, `:`...) — the
                // sequence is not a plain set/reset; consume without effect.
                _ => self.state = ScanState::SkipToFinal,
            },
            ScanState::SkipToFinal => {
                if (0x40..=0x7e).contains(&b) {
                    self.state = ScanState::Ground;
                }
            }
        }
    }

    fn push_param(&mut self) {
        if self.has_cur && self.params.len() < MAX_PARAMS {
            self.params.push(self.cur);
        }
        self.cur = 0;
        self.has_cur = false;
    }

    fn apply(&mut self, set: bool) {
        for &p in &self.params {
            if let Some(i) = TRACKED_MODES.iter().position(|&m| u32::from(m) == p) {
                self.active[i] = set;
            }
        }
        self.params.clear();
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fed(bytes: &[u8]) -> ModeState {
        let mut st = ModeState::new();
        st.feed(bytes);
        st
    }

    #[test]
    fn set_single_mode() {
        let st = fed(b"\x1b[?2004h");
        assert_eq!(st.reassert_sequence(), "\x1b[?2004h");
    }

    #[test]
    fn set_then_reset_clears() {
        let st = fed(b"\x1b[?2004h\x1b[?2004l");
        assert_eq!(st.reassert_sequence(), "");
    }

    #[test]
    fn multiple_params_in_one_sequence() {
        let st = fed(b"\x1b[?1000;1006h");
        assert_eq!(st.reassert_sequence(), "\x1b[?1000h\x1b[?1006h");
    }

    #[test]
    fn reset_one_of_several() {
        let st = fed(b"\x1b[?1000;1002;1006h\x1b[?1002l");
        assert_eq!(st.reassert_sequence(), "\x1b[?1000h\x1b[?1006h");
    }

    #[test]
    fn every_tracked_mode_round_trips() {
        for m in TRACKED_MODES {
            let set = format!("\x1b[?{m}h");
            let st = fed(set.as_bytes());
            assert_eq!(st.reassert_sequence(), set, "mode {m} set");
            let st = fed(format!("\x1b[?{m}h\x1b[?{m}l").as_bytes());
            assert_eq!(st.reassert_sequence(), "", "mode {m} reset");
        }
    }

    #[test]
    fn replay_order_is_deterministic() {
        // Feed in scrambled order; replay must follow TRACKED_MODES order.
        let st = fed(b"\x1b[?2026h\x1b[?1h\x1b[?1049h\x1b[?2004h");
        assert_eq!(
            st.reassert_sequence(),
            "\x1b[?1h\x1b[?1049h\x1b[?2004h\x1b[?2026h"
        );
    }

    #[test]
    fn split_across_chunks_at_every_offset() {
        let seq = b"\x1b[?1000;1006h";
        for i in 1..seq.len() {
            let mut st = ModeState::new();
            st.feed(&seq[..i]);
            st.feed(&seq[i..]);
            assert_eq!(
                st.reassert_sequence(),
                "\x1b[?1000h\x1b[?1006h",
                "split at byte {i}"
            );
        }
    }

    #[test]
    fn split_byte_by_byte() {
        let mut st = ModeState::new();
        for &b in b"\x1b[?1049h" {
            st.feed(&[b]);
        }
        assert_eq!(st.reassert_sequence(), "\x1b[?1049h");
    }

    #[test]
    fn interleaved_with_ordinary_output() {
        let st = fed(b"hello\r\n\x1b[1;31mred\x1b[0m\x1b[?2004hworld\x1b[?1004h$ ");
        assert_eq!(st.reassert_sequence(), "\x1b[?1004h\x1b[?2004h");
    }

    #[test]
    fn ignores_non_private_csi() {
        // ANSI SM with the same number must not flip the private mode.
        let st = fed(b"\x1b[2004h\x1b[4h\x1b[1000;1006h");
        assert_eq!(st.reassert_sequence(), "");
    }

    #[test]
    fn ignores_untracked_private_modes() {
        let st = fed(b"\x1b[?25l\x1b[?12h\x1b[?7l");
        assert_eq!(st.reassert_sequence(), "");
    }

    #[test]
    fn private_sequence_with_garbage_is_dropped() {
        // `$` is not a digit/`;`/final set-reset — sequence has no effect,
        // and scanning resumes cleanly afterwards.
        let st = fed(b"\x1b[?20$04h\x1b[?2004h");
        assert_eq!(st.reassert_sequence(), "\x1b[?2004h");
    }

    #[test]
    fn private_sequence_with_other_final_byte_is_dropped() {
        // DECRQM-style `CSI ? Pm $p` and save/restore `CSI ? Pm s/r`.
        let st = fed(b"\x1b[?2004s\x1b[?1049r");
        assert_eq!(st.reassert_sequence(), "");
    }

    #[test]
    fn esc_restarts_recognition_mid_sequence() {
        // A fresh ESC cancels the in-flight sequence; the new one applies.
        let st = fed(b"\x1b[?10\x1b[?2004h");
        assert_eq!(st.reassert_sequence(), "\x1b[?2004h");
    }

    #[test]
    fn double_esc_then_sequence() {
        let st = fed(b"\x1b\x1b[?1004h");
        assert_eq!(st.reassert_sequence(), "\x1b[?1004h");
    }

    #[test]
    fn alt_screen_variants_tracked_independently() {
        let st = fed(b"\x1b[?47h\x1b[?1047h\x1b[?1049h\x1b[?1047l");
        assert_eq!(st.reassert_sequence(), "\x1b[?47h\x1b[?1049h");
    }

    #[test]
    fn oversized_param_value_saturates_without_panic() {
        let st = fed(b"\x1b[?99999999999999999999h\x1b[?2004h");
        assert_eq!(st.reassert_sequence(), "\x1b[?2004h");
    }

    #[test]
    fn param_list_bounded() {
        // 100 params, the tracked one past the cap is dropped; one inside kept.
        let mut seq = b"\x1b[?2004".to_vec();
        for _ in 0..99 {
            seq.extend_from_slice(b";5");
        }
        seq.extend_from_slice(b";1049h");
        let st = fed(&seq);
        assert_eq!(st.reassert_sequence(), "\x1b[?2004h");
    }
}
