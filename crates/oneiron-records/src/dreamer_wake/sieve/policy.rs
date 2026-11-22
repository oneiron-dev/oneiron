//! Moved from `crates/oneiron/src/dreamer_wake/sieve/policy.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The sieve's three per-pass work budgets, the part of its policy a holder
/// of `engine.controls` may lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SievePassBudgets {
    /// Turns one pass reads.
    pub max_turns_per_pass: u32,
    /// Timeline rows one pass's forward scan steps over.
    pub max_scan_per_pass: u32,
    /// Bytes of turn text one pass reads.
    pub max_text_bytes_per_pass: u32,
}
