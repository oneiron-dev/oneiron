//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/site_skills/distill.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

/// One trap kind and its occurrence count. Kinds are stable snake-case
/// tokens; they never carry a locator, a value or caller-authored text.
#[derive(Debug, Clone, Serialize)]
pub struct TrapCount {
    /// The stable kind token.
    pub kind: String,
    /// Its occurrence count.
    pub count: u64,
}
