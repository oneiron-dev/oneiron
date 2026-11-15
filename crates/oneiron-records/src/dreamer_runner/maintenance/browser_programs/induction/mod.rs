//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/browser_programs/induction/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

/// How far a candidate got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Aligned and verified, every parameter bound.
    Aligned,
    /// Aligned, with secret slots or arguments its admission binds again.
    NeedsBinding,
    /// Did not align, ran short or failed a check: its reasons say why.
    Diagnostic,
}

impl Status {
    /// Whether an admission job may take the candidate.
    pub fn eligible(self) -> bool {
        !matches!(self, Self::Diagnostic)
    }
}
