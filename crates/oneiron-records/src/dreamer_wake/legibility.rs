//! Moved from `crates/oneiron/src/dreamer_wake/legibility.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Budget legibility attached to EVERY host-call response inside a wake
/// pass (1184-D4-D): remaining budget, remaining wall-clock, the wrap-up
/// notice, and the finalize deadline once the graceful-wrap window opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BudgetLegibilityEnvelope {
    pub remaining_units: u64,
    pub limit_units: u64,
    pub remaining_ms: u64,
    pub wrap_up: bool,
    pub finalize_by_ms: Option<u64>,
}
