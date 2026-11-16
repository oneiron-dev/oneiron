//! Moved from `crates/oneiron/src/skill_attribution/audit.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Aggregate result of one audit pass.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AttributionAuditReport {
    pub total: usize,
    /// Cases the judge answered correctly — including the cases where the
    /// correct answer was to abstain.
    pub passed: usize,
    /// Cases the judge abstained on, right or wrong. A judge that abstains on
    /// everything earns only the fixtures whose honest answer is abstention,
    /// so it can never score 100%.
    pub abstained: usize,
    pub at: u64,
}

impl AttributionAuditReport {
    /// Passed over total. An empty fixture set scores 0.0, never 1.0: "nothing
    /// was checked" is the worst evidence, not the best.
    #[must_use]
    pub fn pass_rate(&self) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        // Precision loss here is intended: this is a reported metric, not an
        // accumulator, and both counts are bounded by the fixture set.
        #[expect(
            clippy::cast_precision_loss,
            reason = "reported aggregate metric over a bounded fixture set"
        )]
        {
            self.passed as f32 / self.total as f32
        }
    }
}
