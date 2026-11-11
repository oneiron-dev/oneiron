//! Moved from `crates/oneiron/src/dreamer_runner/admission/budget_line.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;

/// Accounting provenance, not an execution grant or a paid receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedBudgetLine {
    attempt_id: AttemptId,
    budget_id: String,
}

impl AdmittedBudgetLine {
    pub fn new(attempt_id: AttemptId, budget_id: String) -> Self {
        Self {
            attempt_id,
            budget_id,
        }
    }

    pub fn for_attempt(&self, attempt_id: AttemptId) -> Option<&str> {
        (self.attempt_id == attempt_id).then_some(self.budget_id.as_str())
    }
}
