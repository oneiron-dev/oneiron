//! The original line established by a successful native admission.

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;

/// Accounting provenance, not an execution grant or a paid receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedBudgetLine {
    attempt_id: AttemptId,
    budget_id: String,
}

impl AdmittedBudgetLine {
    pub(super) fn new(attempt_id: AttemptId, budget_id: String) -> Self {
        Self {
            attempt_id,
            budget_id,
        }
    }

    pub(crate) fn for_attempt(&self, attempt_id: AttemptId) -> Option<&str> {
        (self.attempt_id == attempt_id).then_some(self.budget_id.as_str())
    }
}

impl DreamerAdmittedAttempt {
    pub(crate) fn admitted_budget_line(&self) -> &AdmittedBudgetLine {
        &self.admitted_budget_line
    }
}
