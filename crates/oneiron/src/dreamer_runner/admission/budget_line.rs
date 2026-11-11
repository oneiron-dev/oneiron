//! The original line established by a successful native admission.

use crate::dreamer_runner::DreamerAdmittedAttempt;

#[doc(hidden)]
pub(crate) use oneiron_wake_contract::dreamer_runner::admission::budget_line::AdmittedBudgetLine;

impl DreamerAdmittedAttempt {
    pub(crate) fn admitted_budget_line(&self) -> &AdmittedBudgetLine {
        &self.admitted_budget_line
    }
}
