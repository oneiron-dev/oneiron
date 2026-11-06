//! Original caller provenance for a native decision read, never an execution grant.

use super::WakePassDeadline;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::AdmittedCallId;
use oneiron_model::llm::{BudgetAccountingSnapshot, BudgetGuard, BudgetLease};

/// The original admitted line of a scoped caller. Merely carrying this value
/// allocates nothing; the native read draws its own invocation after admission.
#[derive(Clone, Copy)]
pub struct DecisionCallSource<'a> {
    deadline: &'a WakePassDeadline,
    attempt_id: AttemptId,
}

impl<'a> DecisionCallSource<'a> {
    pub(crate) fn new(deadline: &'a WakePassDeadline, attempt_id: AttemptId) -> Self {
        Self {
            deadline,
            attempt_id,
        }
    }

    pub(crate) fn admitted(
        &self,
        guard: &BudgetGuard,
        lease: &BudgetLease,
    ) -> crate::Result<Option<DecisionCallAdmission>> {
        Ok(self
            .deadline
            .admitted_call_id(self.attempt_id)?
            .map(|origin| DecisionCallAdmission {
                origin,
                guard: guard.clone(),
                lease: lease.clone(),
            }))
    }
}

/// One native admission's original coordinate and the actual issuing guard and
/// lease. A snapshot is GROSS meter data, not a NET invoice or a paid receipt.
#[derive(Clone)]
pub struct DecisionCallAdmission {
    pub(crate) origin: AdmittedCallId,
    pub(crate) guard: BudgetGuard,
    pub(crate) lease: BudgetLease,
}

impl DecisionCallAdmission {
    /// Samples this exact lease through its issuing guard, including unknown
    /// and unstarted states. Its public lease id is never used to reconstruct it.
    #[must_use]
    pub fn accounting_snapshot(&self) -> BudgetAccountingSnapshot {
        self.guard.accounting_snapshot(&[&self.lease])
    }
}

impl std::fmt::Debug for DecisionCallAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionCallAdmission")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl PartialEq for DecisionCallAdmission {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin && self.lease == other.lease
    }
}

impl Eq for DecisionCallAdmission {}
