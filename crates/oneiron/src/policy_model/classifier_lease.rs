//! Cancellation-safe ownership of a stateless classifier's private reservation.

use crate::llm::{BudgetGuard, BudgetLease};

/// A started classifier call must spend its estimate if it never returns
/// terminal usage. The caller may settle actual usage first; settlement of an
/// already-settled lease is idempotent. A backend that aborted the call may
/// already have released the reservation before this owner drops.
pub(super) struct ClassifierLease<'a> {
    budget: &'a BudgetGuard,
    lease: BudgetLease,
}

impl<'a> ClassifierLease<'a> {
    pub(super) fn new(budget: &'a BudgetGuard, lease: BudgetLease) -> Self {
        Self { budget, lease }
    }

    pub(super) fn lease(&self) -> &BudgetLease {
        &self.lease
    }
}

impl Drop for ClassifierLease<'_> {
    fn drop(&mut self) {
        // Drop has no error channel. This is a no-op when normal completion
        // settled usage, or the backend already settled/aborted the lease.
        // On cancellation while generate is pending it closes the still-open
        // reservation, charging the estimate rather than forgiving spend.
        let _ = self.budget.settle_reserved(&self.lease);
    }
}
