//! One guard read and selected lease states from the same lock.

use super::ledger::{LeaseRecord, LeaseState};
use super::{BudgetGuard, BudgetLeaseState, BudgetRead};
use crate::llm::BudgetLease;

/// Accounting data only: neither funding authority nor a durable paid receipt.
#[derive(Debug, Clone)]
pub struct BudgetAccountingSnapshot {
    pub read: BudgetRead,
    /// One entry per requested lease, in the same order. A foreign or unknown
    /// lease has no state on this guard, even if its public id matches.
    pub leases: Vec<Option<BudgetLeaseState>>,
}

impl BudgetGuard {
    /// Captures the meter and the selected native leases under one lock.
    /// No caller code or storage writer runs while that lock is held.
    #[must_use]
    pub fn accounting_snapshot(&self, leases: &[&BudgetLease]) -> BudgetAccountingSnapshot {
        let state = self.lock_state();
        let read = state.read();
        let leases = leases
            .iter()
            .map(|lease| {
                state.check_lease_provenance(lease).ok()?;
                state.leases.get(lease.id()).map(lease_observation)
            })
            .collect();
        BudgetAccountingSnapshot { read, leases }
    }
}

pub(super) fn lease_observation(record: &LeaseRecord) -> BudgetLeaseState {
    match record.state {
        LeaseState::Open => BudgetLeaseState::Open {
            reserve_units: record.reserve_units,
            dispatched: record.dispatched,
        },
        LeaseState::Settled { charged_units } => BudgetLeaseState::Settled {
            used_units: charged_units,
        },
        LeaseState::Aborted => BudgetLeaseState::Aborted,
    }
}
