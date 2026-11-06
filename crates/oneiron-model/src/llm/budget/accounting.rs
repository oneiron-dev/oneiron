//! One guard read and selected lease states from the same lock.

use super::ledger::{LeaseRecord, LeaseState};
use super::{BudgetGuard, BudgetLeaseState, BudgetRead};
use crate::llm::BudgetLease;

/// One native lease's actual contribution to this guard's global meter.
/// The interval is immutable after its first settlement, and may be empty.
/// It is not the native NET invoice, a per-row total, or a paid fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetMeterRange {
    pub start_used_units: u64,
    pub end_used_units: u64,
}

/// Accounting data only: neither funding authority nor a durable paid receipt.
#[derive(Debug, Clone)]
pub struct BudgetAccountingSnapshot {
    pub read: BudgetRead,
    /// One entry per requested lease, in the same order. A foreign or unknown
    /// lease has no state on this guard, even if its public id matches.
    pub leases: Vec<Option<BudgetLeaseState>>,
    /// The corresponding first-settlement interval on this guard. Open,
    /// aborted, foreign and unknown leases have no interval. An unmetered
    /// settled lease has an empty interval, not a missing one.
    pub meter_ranges: Vec<Option<BudgetMeterRange>>,
}

impl BudgetGuard {
    /// Captures the meter and the selected native leases under one lock.
    /// No caller code or storage writer runs while that lock is held.
    #[must_use]
    pub fn accounting_snapshot(&self, leases: &[&BudgetLease]) -> BudgetAccountingSnapshot {
        let state = self.lock_state();
        let read = state.read();
        let (leases, meter_ranges) = leases
            .iter()
            .map(|lease| {
                if state.check_lease_provenance(lease).is_err() {
                    return (None, None);
                }
                let Some(record) = state.leases.get(lease.id()) else {
                    return (None, None);
                };
                (Some(lease_observation(record)), lease_meter_range(record))
            })
            .unzip();
        BudgetAccountingSnapshot {
            read,
            leases,
            meter_ranges,
        }
    }
}

pub(super) fn lease_observation(record: &LeaseRecord) -> BudgetLeaseState {
    match record.state {
        LeaseState::Open => BudgetLeaseState::Open {
            reserve_units: record.reserve_units,
            dispatched: record.dispatched,
        },
        LeaseState::Settled { charged_units, .. } => BudgetLeaseState::Settled {
            used_units: charged_units,
        },
        LeaseState::Aborted => BudgetLeaseState::Aborted,
    }
}

fn lease_meter_range(record: &LeaseRecord) -> Option<BudgetMeterRange> {
    match record.state {
        LeaseState::Settled {
            meter_start_used_units,
            meter_end_used_units,
            ..
        } => Some(BudgetMeterRange {
            start_used_units: meter_start_used_units,
            end_used_units: meter_end_used_units,
        }),
        LeaseState::Open | LeaseState::Aborted => None,
    }
}
