//! Raw retained-token observations from each successful aggregate writer.

use oneiron_model::llm::{BudgetGuardId, BudgetLeaseState};
use serde::{Deserialize, Serialize};

use super::super::{DreamerBudgetSettlement, NativeMeterSnapshot, SettleDreamerBudget};
use super::{CALLS, Error, NativeCallMeter, Result, Vault, invalid_dreamer_runner};
use crate::attempt_queue::AttemptId;
use crate::model_step_context::StepReceipt;

/// A consumed reservation and its snapshot, not a payment or exclusion fact.
/// Equal observations from separate successful settlements remain separate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeAggregateObservation {
    snapshot_guard_id: BudgetGuardId,
    attempt_id: AttemptId,
    reservation_birth_generation: Option<u32>,
    reserved_units: u64,
    owed_units: u64,
    snapshot_start_used_units: u64,
    snapshot_end_used_units: u64,
    aggregate_units: u64,
    settled_units: u64,
    /// Marker keys newly written by this successful settlement, not per-step amounts.
    newly_pinned_steps: Vec<StepReceipt>,
    lease_state: NativeObservedLeaseState,
    lease_meter: NativeCallMeter,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum NativeObservedLeaseState {
    Unknown,
    Open {
        reserve_units: u64,
        dispatched: bool,
    },
    Settled {
        used_units: u64,
    },
    Aborted,
}

impl From<Option<BudgetLeaseState>> for NativeObservedLeaseState {
    fn from(state: Option<BudgetLeaseState>) -> Self {
        match state {
            None => Self::Unknown,
            Some(BudgetLeaseState::Open {
                reserve_units,
                dispatched,
            }) => Self::Open {
                reserve_units,
                dispatched,
            },
            Some(BudgetLeaseState::Settled { used_units }) => Self::Settled { used_units },
            Some(BudgetLeaseState::Aborted) => Self::Aborted,
        }
    }
}

/// The caller has already attempted Included evidence in a separate child.
/// This child cannot undo that evidence, the charge, receipts or park.
pub(in crate::dreamer_runner::admission) fn record_native_aggregate_observations_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &SettleDreamerBudget,
    actual: &DreamerBudgetSettlement,
    native: &NativeMeterSnapshot,
    newly_pinned_steps: &[StepReceipt],
) {
    let recorded = (|| -> Result<()> {
        let reservation = &actual.reservation;
        if reservation.budget_id != input.budget_id
            || actual.budget.budget_id != input.budget_id
            || reservation.attempt_id != input.child_attempt
            || !native.matches_settlement(&input.budget_id, input.child_attempt)
        {
            return Err(invalid_dreamer_runner(
                "native aggregate observation reservation differs",
            ));
        }
        let interval = native.interval();
        let mut child = vault.store.env.nested_write_txn(wtxn)?;
        for (origin, lease_id, state, range) in native.observed_calls() {
            let Some(mut row) = CALLS.get(&vault.store, &child, &origin)? else {
                return Err(invalid_dreamer_runner(
                    "native aggregate observation admission missing",
                ));
            };
            if row.line != reservation.budget_id || row.lease != lease_id {
                return Err(invalid_dreamer_runner(
                    "native aggregate observation original differs",
                ));
            }
            row.aggregate_observations.push(NativeAggregateObservation {
                snapshot_guard_id: native.guard_id(),
                attempt_id: reservation.attempt_id,
                reservation_birth_generation: reservation.birth_generation,
                reserved_units: reservation.reserved_units,
                owed_units: reservation.owed_units,
                snapshot_start_used_units: interval.start_used_units,
                snapshot_end_used_units: interval.end_used_units,
                aggregate_units: input.actual_units,
                settled_units: actual.actual_units,
                newly_pinned_steps: newly_pinned_steps.to_vec(),
                lease_state: state.into(),
                lease_meter: range.map_or(NativeCallMeter::Unknown, |range| {
                    NativeCallMeter::Settled {
                        start_used_units: range.start_used_units,
                        end_used_units: range.end_used_units,
                    }
                }),
            });
            CALLS.put(&vault.store, &mut child, &origin, &row)?;
        }
        child.commit().map_err(Error::from)
    })();
    if let Err(error) = recorded {
        tracing::warn!(kind = ?error.kind(), %error, "native aggregate observation skipped");
    }
}
