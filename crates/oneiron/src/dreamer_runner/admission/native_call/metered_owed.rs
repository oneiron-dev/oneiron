//! Raw original snapshot sources for a successful held-reservation owed add.

use oneiron_model::llm::BudgetGuardId;
use serde::{Deserialize, Serialize};

use super::super::{
    BUDGET_RESERVATION, BudgetReservationKey, NativeMeterSnapshot, SettleDreamerBudget,
};
use super::observations::NativeObservedLeaseState;
use super::{CALLS, DreamerRunnerStore, Error, NativeCallMeter, Result, invalid_dreamer_runner};

/// The increment and cumulative owed value are aggregates, not per-call shares.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeMeteredOwedObservation {
    snapshot_guard_id: BudgetGuardId,
    reservation_birth_generation: Option<u32>,
    reserved_units: u64,
    owed_units_after: u64,
    owed_increment_units: u64,
    snapshot_start_used_units: u64,
    snapshot_end_used_units: u64,
    lease_state: NativeObservedLeaseState,
    lease_meter: NativeCallMeter,
    at: u64,
}

impl DreamerRunnerStore<'_> {
    /// Called only after the original owed and budget writes succeed. The child
    /// records no direct-line charge, paid receipt, inclusion or NET settlement.
    pub(crate) fn record_native_metered_owed_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: &SettleDreamerBudget,
        native: &NativeMeterSnapshot,
    ) {
        let recorded = (|| -> Result<()> {
            if !native.matches_settlement(&input.budget_id, input.child_attempt) {
                return Err(invalid_dreamer_runner("native metered owed source differs"));
            }
            let mut child = self.vault.store.env.nested_write_txn(wtxn)?;
            let Some(reservation) = BUDGET_RESERVATION.get(
                &self.vault.store,
                &child,
                &BudgetReservationKey {
                    budget_id: input.budget_id.clone(),
                    attempt_id: input.child_attempt,
                },
            )?
            else {
                return Ok(());
            };
            if reservation.budget_id != input.budget_id
                || reservation.attempt_id != input.child_attempt
            {
                return Err(invalid_dreamer_runner(
                    "native metered owed reservation differs",
                ));
            }
            let interval = native.interval();
            for (origin, lease_id, state, range) in native.observed_calls() {
                let Some(mut row) = CALLS.get(&self.vault.store, &child, &origin)? else {
                    return Err(invalid_dreamer_runner(
                        "native metered owed admission missing",
                    ));
                };
                if row.line != reservation.budget_id || row.lease != lease_id {
                    return Err(invalid_dreamer_runner(
                        "native metered owed original differs",
                    ));
                }
                row.metered_owed_observations
                    .push(NativeMeteredOwedObservation {
                        snapshot_guard_id: native.guard_id(),
                        reservation_birth_generation: reservation.birth_generation,
                        reserved_units: reservation.reserved_units,
                        owed_units_after: reservation.owed_units,
                        owed_increment_units: input.actual_units,
                        snapshot_start_used_units: interval.start_used_units,
                        snapshot_end_used_units: interval.end_used_units,
                        lease_state: state.into(),
                        lease_meter: range.map_or(NativeCallMeter::Unknown, |range| {
                            NativeCallMeter::Settled {
                                start_used_units: range.start_used_units,
                                end_used_units: range.end_used_units,
                            }
                        }),
                        at: input.now,
                    });
                CALLS.put(&self.vault.store, &mut child, &origin, &row)?;
            }
            child.commit().map_err(Error::from)
        })();
        if let Err(error) = recorded {
            tracing::warn!(kind = ?error.kind(), %error, "native metered owed observation skipped");
        }
    }
}
