//! Original owed-row sources retained by the successful reconciliation writer.

use serde::{Deserialize, Serialize};

use super::super::DreamerBudgetSettlementOutcome;
use super::{CALLS, DreamerRunnerStore, Error, Result, invalid_dreamer_runner};
use crate::attempt_queue::AttemptId;
use crate::dreamer_wake::owed::OwedCallUsage;
use crate::entity_id::EntityId;

/// Step-derived usage, not a physical call invoice or a share of old owed units.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeOwedReconciliation {
    terminal_claim: Option<EntityId>,
    step_usage_units: u64,
    aggregate_units: u64,
    settlement: NativeOwedSettlement,
    at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum NativeOwedSettlement {
    Reservation {
        birth_generation: Option<u32>,
        reserved_units: u64,
        old_owed_units: u64,
        settled_units: u64,
    },
    Unreserved,
}

impl DreamerRunnerStore<'_> {
    /// This optional child cannot undo the existing charge or owed-row deletes.
    pub(crate) fn record_native_owed_reconciliation_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        line: &str,
        aggregate_units: u64,
        outcome: &DreamerBudgetSettlementOutcome,
        sources: &[OwedCallUsage],
        now: u64,
    ) {
        let recorded = (|| -> Result<()> {
            let settlement = match outcome {
                DreamerBudgetSettlementOutcome::Settled(actual) => {
                    let reservation = &actual.reservation;
                    if reservation.budget_id != line
                        || actual.budget.budget_id != line
                        || reservation.attempt_id != attempt
                    {
                        return Err(invalid_dreamer_runner(
                            "native owed reconciliation reservation differs",
                        ));
                    }
                    NativeOwedSettlement::Reservation {
                        birth_generation: reservation.birth_generation,
                        reserved_units: reservation.reserved_units,
                        old_owed_units: reservation.owed_units,
                        settled_units: actual.actual_units,
                    }
                }
                DreamerBudgetSettlementOutcome::NoReservation if aggregate_units > 0 => {
                    NativeOwedSettlement::Unreserved
                }
                DreamerBudgetSettlementOutcome::NoReservation => return Ok(()),
            };
            let mut child = self.vault.store.env.nested_write_txn(wtxn)?;
            for source in sources {
                let call = &source.call;
                let Some(mut row) = CALLS.get(&self.vault.store, &child, &call.origin)? else {
                    return Err(invalid_dreamer_runner(
                        "native owed reconciliation admission missing",
                    ));
                };
                if call.origin.attempt_id != attempt
                    || call.line != line
                    || row.line != call.line
                    || row.step_hash != source.step_hash
                    || row.boot != call.boot
                    || row.lease != call.lease
                    || row.reserved_units != call.reserved_units
                    || row.admitted_at != call.at
                {
                    return Err(invalid_dreamer_runner(
                        "native owed reconciliation original differs",
                    ));
                }
                row.owed_reconciliations.push(NativeOwedReconciliation {
                    terminal_claim: source.terminal_claim,
                    step_usage_units: source.step_units,
                    aggregate_units,
                    settlement: settlement.clone(),
                    at: now,
                });
                CALLS.put(&self.vault.store, &mut child, &call.origin, &row)?;
            }
            child.commit().map_err(Error::from)
        })();
        if let Err(error) = recorded {
            tracing::warn!(kind = ?error.kind(), %error, "native owed reconciliation skipped");
        }
    }
}
