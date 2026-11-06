//! Original NET invoice inclusion in the existing partition settlement.

use std::sync::{Mutex, PoisonError};

use super::*;
use crate::dreamer_runner::AdmittedBudgetLine;
use crate::model_step_context::StepReceipt;

#[derive(Debug)]
pub(crate) struct NativeNetTally {
    original_line: AdmittedBudgetLine,
    state: Mutex<Option<NetTallyState>>,
}

#[derive(Debug, Default)]
struct NetTallyState {
    units: u64,
    unpaired_units: u64,
    unpaired_entries: u64,
    terminals: Vec<(StepReceipt, u64)>,
    published: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeNetSnapshot {
    original_line: AdmittedBudgetLine,
    units: u64,
    unpaired_units: u64,
    unpaired_entries: u64,
    terminals: Vec<(StepReceipt, u64)>,
}

impl NativeNetTally {
    pub(crate) fn new(original_line: AdmittedBudgetLine) -> Self {
        Self {
            original_line,
            state: Mutex::new(Some(NetTallyState::default())),
        }
    }

    pub(crate) fn record(&self, binding: Option<StepReceipt>, units: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let recorded = (|| {
            let tally = state.as_mut()?;
            tally.units = tally.units.checked_add(units)?;
            if let Some(binding) = binding {
                tally.terminals.push((binding, units));
            } else {
                tally.unpaired_units = tally.unpaired_units.checked_add(units)?;
                tally.unpaired_entries = tally.unpaired_entries.checked_add(1)?;
            }
            tally.published = false;
            Some(())
        })();
        if recorded.is_none() {
            *state = None;
        }
    }

    /// A child's guard total is not a native NET response population.
    pub(crate) fn discard(&self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    pub(crate) fn publish(&self) {
        if let Some(tally) = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            tally.published = true;
        }
    }

    pub(crate) fn snapshot(&self, reported_units: u64) -> Option<NativeNetSnapshot> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let tally = state.as_ref()?;
        if !tally.published || tally.units != reported_units {
            return None;
        }
        Some(NativeNetSnapshot {
            original_line: self.original_line.clone(),
            units: tally.units,
            unpaired_units: tally.unpaired_units,
            unpaired_entries: tally.unpaired_entries,
            terminals: tally.terminals.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum NativeNetCoverage {
    Unknown,
    Included {
        terminal_claim: EntityId,
        response_units: u64,
        aggregate_units: u64,
        settled_units: u64,
        unpaired_units: u64,
        unpaired_entries: u64,
        at: u64,
    },
}

pub(in crate::dreamer_runner) fn record_native_net_settlement_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    settlement: &super::super::SettleDreamerBudget,
    settled_units: u64,
    native: &NativeNetSnapshot,
) {
    let recorded = (|| -> Result<()> {
        if native.original_line.for_attempt(settlement.child_attempt)
            != Some(settlement.budget_id.as_str())
            || native.units != settlement.actual_units
            || settled_units < native.units
        {
            return Err(invalid_dreamer_runner("native NET aggregate differs"));
        }
        let total = native
            .terminals
            .iter()
            .try_fold(native.unpaired_units, |total, (_, units)| {
                total.checked_add(*units)
            });
        if total != Some(native.units) {
            return Err(invalid_dreamer_runner("native NET tally differs"));
        }
        let mut child = vault.store.env.nested_write_txn(wtxn)?;
        let mut selected = Vec::new();
        for &(binding, response_units) in &native.terminals {
            // Exact terminal aliases resolve original O0 rows, never the mutable memo index.
            let roots = CALLS.scan_from(&vault.store, &child, binding.attempt_id.as_bytes())?;
            let mut roots = roots.into_iter().filter(|(origin, row)| {
                origin.ordinal == 0
                    && row.step_hash == binding.step_hash
                    && row.terminal_claims.contains(&binding.claim_id)
            });
            let Some((origin, root)) = roots.next() else {
                return Err(invalid_dreamer_runner(
                    "native NET terminal original missing",
                ));
            };
            if roots.next().is_some() {
                return Err(invalid_dreamer_runner(
                    "native NET terminal original ambiguous",
                ));
            }
            let NativeNetResponse::Captured {
                invoices,
                response_units: original_units,
            } = root.net_response
            else {
                return Err(invalid_dreamer_runner("native NET response unknown"));
            };
            if original_units != response_units || root.line != settlement.budget_id {
                return Err(invalid_dreamer_runner(
                    "native NET response original differs",
                ));
            }
            let coverage = NativeNetCoverage::Included {
                terminal_claim: binding.claim_id,
                response_units,
                aggregate_units: native.units,
                settled_units,
                unpaired_units: native.unpaired_units,
                unpaired_entries: native.unpaired_entries,
                at: settlement.now,
            };
            let mut response_total = 0_u64;
            for (index, &(ordinal, units)) in invoices.iter().enumerate() {
                if usize::try_from(ordinal).ok() != Some(index) {
                    return Err(invalid_dreamer_runner("native NET population differs"));
                }
                let call = AdmittedCallId { ordinal, ..origin };
                if selected.contains(&call) {
                    return Err(invalid_dreamer_runner("native NET invoice overlaps"));
                }
                selected.push(call);
                let Some(mut row) = CALLS.get(&vault.store, &child, &call)? else {
                    return Err(invalid_dreamer_runner("native NET invoice missing"));
                };
                let invoiced = match row.invoice {
                    NativeCallInvoice::Invoiced { units }
                    | NativeCallInvoice::Paid { units, .. } => Some(units),
                    NativeCallInvoice::Admitted => None,
                };
                if invoiced != Some(units)
                    || row.line != settlement.budget_id
                    || row.step_hash != binding.step_hash
                    || !row.terminal_claims.contains(&binding.claim_id)
                {
                    return Err(invalid_dreamer_runner(
                        "native NET invoice original differs",
                    ));
                }
                response_total = response_total
                    .checked_add(units)
                    .ok_or_else(|| invalid_dreamer_runner("native NET total overflows"))?;
                if row.net_coverage != NativeNetCoverage::Unknown && row.net_coverage != coverage {
                    return Err(invalid_dreamer_runner("native NET coverage differs"));
                }
                row.net_coverage = coverage.clone();
                // The existing NET aggregate already charged this original line.
                // A different attempt's free-time attribution is not paired here.
                if call.attempt_id == settlement.child_attempt
                    && let NativeCallInvoice::Invoiced { units } = row.invoice
                {
                    row.invoice = NativeCallInvoice::Paid {
                        units,
                        at: settlement.now,
                    };
                }
                CALLS.put(&vault.store, &mut child, &call, &row)?;
            }
            if response_total != response_units {
                return Err(invalid_dreamer_runner(
                    "native NET response quantity differs",
                ));
            }
        }
        child.commit().map_err(Error::from)
    })();
    if let Err(error) = recorded {
        tracing::warn!(kind = ?error.kind(), %error, "native NET aggregate inclusion skipped");
    }
}
