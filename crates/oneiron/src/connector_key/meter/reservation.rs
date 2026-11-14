//! An outbound send's reserved budget (FIX 7964): the usage entries its
//! admission charge wrote, and their release when the send certainly did
//! not go. A release takes out only those entries, in the window they were
//! written in: an entry a window rollover or a rolling expiry already
//! dropped is not taken twice, and nothing is moved into a later window.

use serde::{Deserialize, Serialize};

use super::*;
use crate::connector_key::txn::read_connector_key_in_txn;

/// The original row's approval, not permission to use the connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectorBudgetApproval {
    Key,
    Charter(EntityId),
}

impl EffectorBudgetApproval {
    pub(super) fn capture(record: &ConnectorKeyRecord, row: EffectorBudgetRowId) -> Result<Self> {
        match row.source {
            EffectorBudgetRowSource::Key => Ok(Self::Key),
            EffectorBudgetRowSource::Charter => record
                .charter
                .as_ref()
                .map(|charter| Self::Charter(charter.approval_id))
                .ok_or(Error::InvariantViolation(
                    "charter budget row has no approved charter",
                )),
        }
    }

    pub(super) fn matches(self, record: &ConnectorKeyRecord, row: EffectorBudgetRowId) -> bool {
        match (row.source, self) {
            (EffectorBudgetRowSource::Key, Self::Key) => true,
            (EffectorBudgetRowSource::Charter, Self::Charter(approval_id)) => record
                .charter
                .as_ref()
                .is_some_and(|charter| charter.approval_id == approval_id),
            _ => false,
        }
    }
}

/// A preauthorizing spend target, including one that wrote no estimate debit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectorSpendReservationRow {
    pub key_ref: EntityId,
    pub row: EffectorBudgetRowId,
    pub approval: EffectorBudgetApproval,
}

/// One usage entry a charge wrote: the key whose row it sits in, the row,
/// the amount and the charge's instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectorBudgetDebit {
    pub entry_id: EntityId,
    pub key_ref: EntityId,
    pub row: EffectorBudgetRowId,
    pub approval: EffectorBudgetApproval,
    pub amount: u64,
    pub at: u64,
}

/// Takes `debits` back out of their usage rows in `wtxn`: one matching
/// entry each, when the row still holds it. Thresholds the debit fired stay
/// fired; a rolling window re-arms them on its next touch.
///
/// # Errors
/// Storage and row-codec faults.
pub(crate) fn release_effector_debits_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    debits: &[EffectorBudgetDebit],
) -> Result<()> {
    for debit in debits {
        if debit.row.source != EffectorBudgetRowSource::Key
            || debit.approval != EffectorBudgetApproval::Key
        {
            let Some(record) = read_connector_key_in_txn(store, wtxn, &debit.key_ref)? else {
                continue;
            };
            if !debit.approval.matches(&record, debit.row) {
                continue;
            }
        }
        let key = (debit.key_ref, debit.row.usage_key());
        let Some(mut usage) = USAGE.get(store, wtxn, &key)? else {
            continue;
        };
        let Some(position) = usage
            .entries
            .iter()
            .position(|entry| entry.id == debit.entry_id)
        else {
            continue;
        };
        usage.entries.remove(position);
        USAGE.put(store, wtxn, &key, &usage)?;
    }
    Ok(())
}

/// Restores retained, still-live debits only if every owning row has room.
/// Original charter approvals must still match before a debit is grouped.
/// Preflight includes repeated debits of the same row and all co-actor/pool
/// rows before writing any usage. A blocked retry keeps its released budget.
pub(crate) fn restore_effector_debits_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    debits: &[EffectorBudgetDebit],
    now: u64,
) -> Result<BudgetBlock> {
    let mut grouped = std::collections::BTreeMap::new();
    for debit in debits {
        if debit.row.source != EffectorBudgetRowSource::Key
            || debit.approval != EffectorBudgetApproval::Key
        {
            let Some(record) = read_connector_key_in_txn(store, wtxn, &debit.key_ref)? else {
                continue;
            };
            if !debit.approval.matches(&record, debit.row) {
                continue;
            }
        }
        grouped
            .entry((debit.key_ref, debit.row))
            .or_insert_with(Vec::new)
            .push(UsageEntry {
                id: debit.entry_id,
                at: debit.at,
                amount: debit.amount,
                reserved: true,
            });
    }
    let mut block = BudgetBlock::Open;
    let mut restored_rows = Vec::new();
    let mut suspensions = std::collections::BTreeMap::new();
    for ((key_ref, row), entries) in grouped {
        let key = (key_ref, row.usage_key());
        let Some(mut usage) = USAGE.get(store, wtxn, &key)? else {
            continue;
        };
        let Some(record) = super::super::txn::read_connector_key_in_txn(store, wtxn, &key_ref)?
        else {
            continue;
        };
        let Some((_, budget)) = record_budget_rows(&record)
            .into_iter()
            .find(|(candidate, _)| *candidate == row)
        else {
            continue;
        };
        usage.touch(&budget.window, budget.limit, now);
        let mut restored = ConnectorKeyUsage {
            window_start: usage.window_start,
            entries,
            fired: Vec::new(),
        };
        restored.touch(&budget.window, budget.limit, now);
        if restored.used() == 0 {
            continue;
        }
        usage.entries.extend(restored.entries);
        if usage.used() > budget.limit {
            let state = BudgetRowState {
                row,
                budget,
                usage,
                amount: 0,
                matched: true,
            };
            let row_block = if rate_window::row_paces(budget.dimension, budget.on_exhaust) {
                // The original debits may expire before newer usage does.
                // Evaluate the combined log, not a newly dated charge.
                rate_window::next_eligible(&state, now)
                    .map_or(BudgetBlock::Hard, |next_eligible_at| BudgetBlock::Paced {
                        next_eligible_at,
                    })
            } else {
                BudgetBlock::Hard
            };
            block = block.and(row_block);
            if budget.on_exhaust == EffectorBudgetOnExhaust::Suspend {
                suspensions
                    .entry(key_ref)
                    .or_insert_with(|| (record.clone(), EffectorBudgetLocation { key_ref, row }));
            }
        } else {
            restored_rows.push((key, usage));
        }
    }
    if block != BudgetBlock::Open {
        // The writer suspends an Active key alone; any other stays as it is.
        for (key_ref, (record, location)) in suspensions {
            suspend_connector_key_in_txn(
                store,
                wtxn,
                &key_ref,
                &record,
                SuspendCause::BudgetExhausted(&location),
                now,
            )?;
        }
        return Ok(block);
    }
    for (key, usage) in restored_rows {
        USAGE.put(store, wtxn, &key, &usage)?;
    }
    Ok(BudgetBlock::Open)
}

/// Fires only previously unemitted thresholds of this send's current live
/// rows. It runs after the exact entries settle, in that same Done writer;
/// neither an obsolete charter nor an expired or removed debit contributes.
pub(crate) fn fire_settled_effector_debits_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    debits: &[EffectorBudgetDebit],
    now: u64,
) -> Result<Vec<EffectorBudgetSettlementEvents>> {
    let mut grouped = std::collections::BTreeMap::new();
    for debit in debits {
        grouped
            .entry((debit.key_ref, debit.row))
            .or_insert_with(Vec::new)
            .push(debit);
    }
    let mut events: Vec<EffectorBudgetSettlementEvents> = Vec::new();
    for ((key_ref, row), debits) in grouped {
        let Some(record) = read_connector_key_in_txn(store, wtxn, &key_ref)? else {
            continue;
        };
        let Some((_, budget)) = record_budget_rows(&record)
            .into_iter()
            .find(|(candidate, _)| *candidate == row)
        else {
            continue;
        };
        if budget.dimension == EffectorBudgetDimension::Spend {
            continue;
        }
        let key = (key_ref, row.usage_key());
        let Some(mut usage) = USAGE.get(store, wtxn, &key)? else {
            continue;
        };
        usage.touch(&budget.window, budget.limit, now);
        if !debits.iter().any(|debit| {
            debit.approval.matches(&record, row)
                && debit.amount > 0
                && usage.entries.iter().any(|entry| {
                    entry.id == debit.entry_id
                        && entry.at == debit.at
                        && entry.amount == debit.amount
                        && !entry.reserved
                })
        }) {
            continue;
        }
        let ladder_events = charge::fire_ladder_thresholds(row, budget, &mut usage);
        USAGE.put(store, wtxn, &key, &usage)?;
        if !ladder_events.is_empty() {
            if let Some(last) = events.last_mut().filter(|event| event.key_ref == key_ref) {
                last.ladder_events.extend(ladder_events);
            } else {
                events.push(EffectorBudgetSettlementEvents {
                    key_ref,
                    ladder_events,
                });
            }
        }
    }
    Ok(events)
}

/// Changes only the exact live entries carried by one outbound reservation.
/// A window expiry or charter reset leaves no entry to mark.
pub(crate) fn set_effector_debits_reserved_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    debits: &[EffectorBudgetDebit],
    reserved: bool,
) -> Result<()> {
    for debit in debits {
        let key = (debit.key_ref, debit.row.usage_key());
        let Some(mut usage) = USAGE.get(store, wtxn, &key)? else {
            continue;
        };
        let Some(entry) = usage
            .entries
            .iter_mut()
            .find(|entry| entry.id == debit.entry_id)
        else {
            continue;
        };
        entry.reserved = reserved;
        USAGE.put(store, wtxn, &key, &usage)?;
    }
    Ok(())
}
