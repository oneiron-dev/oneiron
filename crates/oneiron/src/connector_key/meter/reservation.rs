//! An outbound send's reserved budget (FIX 7964): the usage entries its
//! admission charge wrote, and their release when the send certainly did
//! not go. A release takes out only those entries, in the window they were
//! written in: an entry a window rollover or a rolling expiry already
//! dropped is not taken twice, and nothing is moved into a later window.

use serde::{Deserialize, Serialize};

use super::*;

/// One usage entry a charge wrote: the key whose row it sits in, the row,
/// the amount and the charge's instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectorBudgetDebit {
    pub key_ref: EntityId,
    pub row: EffectorBudgetRowId,
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
        let key = (debit.key_ref, debit.row.usage_key());
        let Some(mut usage) = USAGE.get(store, wtxn, &key)? else {
            continue;
        };
        let Some(position) = usage
            .entries
            .iter()
            .position(|entry| *entry == (debit.at, debit.amount))
        else {
            continue;
        };
        usage.entries.remove(position);
        USAGE.put(store, wtxn, &key, &usage)?;
    }
    Ok(())
}

/// Restores retained, still-live debits only if every owning row has room.
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
        grouped
            .entry((debit.key_ref, debit.row))
            .or_insert_with(Vec::new)
            .push((debit.at, debit.amount));
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
            if budget.on_exhaust == EffectorBudgetOnExhaust::Suspend
                && record.status == ConnectorKeyStatus::Active
            {
                suspensions
                    .entry(key_ref)
                    .or_insert_with(|| (record.clone(), EffectorBudgetLocation { key_ref, row }));
            }
        } else {
            restored_rows.push((key, usage));
        }
    }
    if block != BudgetBlock::Open {
        for (key_ref, (record, location)) in suspensions {
            suspend_connector_key_in_txn(
                store,
                wtxn,
                &key_ref,
                &record,
                budget_exhausted_reason(&location),
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
