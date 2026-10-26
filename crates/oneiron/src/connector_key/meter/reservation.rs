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
    pub row_index: u16,
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
        let key = (debit.key_ref, debit.row_index.to_be_bytes());
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
