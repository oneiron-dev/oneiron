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
            .position(|entry| *entry == (debit.at, debit.amount))
        else {
            continue;
        };
        usage.entries.remove(position);
        USAGE.put(store, wtxn, &key, &usage)?;
    }
    Ok(())
}
