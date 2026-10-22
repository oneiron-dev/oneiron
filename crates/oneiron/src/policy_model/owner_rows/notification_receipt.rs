//! A queued policy-change notice, delivered as the change it records (FIX
//! 10031). The queue row is checked against the landed, immutable ledger
//! receipt it names, and that receipt's write-time author travels as the
//! notice's provenance. Delivery never asks the author to still hold policy
//! power: a lawfully queued change reaches a current recipient after its
//! author lost it. The recipient, its route, the follow-up's idempotence and
//! the digest's pacing stay the delivery pass's checks, and a row that does
//! not match its receipt is never delivered as one.
use std::collections::{BTreeMap, BTreeSet};

use super::ledger::{PolicyRowReceipt, read_receipts_in};
use super::notifications::PolicyQueuedNotification;
use crate::error::Result;
use crate::{EntityId, Vault};

/// One queued notice proven against its landed receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CommittedPolicyNotice {
    pub(super) receipt_id: String,
    /// The receipt's write-time author: provenance, not a live holder.
    pub(super) author: EntityId,
}

/// Each of `rows` checked against the landed receipt it names, in one pass
/// over the ledger, in `rows` order: `None` for a row whose receipt never
/// landed, or whose author, scope or grant target is not the receipt's.
///
/// # Errors
///
/// Storage errors, and a ledger row that does not decode.
pub(super) fn committed_policy_notices_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    rows: &[&PolicyQueuedNotification],
) -> Result<Vec<Option<CommittedPolicyNotice>>> {
    let wanted: BTreeSet<&str> = rows.iter().map(|row| row.receipt_id.as_str()).collect();
    let landed: BTreeMap<String, PolicyRowReceipt> = read_receipts_in(vault, txn)?
        .into_iter()
        .filter(|receipt| wanted.contains(receipt.receipt_id.as_str()))
        .map(|receipt| (receipt.receipt_id.clone(), receipt))
        .collect();
    Ok(rows
        .iter()
        .map(|row| {
            let receipt = landed.get(&row.receipt_id)?;
            let scope = receipt.change.scope();
            let target = super::policy_row_grant_target(scope, receipt.change.row_ref());
            if receipt.author != row.author || *scope != row.scope || target != row.grant_target {
                return None;
            }
            Some(CommittedPolicyNotice {
                receipt_id: receipt.receipt_id.clone(),
                author: EntityId::from_hex(&receipt.author).ok()?,
            })
        })
        .collect())
}
