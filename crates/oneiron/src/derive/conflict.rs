//! The conflict item: the set a bound Resolution read of `ai.verdict` names,
//! opened instead of asked.
//!
//! Its operands are that read's operands: one candidate per member, exactly
//! as the verdict takes it, with the confidence and the prospective query
//! hints a kept alternative lands with, and the stored heads the set stands
//! against, each with the version the job read. A later Settle item of the
//! batch names the marker this item opens by this item's local name.
//!
//! Only a queued extraction attempt stages one: the commit's stamp must name
//! an attempt that is still in the queue as a Micro, Meso or Macro
//! consolidation attempt with a partition payload. An agent run cannot stage
//! one: its stamp carries its own run lease, which is never a queued
//! extraction branch.

use super::batch::DerivedConflict;
use super::commit::{ItemContext, ItemOutcome, refusal_receipt_in_txn};
use crate::error::Result;
use crate::{EntityId, Vault};

/// The refusal of a conflict item whose commit runs outside a queued
/// extraction attempt: it names no attempt, or its attempt is not in the
/// queue as a Micro, Meso or Macro consolidation attempt with a partition
/// payload.
pub const CONFLICT_NEEDS_EXTRACTION_ATTEMPT: &str =
    "gate.deny.derive.conflict_needs_extraction_attempt";

/// The refusal of a conflict item in a queued extraction attempt: the set
/// rebuild and the marker write are the next leaf (PR-B), so this leaf
/// stages nothing. This arm goes with it.
const CONFLICT_NOT_STAGED: &str = "gate.deny.derive.conflict_not_staged";

/// Stages a conflict item: it stages only inside a queued extraction
/// attempt. Outside one the item is refused; inside one it is refused too,
/// because the set rebuild and the marker write are the next leaf, which
/// stages from the item's operands. Each refusal writes the item's receipt
/// and lands nothing.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit, never a refusal.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    _item: &DerivedConflict,
) -> Result<ItemOutcome> {
    let Some(attempt) = context.stamp.attempt else {
        return refuse(vault, txn, context, CONFLICT_NEEDS_EXTRACTION_ATTEMPT);
    };
    let attempt = EntityId::from_bytes_unchecked(*attempt.as_bytes());
    match crate::snapshot_read::queued_extraction_branch_opt_in_txn(vault, txn, attempt)? {
        Some(_) => refuse(vault, txn, context, CONFLICT_NOT_STAGED),
        None => refuse(vault, txn, context, CONFLICT_NEEDS_EXTRACTION_ATTEMPT),
    }
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    reason: &str,
) -> Result<ItemOutcome> {
    let reasons = vec![reason.to_owned()];
    let receipt = refusal_receipt_in_txn(vault, txn, context, None, &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
