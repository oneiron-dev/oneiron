//! The attempt row behind each attributed outcome (FIX 7288): the row ids a
//! sourced held-out read names beside its receipts.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::ledger::attributed_outcomes_weighted;

/// One row id per receipt of [`super::ledger::attributed_outcome_receipts`],
/// in its order: the attempt row each outcome cites. `None` when any receipt
/// names no row. Capture only: the ledger is read, never refused.
///
/// # Errors
///
/// Storage errors; a typed side-table row error on a malformed outcome key.
pub(crate) fn attributed_outcome_row_ids(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Option<Vec<EntityId>>> {
    let mut ids = Vec::new();
    for (receipt, _) in attributed_outcomes_weighted(vault, rtxn, skill)? {
        let Some(id) = outcome_row_id(&receipt) else {
            return Ok(None);
        };
        ids.push(id);
    }
    Ok(Some(ids))
}

/// The attempt row `receipt` cites: a pack receipt id is `attempt:` and its
/// attempt's hex ([`crate::receipt::attempt_pack_receipt_id`]), which reads
/// back as that attempt's row id. `None` for a receipt that names none.
fn outcome_row_id(receipt: &str) -> Option<EntityId> {
    let hex = receipt.strip_prefix("attempt:")?;
    let id = EntityId::from_hex(hex).ok()?;
    (id.to_hex() == hex).then_some(id)
}
