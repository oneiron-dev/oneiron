//! The decision receipts behind each attempt-lane judgment (FIX 11512): the
//! judgment row is immutable by equality, so the receipts its judge's
//! decisions gave are kept beside it, written once with it. An outcome the
//! judge left unclear or labelled environment makes no judgment; its
//! receipts are kept the same way, beside its unclear and cause rows under
//! the same sequence (FIX 12075).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::DecisionReceipt;
use crate::side_table::{self, Named, SideTable};

/// Each judgment's decision receipts. Key: the judgment's evidence sequence.
const DECISION_RECEIPTS: SideTable<u64, DecisionReceiptsRow, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_DECISION_RECEIPTS);

/// [`DECISION_RECEIPTS`]'s stored row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionReceiptsRow {
    /// The receipt of each decision that gave the verdict, in hunk order.
    receipts: Vec<DecisionReceipt>,
}

/// Keeps `receipts` beside the judgment routed under `sequence`, in the
/// write that persists it. A judgment no ladder answered has none to keep,
/// and a row already kept stands: judgments are never rescored.
///
/// # Errors
///
/// Storage errors.
pub(super) fn keep_decision_receipts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    sequence: u64,
    receipts: &[DecisionReceipt],
) -> Result<()> {
    if receipts.is_empty() || DECISION_RECEIPTS.contains(&vault.store, wtxn, &sequence)? {
        return Ok(());
    }
    DECISION_RECEIPTS.put(
        &vault.store,
        wtxn,
        &sequence,
        &DecisionReceiptsRow {
            receipts: receipts.to_vec(),
        },
    )
}

/// The receipt of each decision that gave the attempt-lane judgment, or the
/// unclear or environment label, routed under `sequence`, in hunk order;
/// empty when no ladder answered it.
///
/// # Errors
///
/// Storage errors; a row that does not decode.
pub fn attribution_decision_receipts(vault: &Vault, sequence: u64) -> Result<Vec<DecisionReceipt>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(DECISION_RECEIPTS
        .get(&vault.store, &rtxn, &sequence)?
        .map_or_else(Vec::new, |row| row.receipts))
}

/// An erase's scrub over [`DECISION_RECEIPTS`] (FIX 3520): each receipt's
/// evidence pin naming `entity` goes, and a row with a receipt decided for
/// `entity` goes whole, since a receipt's principal has no erased form. The
/// judgment beside it keeps its own scrub.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_decision_receipts_entity_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (sequence, mut row) in super::erase_scan_in_txn(vault, wtxn, DECISION_RECEIPTS)? {
        if row
            .receipts
            .iter()
            .any(|receipt| receipt.principal == *entity)
        {
            DECISION_RECEIPTS.delete(&vault.store, wtxn, &sequence)?;
            continue;
        }
        let mut named = false;
        for receipt in &mut row.receipts {
            let pins = receipt.evidence_versions.len();
            receipt.evidence_versions.retain(|pin| pin.id != *entity);
            named |= receipt.evidence_versions.len() != pins;
        }
        if named {
            DECISION_RECEIPTS.put(&vault.store, wtxn, &sequence, &row)?;
        }
    }
    Ok(())
}
