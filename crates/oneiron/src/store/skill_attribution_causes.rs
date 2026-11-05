//! Core half of `store::skill_attribution_causes`: its store-layer items live in `oneiron_store::skill_attribution_causes` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::skill_attribution_causes::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

/// One settled label. Key: blake3 of the terminal pack receipt id, then the
/// evidence sequence.
pub(crate) const CAUSES: SideTable<([u8; 32], u64), CauseRow, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_CAUSE);

/// Forgets erased `entity` on every cause row that names it, in the erase's
/// own write: an actor it executed or a skill it loaded (FIX 8265), each slot
/// nil, and the label stays with its receipt, as a call receipt keeps its row
/// and drops its identity. A later projection keeps the row's identity slots
/// as they are held (`skill_attribution::causes::put_attribution_cause_in_txn`),
/// so it never names either again.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_cause_entity_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let mut erased = Vec::new();
    for row in CAUSES.iter_from(&vault.store, wtxn, &[])? {
        let (key, row) = row?;
        if row.actor == Some(*entity) || row.skill == Some(*entity) {
            erased.push((key, row));
        }
    }
    for (key, mut row) in erased {
        if row.actor == Some(*entity) {
            row.actor = None;
        }
        if row.skill == Some(*entity) {
            row.skill = None;
        }
        CAUSES.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}
