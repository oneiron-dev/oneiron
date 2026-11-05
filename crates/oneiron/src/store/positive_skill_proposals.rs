//! Core half of `store::positive_skill_proposals`: its store-layer items live in `oneiron_store::positive_skill_proposals` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::positive_skill_proposals::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

/// Positive proposals. Key: the attribution evidence sequence.
pub(crate) const POSITIVE_PROPOSAL: SideTable<u64, PositiveSkillProposal, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_POSITIVE_PROPOSAL);

/// Deletes every pending positive proposal that names erased `entity` as
/// its skill or its actor (FIX 8988): pending work whose authority ended
/// with it. A row that no longer decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_positive_proposals_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (sequence, proposal) in
        crate::store::side_table_erase_scan::erase_scan_in_txn(vault, wtxn, POSITIVE_PROPOSAL)?
    {
        if proposal.skill == *entity || proposal.actor == *entity {
            POSITIVE_PROPOSAL.delete(&vault.store, wtxn, &sequence)?;
        }
    }
    Ok(())
}
