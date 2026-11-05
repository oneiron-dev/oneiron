//! The pending positive skill proposals (`SKILL_ATTRIBUTION_POSITIVE_PROPOSAL`
//! rows): what a succeeded attempt taught its skill, cited to its receipt,
//! and the erase that drops the proposals naming an erased skill or actor.
//! The positive lane (`skill_attribution::positive`) writes and reads them;
//! the row's side-table declaration names its erase hook.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// Positive proposals. Key: the attribution evidence sequence.
pub(crate) const POSITIVE_PROPOSAL: SideTable<u64, PositiveSkillProposal, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_POSITIVE_PROPOSAL);

/// What a succeeded attempt taught its skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PositiveFinding {
    /// The actor departed from the skill for `reason`, and the attempt won.
    DeviationWorked { reason: String },
    /// The actor performed a step the skill did not cover, and the attempt won.
    UncoveredStepWorked,
}

/// One positive skill proposal, cited to the receipt that earned it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositiveSkillProposal {
    pub evidence_sequence: u64,
    pub skill: EntityId,
    /// The executing actor whose departure or extra step worked.
    pub actor: EntityId,
    pub finding: PositiveFinding,
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

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
