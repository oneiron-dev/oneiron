//! The attribution judge's durable verdicts and the edit proposals they mint
//! (`SKILL_ATTRIBUTION_JUDGMENT`, `SKILL_ATTRIBUTION_EDIT_PROPOSAL` rows), and
//! the erase that clears an erased skill from them. Skill attribution
//! (`skill_attribution`) routes, mints and applies them; the judgment row's
//! side-table declaration names its erase hook.
use oneiron_skill_attribution::types::{
    AttributionJudgment, AttributionVerdict, SkillEditProposal,
};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::side_table_erase_scan::erase_scan_in_txn;

/// One durable attribution verdict routed from evidence. Key: u64be evidence sequence.
pub(crate) const JUDGMENT: SideTable<u64, AttributionJudgment, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_JUDGMENT);

/// One minted skill-edit proposal awaiting gated apply. Key: u64be judgment sequence.
pub(crate) const EDIT_PROPOSAL: SideTable<u64, SkillEditProposal, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_EDIT_PROPOSAL);

/// Erases the subject of every judgment that charges erased `entity` as
/// its skill, keeping the row (FIX 10640), and drops every edit proposal
/// that names it; a lapse judgment that charges it as its actor stays, its
/// subject nil.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_judgment_skill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (sequence, mut judgment) in erase_scan_in_txn(vault, wtxn, JUDGMENT)? {
        if judgment.subject != Some(*entity) {
            continue;
        }
        match judgment.verdict {
            AttributionVerdict::SkillDefect
            | AttributionVerdict::Discovery
            | AttributionVerdict::ExecutionLapse => {
                judgment.subject = None;
                JUDGMENT.put(&vault.store, wtxn, &sequence, &judgment)?;
            }
            _ => {}
        }
    }
    for (sequence, proposal) in erase_scan_in_txn(vault, wtxn, EDIT_PROPOSAL)? {
        if proposal.skill == *entity {
            EDIT_PROPOSAL.delete(&vault.store, wtxn, &sequence)?;
        }
    }
    Ok(())
}
