//! An erase in the attribution ledgers (FIX 8265, OF-568 L10; FIX 8988): the
//! rows that name an erased skill or actor drop it in the erase's own write,
//! as a cause row does
//! ([`crate::store::skill_attribution_causes::erase_attribution_cause_entity_in_txn`]).
//!
//! An evidence row keeps its receipt and outcome with its skill or actor
//! slot nil, so a projection that reads it again routes it with no one to
//! name. A judgment charging an erased skill stays, its subject nil (FIX
//! 10640), while every edit proposal naming that skill goes, and the
//! projector, whose cursor is past them, routes neither again. A lapse
//! judgment charging an erased actor stays, its subject nil, and charges
//! no one.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
pub(crate) use crate::store::side_table_erase_scan::erase_scan_in_txn;

use super::codec::{EDIT_PROPOSAL, EVIDENCE, JUDGMENT};
use super::types::AttributionVerdict;

/// Forgets erased `entity` as the skill or the actor of every evidence row
/// that names it.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_evidence_skill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (sequence, mut row) in erase_scan_in_txn(vault, wtxn, EVIDENCE)? {
        let skill = row.evidence.skill == Some(*entity);
        let actor = row.evidence.actor == Some(*entity);
        if !skill && !actor {
            continue;
        }
        if skill {
            row.evidence.skill = None;
        }
        if actor {
            row.evidence.actor = None;
        }
        EVIDENCE.put(&vault.store, wtxn, &sequence, &row)?;
    }
    Ok(())
}

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
