//! A skill's erase in the attribution ledgers (FIX 8265, OF-568 L10): the
//! evidence rows and routed judgments that name an erased skill drop it in
//! the erase's own write, as a cause row does
//! ([`super::causes::erase_attribution_cause_entity_in_txn`]).
//!
//! An evidence row keeps its receipt and outcome with its skill slot nil, so
//! a projection that reads it again routes it with no skill to name. A
//! judgment's subject is the entity it charges and has no nil: a judgment
//! charging the erased skill goes, as does every edit proposal naming that
//! skill, and the projector, whose cursor is past them, routes neither again.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::codec::{EDIT_PROPOSAL, EVIDENCE, JUDGMENT};
use super::types::AttributionVerdict;

/// Forgets erased `entity` as the skill of every evidence row that names it.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_evidence_skill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let named: Vec<_> = EVIDENCE
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| row.evidence.skill == Some(*entity))
        .collect();
    for (sequence, mut row) in named {
        row.evidence.skill = None;
        EVIDENCE.put(&vault.store, wtxn, &sequence, &row)?;
    }
    Ok(())
}

/// Drops every judgment that charges erased `entity` as its skill, and every
/// edit proposal that names it.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_judgment_skill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let charged: Vec<u64> = JUDGMENT
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, judgment)| {
            judgment.subject == *entity
                && matches!(
                    judgment.verdict,
                    AttributionVerdict::SkillDefect | AttributionVerdict::Discovery
                )
        })
        .map(|(sequence, _)| sequence)
        .collect();
    for sequence in charged {
        JUDGMENT.delete(&vault.store, wtxn, &sequence)?;
    }
    let proposed: Vec<u64> = EDIT_PROPOSAL
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, proposal)| proposal.skill == *entity)
        .map(|(sequence, _)| sequence)
        .collect();
    for sequence in proposed {
        EDIT_PROPOSAL.delete(&vault.store, wtxn, &sequence)?;
    }
    Ok(())
}
