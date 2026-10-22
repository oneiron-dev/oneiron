//! The positive lane (OF-379): a win that taught the skill something.
//!
//! The blame projector abstains on every succeeded attempt, because crediting
//! a plain win is the reliability posterior's job. Two wins are more than a
//! win: the actor deviated from the loaded skill with a stated reason and
//! succeeded, or it performed a step the skill did not cover and succeeded.
//! Either one says the skill's text should change, so it becomes a positive
//! skill proposal: evidence handed to the optimizer, never an applied edit.
//! The optimizer's held-out gate decides whether the change lands.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::codec::{EVIDENCE, evidence_after};
use super::types::{AttemptOutcome, FollowedState, OutcomeEvidence};

/// Positive proposals. Key: the attribution evidence sequence.
const POSITIVE_PROPOSAL: SideTable<u64, PositiveSkillProposal, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_POSITIVE_PROPOSAL);

/// The highest evidence sequence the positive lane has read. Key: ().
const POSITIVE_CURSOR: SideTable<(), u64, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_POSITIVE_CURSOR);

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

/// The finding a succeeded attempt carries, if any.
#[must_use]
pub fn positive_finding(evidence: &OutcomeEvidence) -> Option<PositiveFinding> {
    if evidence.outcome != AttemptOutcome::Succeeded || evidence.skill.is_none() {
        return None;
    }
    match &evidence.followed_state {
        Some(FollowedState::DeviatedWithReason { reason, .. }) if !reason.trim().is_empty() => {
            return Some(PositiveFinding::DeviationWorked {
                reason: reason.clone(),
            });
        }
        Some(FollowedState::Ignored) => return None,
        _ => {}
    }
    (evidence.skill_covered_step == Some(false)).then_some(PositiveFinding::UncoveredStepWorked)
}

/// Reads the attribution evidence past the lane's cursor and mints one
/// positive proposal per succeeded attempt that taught its skill. Returns the
/// proposals this pass minted. Off the hot path; replays are idempotent.
///
/// # Errors
///
/// Storage errors.
pub fn run_positive_attribution_pass(vault: &Vault) -> Result<Vec<PositiveSkillProposal>> {
    let since = {
        let rtxn = vault.store.env.read_txn()?;
        POSITIVE_CURSOR.get(&vault.store, &rtxn, &())?.unwrap_or(0)
    };
    let pending = evidence_after(vault, since)?;
    let mut highest = since;
    let mut minted = Vec::new();
    for (sequence, evidence) in &pending {
        highest = highest.max(*sequence);
        let (Some(finding), Some(skill), Some(actor)) =
            (positive_finding(evidence), evidence.skill, evidence.actor)
        else {
            continue;
        };
        minted.push(PositiveSkillProposal {
            evidence_sequence: *sequence,
            skill,
            actor,
            finding,
            evidence_receipts: vec![evidence.receipt_ref.clone()],
            at: evidence.at,
        });
    }
    vault.with_write_txn_grouped(|wtxn| {
        let mut kept = Vec::with_capacity(minted.len());
        for proposal in minted {
            // An erase since the read left its evidence naming no one: the
            // proposal is not made (FIX 8988).
            let live = EVIDENCE
                .get(&vault.store, wtxn, &proposal.evidence_sequence)?
                .is_some_and(|row| {
                    row.evidence.skill == Some(proposal.skill)
                        && row.evidence.actor == Some(proposal.actor)
                });
            if !live {
                continue;
            }
            POSITIVE_PROPOSAL.put(&vault.store, wtxn, &proposal.evidence_sequence, &proposal)?;
            kept.push(proposal);
        }
        if highest > since {
            POSITIVE_CURSOR.put(&vault.store, wtxn, &(), &highest)?;
        }
        Ok(kept)
    })
}

/// Every positive proposal still waiting for the optimizer, oldest first.
///
/// # Errors
///
/// Storage errors.
pub fn pending_positive_proposals(vault: &Vault) -> Result<Vec<PositiveSkillProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(POSITIVE_PROPOSAL
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, proposal)| proposal)
        .collect())
}

/// Retires a positive proposal once the optimizer has drafted from it (or
/// declined it). Returns whether one was waiting.
///
/// # Errors
///
/// Storage errors.
pub fn retire_positive_proposal(vault: &Vault, evidence_sequence: u64) -> Result<bool> {
    vault.with_write_txn_grouped(|wtxn| {
        POSITIVE_PROPOSAL.delete(&vault.store, wtxn, &evidence_sequence)
    })
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
        super::skill_erase::erase_scan_in_txn(vault, wtxn, POSITIVE_PROPOSAL)?
    {
        if proposal.skill == *entity || proposal.actor == *entity {
            POSITIVE_PROPOSAL.delete(&vault.store, wtxn, &sequence)?;
        }
    }
    Ok(())
}
