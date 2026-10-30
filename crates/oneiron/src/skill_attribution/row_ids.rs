//! The row behind each forwarded judgment and discovery proposal (FIX 12088):
//! the row ids a sourced brief names beside what it forwards.
//!
//! Judgments and proposals are u64-keyed, so no receipt string witnesses them
//! the way an `attempt:` receipt witnesses its attempt row
//! ([`crate::skill_reliability::attributed_outcome_row_ids`], FIX 7288). Each
//! row carries its own id instead, minted when it is written; these readers
//! map in-hand rows to those ids.

use crate::entity_id::EntityId;

use super::types::{AttributionJudgment, SkillEditProposal};

/// One row id per judgment, in order: the [`AttributionJudgment::row_id`] each
/// was written with. Capture only: the rows are named, never refused.
pub(crate) fn attribution_judgment_row_ids(judgments: &[AttributionJudgment]) -> Vec<EntityId> {
    judgments.iter().map(|judgment| judgment.row_id).collect()
}

/// One row id per proposal, in order: the [`SkillEditProposal::row_id`] each
/// was written with. Capture only: the rows are named, never refused.
pub(crate) fn edit_proposal_row_ids(proposals: &[SkillEditProposal]) -> Vec<EntityId> {
    proposals.iter().map(|proposal| proposal.row_id).collect()
}
