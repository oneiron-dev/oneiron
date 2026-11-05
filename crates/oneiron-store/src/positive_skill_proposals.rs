//! The pending positive skill proposals (`SKILL_ATTRIBUTION_POSITIVE_PROPOSAL`
//! rows): what a succeeded attempt taught its skill, cited to its receipt,
//! and the erase that drops the proposals naming an erased skill or actor.
//! The positive lane (`skill_attribution::positive`) writes and reads them;
//! the row's side-table declaration names its erase hook.
use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

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
