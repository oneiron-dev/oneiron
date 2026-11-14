//! Moved from `crates/oneiron/src/store/positive_skill_proposals.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
