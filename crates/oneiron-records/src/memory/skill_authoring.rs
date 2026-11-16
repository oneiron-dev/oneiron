//! Moved from `crates/oneiron/src/memory/skill_authoring.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The skill and its immutable birth-author receipt, not an activation grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillAuthoringReceipt {
    #[serde(with = "super::authorship::entity_serde")]
    pub skill_id: EntityId,
    #[serde(with = "super::authorship::entity_serde")]
    pub author: EntityId,
    pub author_receipt: String,
    pub version: String,
}
