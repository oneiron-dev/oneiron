//! Moved from `crates/oneiron/src/memory/channel_doors/selection.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::channel_identity_selection::selection_resolution::ChannelIdentitySelectionDecision;
use crate::channel_identity_selection::selection_resolution::SelectionRuleScope;
use crate::memory::channel_doors::*;
use oneiron_authority::channel_selection_vocabulary::ChannelIdentityFace;
use oneiron_authority::channel_selection_vocabulary::RelationshipContext;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Authorship fields are deliberately absent. The authenticated writer and
/// engine clock stamp the persisted row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSelectionRuleInput {
    pub rule_id: String,
    pub relationship: RelationshipContext,
    pub scope: SelectionRuleScope,
    pub face: ChannelIdentityFace,
    #[serde(default)]
    pub pinned_identity_ref: Option<EntityId>,
    pub priority: i32,
    pub enabled: bool,
    pub agent_amendable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelSelectionPatchInput {
    Upsert { rule: ChannelSelectionRuleInput },
    Remove { rule_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSelectionUpdateRequest {
    pub expected_revision: u64,
    pub patch: ChannelSelectionPatchInput,
}

/// Semantic face classification for a selection question, never send
/// authority. Shape and active state are read from live engine records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSelectionCandidateInput {
    pub identity_ref: EntityId,
    pub face: ChannelIdentityFace,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelSelectionView {
    pub revision: u64,
    pub decision: ChannelIdentitySelectionDecision,
    pub mask: ThreadMaskView,
}
