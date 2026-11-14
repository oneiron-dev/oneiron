//! Moved from `crates/oneiron/src/verbs/reservoir_sources.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.coach.training_offers.sources`'s input: the reservoir scope a run
/// would export, as the prepare route reads it, and the sources ticked so
/// far.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReservoirSourcesRequest {
    /// Keep only pairs of these task classes; absent keeps every class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_classes: Option<Vec<String>>,
    /// Keep only pairs observed at or after this Unix second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// The sources the owner ticked "I obtained consent" for so far.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consented_sources: Vec<EntityId>,
}
