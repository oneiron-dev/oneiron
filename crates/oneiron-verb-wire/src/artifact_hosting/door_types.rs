//! Moved from `crates/oneiron/src/artifact_hosting/door_types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::artifact_hosting::vocabulary::ArtifactPointerChannel;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::artifact_hosting::door_types::*;
use oneiron_store::artifact_hosting::vocabulary::ArtifactExportRef;
use oneiron_store::artifact_hosting::vocabulary::ArtifactPublishVerbStatus;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPointerRequest {
    pub artifact: String,
    pub channel: ArtifactPointerChannel,
}
