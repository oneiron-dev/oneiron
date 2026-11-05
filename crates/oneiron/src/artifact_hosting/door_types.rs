//! Core half of `artifact_hosting::door_types`: its store-layer items live in `oneiron_store::artifact_hosting::door_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::artifact_hosting::door_types::*;

use super::{
    ArtifactExportRef, ArtifactPointer, ArtifactPointerChannel, ArtifactPublishVerbStatus,
    ArtifactServeTier,
};
use crate::EntityId;
use serde::{Deserialize, Serialize};

/// One exact immutable export and explicit audience. The host binds the actor;
/// neither this input nor an owner credential replaces the publication Gate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPublishRequest {
    pub artifact: String,
    pub channel: ArtifactPointerChannel,
    pub export: ArtifactExportRef,
    pub serve_tier: ArtifactServeTier,
    /// Retry identity for this exact effect; repointing needs a new identity.
    pub publish_id: EntityId,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPointerRequest {
    pub artifact: String,
    pub channel: ArtifactPointerChannel,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactPublishView {
    pub status: ArtifactPublishVerbStatus,
    pub pointer: Option<ArtifactPointer>,
    /// The durable engine share receipt, readable through the receipt doors.
    pub receipt_ref: Option<String>,
    pub gate_decision_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactLinkToken {
    pub serve_tier: ArtifactServeTier,
    /// Returned once; only the serving digest belongs in a publish request.
    pub token: String,
}
