//! Moved from `crates/oneiron/src/artifact_hosting/door_types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::artifact_hosting::vocabulary::ArtifactPointerChannel;
pub use oneiron_store::artifact_hosting::door_types::*;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPointerRequest {
    pub artifact: String,
    pub channel: ArtifactPointerChannel,
}
