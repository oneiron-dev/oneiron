//! Moved from `crates/oneiron/src/gate/policy_manifest_doors/entity_resolution_bands.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::gate::entity_resolution_bands::EntityResolutionBands;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityResolutionBandsConfigureRequest {
    pub expected_body_hash: String,
    pub bands: EntityResolutionBands,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntityResolutionBandsView {
    pub manifest_ref: String,
    pub body_hash: String,
    /// The effective trusted-manifest fold, including installed contributions.
    pub bands: EntityResolutionBands,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntityResolutionBandsReceipt {
    pub configuration: EntityResolutionBandsView,
    pub receipt_ref: String,
}
