//! Moved from `crates/oneiron/src/gate/policy_manifest_doors/claim_aging.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::claim::aging_profiles::ClaimAgingProfiles;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimAgingProfilesConfigureRequest {
    pub expected_body_hash: String,
    pub profiles: ClaimAgingProfiles,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimAgingProfilesView {
    pub manifest_ref: String,
    pub body_hash: String,
    pub profiles: ClaimAgingProfiles,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimAgingProfilesReceipt {
    pub configuration: ClaimAgingProfilesView,
    pub receipt_ref: String,
}
