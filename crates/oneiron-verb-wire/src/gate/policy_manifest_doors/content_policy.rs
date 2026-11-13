//! Moved from `crates/oneiron/src/gate/policy_manifest_doors/content_policy.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::gate;
use oneiron_policy_vocabulary::policy_model::contract::PolicyOutputContract;
use oneiron_policy_vocabulary::policy_model::pattern::PolicyPatternRule;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerPolicyConfiguration {
    #[serde(default)]
    pub owner_policy_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_policy_document: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_policy_output_contract: Option<PolicyOutputContract>,
    #[serde(default)]
    pub owner_policy_patterns: Vec<PolicyPatternRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerPolicyConfigureRequest {
    pub expected_body_hash: String,
    pub configuration: OwnerPolicyConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerPolicyConfigurationView {
    pub manifest_ref: String,
    pub body_hash: String,
    pub read_frontier_hash: String,
    /// The folded plane state, including other trusted contributions.
    pub enabled: bool,
    pub configuration: OwnerPolicyConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerPolicyConfigurationReceipt {
    pub configuration: OwnerPolicyConfigurationView,
    pub receipt_ref: String,
}
