//! Moved from `crates/oneiron/src/llm/manifest/doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_model::llm::LlmRequest;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::ModelLocality;
use oneiron_model::llm::ModelTierRef;
use oneiron_model::model_binding::ModelRole;
use oneiron_model::model_binding::ModelSlot;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Binds the Oneironer the server has loaded. The binding's identity is the
/// loaded slot's; these guards only compare with it, and a mismatch refuses.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OneironerBind {
    /// The checkpoint the caller expects the loaded Oneironer to serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_checkpoint_sha16: Option<String>,
    /// The stack the caller expects the loaded Oneironer to serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_stack_sha16: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteRead {
    pub slot: ModelSlot,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteReplace {
    pub slot: ModelSlot,
    pub route: ModelLocality,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelRouteView {
    pub slot: ModelSlot,
    pub pin: Option<ModelLocality>,
    pub route: Option<ModelLocality>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRoleRead {
    pub role: ModelRole,
}

/// A role's binding in one snapshot, not permission to execute it. A call
/// returns the same facts for the model and route its provider actually used.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelRoleReceipt {
    pub role: ModelRole,
    pub model: ModelId,
    pub revision: String,
    pub provider: String,
    pub slot: ModelSlot,
    pub tier: ModelTierRef,
    pub route: ModelLocality,
    /// BLAKE3 of the registered catalog entry in this snapshot, not a
    /// provider-supplied revision. None when the host alone attests the model.
    pub catalog_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRoleInvoke {
    pub role: ModelRole,
    pub input: ModelRoleInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelRoleInput {
    /// The role selects model and route; the request cannot override either.
    Generate { request: Box<LlmRequest> },
    /// A query through the vault's retrieval embedder, not a media seat.
    Embed { text: String },
    /// A write-free extraction over caller-supplied text, never a claim write.
    Tag { text: String },
}
