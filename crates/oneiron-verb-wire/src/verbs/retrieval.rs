//! Moved from `crates/oneiron/src/verbs/retrieval.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::retrieval_depth::controls::RecallTelemetry;
use oneiron_contracts::retrieval_telemetry::RetrievalBlendSignal;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalRunsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalTurnRequest {
    pub turn_id: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalTraceRequest {
    pub fork_hash: [u8; 32],
}

/// Pins one blend weight at `value`, or clears its pin when `value` is absent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicyPinRequest {
    pub signal: RetrievalBlendSignal,
    #[serde(default)]
    pub value: Option<f32>,
}

/// One model-manifest route the owner's manifest currently pins.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalRoutingPin {
    pub slot: oneiron_model::model_binding::ModelSlot,
    pub locality: oneiron_model::llm::ModelLocality,
}

/// Whether a declared update was served or left as an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPolicyDisposition {
    Applied,
    Offered,
}
