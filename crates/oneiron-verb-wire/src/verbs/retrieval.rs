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

/// Pins one blend weight at `value`, or clears its pin when `value` is
/// absent; or, with `read_shape` in place of `signal`, pins or clears the
/// read shape one model's runs work through. A request names exactly one.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicyPinRequest {
    #[serde(default)]
    pub signal: Option<RetrievalBlendSignal>,
    #[serde(default)]
    pub value: Option<f32>,
    #[serde(default)]
    pub read_shape: Option<ReadShapePinRequest>,
}

/// Pins `model`'s runs to `shape`, or clears the model's pin when `shape` is
/// absent. A pin beats every learned pick for that model.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadShapePinRequest {
    pub model: oneiron_model::llm::ModelId,
    #[serde(default)]
    pub shape: Option<ReadShape>,
}

/// What a run reads memory through (ARCH-0051 #decision-r9-bench). Both
/// shapes reach the same memory under the run's grant; the shape is the
/// environment the run's brief names. `oneiron` re-exports it as
/// `store::ReadShape`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReadShape {
    /// The typed memory verbs: the seeded default (RD-12).
    Verbs,
    /// The graph_fs mount, read with coreutils.
    Mount,
}

impl ReadShape {
    /// Both arms, the seeded default first: a tied draw picks the verbs.
    pub const ALL: [Self; 2] = [Self::Verbs, Self::Mount];
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
