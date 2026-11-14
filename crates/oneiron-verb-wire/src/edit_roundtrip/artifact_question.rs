//! Moved from `crates/oneiron/src/edit_roundtrip/artifact_question.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::blob_artifact::unit_refusal::UnitRefusal;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde_json::Value;
use std::time::Duration;
use std::time::Instant;

/// A unit the ask left unanswered, with its receipt; none when the unit had
/// no input to read or its state was past the call's bound.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct UnitAbstention {
    /// The unit, as the caller named it.
    pub unit: Value,
    pub decision: Option<TypedDecision>,
    /// The live body the ask read the unit on, when it read one: its decision
    /// names the head version as evidence (FIX 12018).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judged_live: Option<oneiron_store::typed_body::live_pin::LivePin>,
}
