//! Moved from `crates/oneiron/src/verbs/host/ask_image.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::verbs::host::ask_image::AskImageRequest;
use serde::Deserialize;
use serde::Serialize;

/// `ai.ask_image`'s answer: the vision model's text for a text question, or
/// the located answer and its decisions under a Box or Point contract, and
/// the receipt of the call that made it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AskImageAnswer {
    /// 32-hex ASSET id.
    pub asset_ref: String,
    /// The answer, in text, for a text question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The answer on the contract, for a question asked under one: a Box or
    /// a Point, `null` inside it for an absent target, or an abstention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<oneiron_store::model_decision::DecisionAnswer>,
    /// The decision that stands, for a question asked under an answer
    /// contract: the coordinates', or the presence step's when it found
    /// the target absent or stayed in doubt, with its confidence and
    /// receipt (the rungs' pins, the image's evidence version, its clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<oneiron_wake_contract::llm::decision::types::TypedDecision>,
    /// The presence step, when the coordinates stand on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<oneiron_wake_contract::llm::decision::types::TypedDecision>,
    pub receipt: AskImageReceipt,
}

/// What the call was: the pull its served-form record names, its run, the
/// seat's model and where it ran, and what it spent. A typed question that
/// abstained before the seat answered has no spend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AskImageReceipt {
    pub pull: String,
    pub run: String,
    pub model: oneiron_model::llm::ModelId,
    pub locality: oneiron_model::llm::ModelLocality,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<oneiron_model::llm::LlmUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<oneiron_model::llm::FinishReason>,
}
