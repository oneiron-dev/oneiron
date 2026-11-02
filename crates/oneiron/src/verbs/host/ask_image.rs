//! `ai.ask_image`'s input, answer and receipt (OF-329, FIX 679): one
//! question about an image's pixels to the host's Local-vision seat, by the
//! view handle the image was served with. `POST /v1/ai/ask_image` and the
//! verb's host door share these shapes and one answering path; an embedded
//! handle has no seat and refuses it.
use serde::{Deserialize, Serialize};

/// `ai.ask_image`'s input. The pixels are read, and the pull recorded,
/// through the caller's own lane before any model is called; the call runs
/// on the caller's budget line, as a chat turn does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AskImageRequest {
    /// The view handle the image was served with (`<asset>@<hash>`).
    pub handle: String,
    /// What to ask about its pixels.
    pub question: String,
    /// A region to ask about, in the image's own pixels; the whole image
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<crate::memory::PixelRegion>,
    /// The answer contract to ask under; a text answer when absent. The
    /// Local-vision slot answers a Box or a Point, over the whole image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<crate::llm::decision::AnswerContract>,
}

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
    pub answer: Option<crate::llm::decision::DecisionAnswer>,
    /// The decision that stands, for a question asked under an answer
    /// contract: the coordinates', or the presence step's when it found
    /// the target absent or stayed in doubt, with its confidence and
    /// receipt (the rungs' pins, the image's evidence version, its clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<crate::llm::decision::TypedDecision>,
    /// The presence step, when the coordinates stand on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<crate::llm::decision::TypedDecision>,
    pub receipt: AskImageReceipt,
}

/// What the call was: the pull its served-form record names, its run, the
/// seat's model and where it ran, and what it spent. A typed question that
/// abstained before the seat answered has no spend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AskImageReceipt {
    pub pull: String,
    pub run: String,
    pub model: crate::llm::ModelId,
    pub locality: crate::llm::ModelLocality,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<crate::llm::LlmUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<crate::llm::FinishReason>,
}
