//! The run speech rows' wire types (census L8-25): `self.think.aloud`'s
//! input, and the bubble a run speech row answers with.

use serde::{Deserialize, Serialize};

/// `self.think.aloud`'s input (L8-25): the thought the run publishes, as
/// its text or as `{text}`, the shape `self.think` takes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ThinkAloudInput {
    /// The thought itself.
    Text(String),
    /// The thought as `{text}`.
    Spoken(SpokenText),
}

/// One utterance's words, as `{text}`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpokenText {
    /// The words.
    pub text: String,
}

impl ThinkAloudInput {
    /// The thought's words.
    #[must_use]
    pub fn into_text(self) -> String {
        match self {
            Self::Text(text) | Self::Spoken(SpokenText { text }) => text,
        }
    }
}

/// A run speech row's output: the bubble's place in the run's bridge order,
/// and whether the bubble is shown (`self.think.aloud`'s always is).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpeechOutput {
    /// The bubble's position in the run's bridge order.
    pub order: u32,
    /// Whether the bubble is shown.
    #[serde(rename = "isVisible")]
    pub is_visible: bool,
}
