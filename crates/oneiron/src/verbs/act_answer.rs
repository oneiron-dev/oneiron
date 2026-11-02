//! What an act answers its caller (FIX 3414). The act runs as its caller's
//! authority asked, from whatever surface it asked; only the answer is judged
//! for where it goes. A caller off this device whose act's record, or a row
//! its reply would carry, stays on this device (DEC-0005) hears that the act
//! ran, and nothing of those rows. A connector's questions are the one
//! answer narrowed in part (FIX 5824): only the text of a question that
//! names such a row stays here, and the path to answer them leaves whole.
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An act's answer: its own reply, the content-free word that it ran and
/// its details stay on this device, or a connector's questions with the
/// text of those naming a row that stays here narrowed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ActAnswer<T> {
    /// The act ran; its details stay on the device that holds them.
    DetailsOnDevice(DetailsOnDevice),
    /// A connector's `awaiting_input` reply, narrowed for a caller off this
    /// device (FIX 5824).
    QuestionsNarrowed(NarrowedQuestions),
    /// The act's own reply.
    Done(T),
}

impl<T> ActAnswer<T> {
    /// The act ran, and its details stay on this device.
    #[must_use]
    pub const fn details_on_device() -> Self {
        Self::DetailsOnDevice(DetailsOnDevice {
            details_on_device: true,
        })
    }
}

/// The act ran; its details stay on this device. It carries nothing else:
/// no id, count or text of what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetailsOnDevice {
    /// Always `true`.
    pub details_on_device: bool,
}

/// A connector's `awaiting_input` reply for a caller off this device, some of
/// whose details name a row a world withheld from that caller keeps (FIX
/// 5824). Its answer path leaves whole: the handle `connector.answer` takes,
/// the call's ref, its source, the round's live lease and its reasons. A
/// question whose message or requested schema names such a row keeps its
/// key, and its text stays on this device (`on_device`); every other question
/// keeps its text. It carries none of the rows the call's reads listed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NarrowedQuestions {
    /// Always `awaiting_input`, as on the reply it narrows.
    pub outcome: String,
    /// Always `true`: some of the reply's details stay on this device.
    pub questions_narrowed: bool,
    pub handle: String,
    /// The call's ref, 32 hex, as `connector.call_status` reads it.
    pub call_ref: String,
    /// `connector:<name>.<tool>`.
    pub source: String,
    /// Always true: the connector wrote every question.
    pub foreign: bool,
    pub questions: Vec<NarrowedQuestion>,
    /// How long one answer waits on the owner in a single call (unix ms).
    pub live_until_ms: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// One question of a [`NarrowedQuestions`] reply: its key always, and its
/// message and requested schema unless they name a row that stays on this
/// device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NarrowedQuestion {
    /// The question's key in its round, which its answer names.
    pub key: String,
    /// The connector's message; absent when its text stays on this device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The JSON schema of the answer asked for; absent when its text stays
    /// on this device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_schema: Option<Value>,
    /// Whether this question's text stays on this device.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub on_device: bool,
}
