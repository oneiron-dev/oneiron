//! Moved from `crates/oneiron/src/code_run/dispatcher/connector_answer.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// `connector.answer`'s input (ONE-2510): the handle an `awaiting_input`
/// reply named, and one answer for each of its questions. It names no grant,
/// principal, endpoint or credential: the answer is checked under the
/// original call's, for the caller that made it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorAnswerRequest {
    /// The `handle` of the `awaiting_input` reply being answered.
    pub handle: String,
    /// Exactly one answer per question of that reply.
    pub answers: Vec<ConnectorQuestionAnswer>,
}

/// One answer to one question of an `awaiting_input` reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorQuestionAnswer {
    /// The question's `key`.
    pub key: String,
    pub action: ConnectorAnswerAction,
    /// The answer, a JSON object shaped by the question's
    /// `requested_schema`; only on `accept`.
    #[serde(default)]
    pub content: Option<Value>,
}

/// What an answer does with its question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorAnswerAction {
    /// Answer it with `content`.
    Accept,
    /// Refuse to answer it.
    Decline,
    /// Drop it unanswered.
    Cancel,
}
