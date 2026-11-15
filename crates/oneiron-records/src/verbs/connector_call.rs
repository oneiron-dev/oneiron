//! Moved from `crates/oneiron/src/verbs/connector_call.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::code_run::consent_wait::CONNECTOR_QUESTIONS_NOT_RETAINED;
pub use crate::code_run::consent_wait::CONNECTOR_RESULT_CREDENTIAL_CLEAR_FAILED;
pub use crate::code_run::consent_wait::CONNECTOR_RESULT_NOT_RETAINED;
pub use crate::code_run::consent_wait::ConnectorCallReply;
pub use crate::code_run::consent_wait::ConnectorToolResult;
pub use oneiron_verb_wire::code_run::dispatcher::connector_answer::ConnectorAnswerAction;
pub use oneiron_verb_wire::code_run::dispatcher::connector_answer::ConnectorAnswerRequest;
pub use oneiron_verb_wire::code_run::dispatcher::connector_answer::ConnectorQuestionAnswer;
use oneiron_verb_wire::verbs::act_answer::ActAnswer;
pub use oneiron_verb_wire::verbs::connector_call::ConnectorCallApproveOnceRequest;
pub use oneiron_verb_wire::verbs::connector_call::ConnectorCallStatusRequest;
pub use oneiron_verb_wire::verbs::connector_call::ConnectorSchemaRequest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// `connector.schema`'s reply: the tool's approved input schema on the
/// governing key the caller's own grant resolves, or why there is none. The
/// schema's text is the connector's, approved by the owner: it is marked
/// foreign too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorSchemaReply {
    /// `connector:<name>.<tool>`.
    pub source: String,
    /// Always true.
    pub foreign: bool,
    /// The approved input schema; absent when none is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    /// Whether the tool's slate row marks it destructive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
    /// The hold or refusal a call of the tool would meet first, when no
    /// schema is available.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// `connector.call_status`'s answer: where one held call stands, for its
/// caller or the vault's owner. Its reply is `connector.call`'s own, so a
/// delivered tool's reply stays foreign data under `result`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectorCallStatus {
    /// Held for consent or governance, or its send still retrying: nothing
    /// answered it yet. The settler resumes it on its own; read again later.
    Pending {
        call_ref: String,
        name: String,
        tool: String,
        /// When it was first held (unix ms); its expiry counts from here.
        held_at_ms: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reasons: Vec<String>,
        /// FIX 6424 part 3: the approve-once digest the call's approvable
        /// hold named, kept with it: the owner's press on it releases
        /// exactly the call as it was prepared.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval_digest: Option<String>,
    },
    /// Settled: the reply its wait settled with, as `connector.call` would
    /// have answered.
    Settled {
        call_ref: String,
        name: String,
        tool: String,
        reply: ConnectorCallReply,
    },
    /// Sent, and its connector asks for input (FIX 3837): round
    /// `generation`, `asked` questions, kept on the call's row; answer them
    /// with `connector.answer` and the reply's handle. A served reader joins
    /// the matching live questions; the row itself never keeps their text.
    /// Question text that stays on this device narrows inside `reply`, while
    /// the round's metadata stays whole. `uncertain` when the live exchange ended
    /// unanswered (a restart, a lost stream): the questions stand, and their
    /// delivery is not known.
    AwaitingInput {
        call_ref: String,
        name: String,
        tool: String,
        generation: u64,
        asked: usize,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        uncertain: bool,
        reply: ActAnswer<ConnectorCallReply>,
    },
}
