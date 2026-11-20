//! The question a remote task parks and the answer a poller claims (FIX
//! 16029): the types the served host names.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::owner_ask::{CANCEL, DECLINE};
use crate::model_decision::DecisionAnswer;

/// The domain a question's digest is taken under.
const QUESTION_DIGEST_DOMAIN: &str = "oneiron outbound remote task input question v1";

/// The MCP method of a form question.
const FORM_METHOD: &str = "elicitation/create";

/// One form question a remote task sent in its `tasks/result` stream, as the
/// served poller read it (MCP 2025-11-25 `elicitation/create`, mode `form`).
/// Opaque provider data: never logged.
#[derive(Clone)]
pub struct RemoteTaskFormQuestion {
    /// The MCP session the request came in (`Mcp-Session-Id`); `None` for a
    /// server that keeps no session.
    pub session: Option<String>,
    /// The request's JSON-RPC id, a string or a number.
    pub request_id: Value,
    /// The request's `message`.
    pub message: String,
    /// The request's `requestedSchema`.
    pub requested_schema: Value,
    /// The connector the send went to, as its ledger row names it.
    pub connector: String,
    /// The tool the send called, as its ledger row names it.
    pub tool: String,
}

impl fmt::Debug for RemoteTaskFormQuestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTaskFormQuestion")
            .field("session", &self.session.as_ref().map(|_| "[redacted]"))
            .field("connector", &self.connector)
            .field("tool", &self.tool)
            .finish_non_exhaustive()
    }
}

impl RemoteTaskFormQuestion {
    /// The question's digest: BLAKE3 under its own domain over the method and
    /// the canonical JSON (keys sorted) of the params the owner answers
    /// (`mode`, `message`, `requestedSchema`). The request id and the
    /// related-task metadata are not in it, so the same question sent again
    /// under a new request id has the same digest, and a changed one does
    /// not.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let params = canonical(json!({
            "mode": "form",
            "message": self.message,
            "requestedSchema": self.requested_schema,
        }));
        let mut hasher = blake3::Hasher::new_derive_key(QUESTION_DIGEST_DOMAIN);
        hasher.update(FORM_METHOD.as_bytes());
        hasher.update(&[0]);
        hasher.update(params.to_string().as_bytes());
        *hasher.finalize().as_bytes()
    }
}

#[doc(hidden)]
pub use oneiron_records::outbound_intent_ledger::remote_task_input::question::{
    ParkedInput, RemoteTaskInputPhase,
};

/// What the owner reads of a parked question.
#[derive(Clone, Serialize)]
pub struct RemoteTaskInputView {
    pub generation: u32,
    pub phase: RemoteTaskInputPhase,
    pub connector: String,
    pub tool: String,
    pub message: String,
    pub requested_schema: Value,
    pub field_names: Vec<String>,
    /// The owner Ask's arrival number.
    pub ask: u64,
    /// Vault clock seconds when the round was parked.
    pub parked_at: u64,
}

impl fmt::Debug for RemoteTaskInputView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTaskInputView")
            .field("generation", &self.generation)
            .field("phase", &self.phase)
            .field("connector", &self.connector)
            .field("tool", &self.tool)
            .field("fields", &self.field_names.len())
            .field("ask", &self.ask)
            .finish_non_exhaustive()
    }
}

/// The answer a poller claimed for a parked question.
pub struct RemoteTaskAnswer {
    /// The round it answers, for [`crate::Vault::record_remote_task_answer_sent_in_txn`].
    pub generation: u32,
    /// The parked request's JSON-RPC id. A question sent again comes under
    /// its own id, which the answer goes out with.
    pub request_id: Value,
    /// The MCP session the parked request came in.
    pub session: Option<String>,
    /// MCP's `ElicitResult` JSON: `action`, and `content` for an accept;
    /// no `_meta`.
    pub result: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for RemoteTaskAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTaskAnswer")
            .field("generation", &self.generation)
            .field(
                "result",
                &format_args!("[{} bytes redacted]", self.result.len()),
            )
            .finish_non_exhaustive()
    }
}

/// The owner's press on a parked question's Ask that carries no values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteTaskInputChoice {
    Decline,
    Cancel,
}

impl RemoteTaskInputChoice {
    /// The press an Ask answer names: its Decline or Cancel option; `None`
    /// for any other answer.
    #[must_use]
    pub fn of_answer(answer: &DecisionAnswer) -> Option<Self> {
        match answer {
            DecisionAnswer::Choice(choice) if choice == DECLINE => Some(Self::Decline),
            DecisionAnswer::Choice(choice) if choice == CANCEL => Some(Self::Cancel),
            _ => None,
        }
    }

    /// The phase the press sets.
    pub(super) const fn phase(self) -> RemoteTaskInputPhase {
        match self {
            Self::Decline => RemoteTaskInputPhase::Declined,
            Self::Cancel => RemoteTaskInputPhase::Cancelled,
        }
    }

    /// The Ask option the press answers.
    pub(super) const fn option(self) -> &'static str {
        match self {
            Self::Decline => DECLINE,
            Self::Cancel => CANCEL,
        }
    }
}

/// `value` with every object's keys in sorted order.
fn canonical(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical).collect()),
        Value::Object(entries) => {
            let sorted: BTreeMap<String, Value> = entries
                .into_iter()
                .map(|(key, value)| (key, canonical(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}
