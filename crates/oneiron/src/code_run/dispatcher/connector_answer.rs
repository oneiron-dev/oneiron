//! `connector.answer` (ONE-2510): a run's answer to the questions one of its
//! connector calls waits on, sent through the bound door.

use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_DOOR_UNBOUND, AGENT_VERB_SESSION_BOUND, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfEffect,
};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ExecutorCallSite, HostSelfDispatcher};

impl HostSelfDispatcher<'_> {
    /// The run's answer, through the bound door, which checks it under the
    /// original call's grant and principal and answers with `connector.call`'s
    /// reply, foreign data included. A run whose host binds no door is
    /// refused, as a run bound to an off-record session is: the door sends on
    /// the canonical vault, outside the session's route. A refusal is the
    /// guest's to handle.
    pub(super) fn dispatch_connector_answer(
        &self,
        request: ConnectorAnswerRequest,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let refused = |code: String| {
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: SelfEffect::ConnectorAnswer,
                outcome: code,
                reason_codes: Vec::new(),
            })
        };
        if matches!(self.storage, ExecutorStorage::Session(_)) {
            return Ok(refused(AGENT_VERB_SESSION_BOUND.to_owned()));
        }
        let Some(door) = &self.agent_verbs else {
            return Ok(refused(AGENT_VERB_DOOR_UNBOUND.to_owned()));
        };
        let invocation = self.verb_invocation(&SelfCall::ConnectorAnswer(request.clone()), site)?;
        Ok(match door.connector_answer(&request, invocation)? {
            Ok(answer) => SelfDispatchOutcome::AgentVerb(answer),
            Err(refusal) => refused(refusal.code),
        })
    }
}

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
