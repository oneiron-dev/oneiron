//! `connector.answer` (ONE-2510): a run's answer to the questions one of its
//! connector calls waits on, sent through the bound door.

use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_DOOR_UNBOUND, AGENT_VERB_SESSION_BOUND, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfEffect,
};
use crate::error::Result;
use crate::task_verb::sdk::ConnectorAnswerRequest;

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
