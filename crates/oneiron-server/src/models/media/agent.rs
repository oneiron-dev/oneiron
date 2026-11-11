//! Call-local agent attribution and frozen model lists for media calls.

use oneiron::EntityId;
use oneiron::agent_def::AgentModel;
use oneiron::llm::run_admission::MediaStreamLease;

use super::{
    AiOperation, Arc, FatalLlmError, LlmResult, MediaDispatchRelease, MediaRequest, MediaResponse,
    MediaRuntime, OfferLadder, PayerPerson,
};

/// Attribution and routing metadata, supplied after the caller's real admission.
#[derive(Clone, Copy)]
pub(crate) struct AgentMediaCall<'a> {
    pub(crate) caller: EntityId,
    pub(crate) models: &'a [AgentModel],
}

impl MediaRuntime {
    pub(super) fn ladder_for_model_list(
        &self,
        request: &MediaRequest,
        listed: Option<&[AgentModel]>,
    ) -> LlmResult<Arc<OfferLadder>> {
        let ladder = self.ladder(request)?;
        let Some(listed) = listed.filter(|listed| !listed.is_empty()) else {
            return Ok(ladder);
        };
        let ladder = ladder
            .for_model_list(listed)
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        Ok(Arc::new(ladder))
    }

    pub(crate) async fn run_for_agent(
        &self,
        request: MediaRequest,
        payer: Option<PayerPerson>,
        sources: Option<Vec<EntityId>>,
        agent: AgentMediaCall<'_>,
        release: MediaDispatchRelease<'_>,
    ) -> LlmResult<MediaResponse> {
        let run = self
            .media_run(payer, sources)?
            .initiated_by(Some(agent.caller));
        self.run_admitted_released(&run, request, None, None, release, Some(agent.models))
            .await
    }

    pub(crate) fn open_stream_for_agent(
        &self,
        request: MediaRequest,
        bound_ms: u64,
        payer: Option<PayerPerson>,
        sources: Option<Vec<EntityId>>,
        agent: AgentMediaCall<'_>,
    ) -> LlmResult<MediaStreamLease> {
        self.open_stream_with_agent(request, bound_ms, payer, sources, Some(agent))
    }

    pub(super) fn open_stream_with_agent(
        &self,
        request: MediaRequest,
        bound_ms: u64,
        payer: Option<PayerPerson>,
        sources: Option<Vec<EntityId>>,
        agent: Option<AgentMediaCall<'_>>,
    ) -> LlmResult<MediaStreamLease> {
        if request.operation != AiOperation::Transcribe || bound_ms == 0 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let ladder =
            self.ladder_for_model_list(&request, agent.as_ref().map(|agent| agent.models))?;
        let run = self.media_run(payer, sources)?;
        let run = match agent {
            Some(agent) => run.initiated_by(Some(agent.caller)),
            None => run,
        };
        ladder.open_media_stream(&run, request, bound_ms)
    }
}
