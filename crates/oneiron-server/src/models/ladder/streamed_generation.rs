//! Stream-capable step replies on the generated-call walk.
//!
//! Only the terminal reply escapes this consumer. Admission, retries, source
//! checks, live spend looks and settlement stay on the original call's walk.
use futures_util::StreamExt;
use oneiron::code_run::HOST_PROVIDER_OPTIONS;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{
    FatalLlmError, LlmCapability, LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent,
    RetryableLlmError,
};

use super::{LadderRung, ModelCallBinding, OfferLadder};

impl OfferLadder {
    /// A generated reply from native streaming when this rung can serve it,
    /// otherwise its existing buffered call, with the same answering binding.
    pub(crate) async fn generate_recorded_streamed_while(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> LlmResult<(LlmResponse, ModelCallBinding)> {
        self.generate_from_streamed(
            run,
            request,
            selector,
            may_send,
            self.host_wait(),
            true,
            None,
            None,
            true,
        )
        .await
    }

    /// The same stream-preferring reply for a picked model, with no fallback.
    pub(crate) async fn generate_exact_recorded_streamed_while(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> LlmResult<(LlmResponse, ModelCallBinding)> {
        if !self.picked || self.rungs.len() != 1 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.generate_from_streamed(
            run,
            request,
            selector,
            may_send,
            self.host_wait(),
            false,
            None,
            None,
            true,
        )
        .await
    }
}

/// Native seat effort and host cache descriptors do not request extra response
/// fields. Other custom parameters keep the buffered reply, including scores.
pub(super) fn can_stream(rung: &LadderRung, request: &LlmRequest) -> bool {
    request
        .params
        .keys()
        .all(|param| param == "reasoning_effort")
        && request
            .provider_options
            .keys()
            .all(|namespace| namespace == HOST_PROVIDER_OPTIONS)
        && rung
            .offer
            .backend
            .supports(&rung.model, LlmCapability::Streaming)
        && rung
            .offer
            .backend
            .preflight(&rung.bind(request.clone()), true)
            .is_ok()
}

pub(super) async fn response(mut stream: LlmStream<'_>) -> LlmResult<LlmResponse> {
    while let Some(event) = stream.next().await {
        if let LlmStreamEvent::Done {
            message,
            usage,
            finish_reason,
            reply_assertions,
        } = event?
        {
            return Ok(LlmResponse {
                message,
                usage,
                finish_reason,
                reply_assertions,
                token_scores: None,
            });
        }
    }
    Err(RetryableLlmError::StreamCut.into())
}
