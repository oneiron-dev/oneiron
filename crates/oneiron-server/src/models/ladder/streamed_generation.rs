//! Stream-capable step replies on the generated-call walk.
//!
//! Only the terminal reply escapes this consumer. Admission, retries, source
//! checks, live spend looks and settlement stay on the original call's walk.
use futures_util::StreamExt;
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
            true,
        )
        .await
    }
}

/// Custom output parameters keep the buffered reply: Done carries no token
/// scores. The code-mode step producer supplies empty maps on its native path.
pub(super) fn can_stream(rung: &LadderRung, request: &LlmRequest) -> bool {
    request.params.is_empty()
        && request.provider_options.is_empty()
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
