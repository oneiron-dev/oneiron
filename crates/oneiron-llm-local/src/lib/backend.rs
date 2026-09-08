//! LlmBackend adapter over a LocalLlmRuntime with abort-wired streaming.
use futures_util::StreamExt;
use oneiron::{
    BudgetLease, LlmBackend, LlmCatalogEntry, LlmGenerateFuture, LlmRequest, LlmResponse,
    LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, RetryableLlmError,
};

use super::abort::LocalAbortHandle;
use super::capabilities::validate_request;
use super::metadata::LocalModelMetadata;
use super::output::LocalGeneration;
use super::stream::LocalEventStream;

/// Minimal seam implemented by an in-process local runtime binding.
pub trait LocalLlmRuntime: Send + Sync {
    fn metadata(&self) -> &LocalModelMetadata;

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        abort: LocalAbortHandle,
    ) -> LlmResult<LocalGeneration<'a>>;
}

/// Adapter from a local in-process runtime into [`LlmBackend`].
#[derive(Debug, Clone)]
pub struct LocalLlmBackend<R> {
    runtime: R,
}

impl<R> LocalLlmBackend<R>
where
    R: LocalLlmRuntime,
{
    #[must_use]
    pub fn new(runtime: R) -> Self {
        Self { runtime }
    }

    #[must_use]
    pub fn descriptor(&self) -> LlmCatalogEntry {
        self.runtime.metadata().catalog_entry()
    }

    pub fn stream_with_abort<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmResult<(LlmStream<'a>, LocalAbortHandle)> {
        let descriptor = self.descriptor();
        validate_request(&request, &descriptor)?;

        let abort = LocalAbortHandle::new();
        let generation = self.runtime.generate(request, abort.clone())?;
        let stream = LocalEventStream::new(generation, abort.clone());
        Ok((LlmStream::new(stream), abort))
    }
}

impl<R> LlmBackend for LocalLlmBackend<R>
where
    R: LocalLlmRuntime,
{
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let (mut stream, _abort) = self.stream_with_abort(request, lease)?;
            while let Some(event) = stream.next().await {
                if let LlmStreamEvent::Done {
                    message,
                    usage,
                    finish_reason,
                } = event?
                {
                    return Ok(LlmResponse {
                        message,
                        usage,
                        finish_reason,
                    });
                }
            }

            Err(RetryableLlmError::StreamCut.into())
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let (stream, _abort) = self.stream_with_abort(request, lease)?;
        Ok(stream)
    }
}
