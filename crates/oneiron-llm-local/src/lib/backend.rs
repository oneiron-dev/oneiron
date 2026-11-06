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

    /// Generates while its caller keeps the request's owner alive.
    fn generate_borrowed<'a>(
        &'a self,
        request: &'a LlmRequest,
        abort: LocalAbortHandle,
    ) -> LlmResult<LocalGeneration<'a>>;
}

/// Adapter from a local in-process runtime into [`LlmBackend`].
#[derive(Debug, Clone)]
pub struct LocalLlmBackend<R> {
    runtime: R,
    catalog: LlmCatalogEntry,
}

impl<R> LocalLlmBackend<R>
where
    R: LocalLlmRuntime,
{
    #[must_use]
    #[cfg(test)]
    pub fn new(runtime: R) -> Self {
        let catalog = runtime.metadata().catalog_entry();
        Self { runtime, catalog }
    }

    pub fn from_registry(runtime: R, vault: &oneiron::Vault) -> oneiron::Result<Self> {
        let metadata = runtime.metadata().catalog_entry();
        let row = vault
            .model_registry_row(&metadata.model)?
            .ok_or_else(|| oneiron::Error::InvalidConfig("local model is not registered".into()))?;
        if row.wire != oneiron::llm::registry::ModelWireFormat::Local
            || row.catalog.locality != metadata.locality
        {
            return Err(oneiron::Error::InvalidConfig(
                "local registry wire/locality mismatch".into(),
            ));
        }
        let mut catalog = row.catalog;
        catalog.capabilities.retain(|c| metadata.supports(c));
        catalog.context_window_tokens = catalog
            .context_window_tokens
            .min(metadata.context_window_tokens);
        Ok(Self { runtime, catalog })
    }

    #[must_use]
    pub fn descriptor(&self) -> LlmCatalogEntry {
        self.catalog.clone()
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

async fn finish_generation(mut stream: LlmStream<'_>) -> LlmResult<LlmResponse> {
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

/// One generation per call, when the runtime generates once.
impl<R> oneiron::llm::SingleRouteBackend for LocalLlmBackend<R>
where
    R: LocalLlmRuntime + oneiron::llm::SingleSend,
{
    fn generate_borrowed_bound<'a>(
        &'a self,
        request: &'a LlmRequest,
        _lease: &'a BudgetLease,
        _digest: &'a str,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            validate_request(request, &self.descriptor())?;
            let abort = LocalAbortHandle::new();
            let generation = self.runtime.generate_borrowed(request, abort.clone())?;
            let stream = LlmStream::new(LocalEventStream::new(generation, abort.clone()));
            finish_generation(stream).await
        })
    }
    fn preflight(&self, request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        validate_request(request, &self.descriptor())
    }
}

impl<R> LlmBackend for LocalLlmBackend<R>
where
    R: LocalLlmRuntime,
{
    fn supports(&self, model: &oneiron::ModelId, capability: oneiron::LlmCapability) -> bool {
        let entry = self.descriptor();
        &entry.model == model && entry.supports(&capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let (stream, _abort) = self.stream_with_abort(request, lease)?;
            finish_generation(stream).await
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let (stream, _abort) = self.stream_with_abort(request, lease)?;
        Ok(stream)
    }
}
