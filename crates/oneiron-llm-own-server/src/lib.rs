//! Own-server LlmBackend. Transport belongs to oneiron-remote; policy stays above the trait.
use oneiron::{
    BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmCatalogEntry, LlmGenerateFuture,
    LlmRequest, LlmStreamResult, ModelId, ModelLocality,
};
pub use oneiron_remote::llm::{OwnServerTransport, RemoteLlmClient};
use std::collections::BTreeMap;
pub struct OwnServerBackend<T> {
    transport: T,
    models: BTreeMap<ModelId, LlmCatalogEntry>,
}
impl<T: OwnServerTransport> OwnServerBackend<T> {
    pub fn from_registry(vault: &oneiron::Vault, transport: T) -> oneiron::Result<Self> {
        let models = vault
            .model_catalog_entries(oneiron::llm::registry::ModelWireFormat::OwnServer)?
            .into_iter()
            .map(|m| (m.model.clone(), m))
            .collect();
        Ok(Self { transport, models })
    }
    fn admit(&self, request: &LlmRequest, stream: bool) -> oneiron::LlmResult<()> {
        if request.envelope.locality != ModelLocality::OwnServer {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.models
            .get(&request.model)
            .ok_or(FatalLlmError::InvalidRequest)?
            .admit(request, stream)
    }
}
impl<T: OwnServerTransport> LlmBackend for OwnServerBackend<T> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.models
            .get(model)
            .is_some_and(|e| e.supports(&capability))
    }
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            self.admit(&request, false)?;
            let response = self.transport.generate(request, lease).await?;
            validate_terminal(&response.message, &response.finish_reason)?;
            Ok(response)
        })
    }
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.admit(&request, true)?;
        Ok(oneiron::LlmStream::new(CheckedStream(
            self.transport.stream(request, lease)?,
        )))
    }
}
#[cfg(test)]
mod tests;

fn validate_terminal(
    message: &oneiron::LlmMessage,
    reason: &oneiron::FinishReason,
) -> oneiron::LlmResult<()> {
    if message.role != oneiron::LlmMessageRole::Assistant {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    if *reason != oneiron::FinishReason::Cancelled && (message.content.is_empty() || message.content.iter().all(|p| matches!(p, oneiron::ContentPart::Text {text} | oneiron::ContentPart::Reasoning {text,..} if text.trim().is_empty()))) {
        return Err(FatalLlmError::EmptyResponse.into());
    }
    for part in &message.content {
        let invalid = match part {
            oneiron::ContentPart::Text { .. } | oneiron::ContentPart::Reasoning { .. } => false,
            oneiron::ContentPart::ToolCall {
                call_id,
                name,
                input,
            } => call_id.trim().is_empty() || name.trim().is_empty() || !input.is_object(),
            // Tool results are history from a tool, never an assistant generation.
            oneiron::ContentPart::ToolResult { .. } => true,
            oneiron::ContentPart::Image { media_type, image } => {
                media_type.trim().is_empty()
                    || match image {
                        oneiron::ImageContent::Url { url } => url.trim().is_empty(),
                        oneiron::ImageContent::Base64 { data } => data.trim().is_empty(),
                    }
            }
        };
        if invalid {
            return Err(FatalLlmError::InvalidRequest.into());
        }
    }
    Ok(())
}
struct CheckedStream<'a>(oneiron::LlmStream<'a>);
impl futures_core::Stream for CheckedStream<'_> {
    type Item = oneiron::LlmResult<oneiron::LlmStreamEvent>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.get_mut().0).poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                if let oneiron::LlmStreamEvent::Done {
                    message,
                    finish_reason,
                    ..
                } = &event
                    && let Err(error) = validate_terminal(message, finish_reason)
                {
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(event)))
            }
            result => result,
        }
    }
}
