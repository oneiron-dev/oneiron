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
        Ok(oneiron::LlmStream::new(CheckedStream {
            source: self.transport.stream(request, lease)?,
            parts: BTreeMap::new(),
        }))
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
#[derive(Debug, PartialEq, Eq)]
enum StreamPart {
    Text,
    Reasoning,
    Tool { call_id: String, name: String },
    Image { media_type: String },
    Closed,
}
struct CheckedStream<'a> {
    source: oneiron::LlmStream<'a>,
    parts: BTreeMap<String, StreamPart>,
}
impl CheckedStream<'_> {
    fn start(&mut self, id: &str, part: StreamPart) -> oneiron::LlmResult<()> {
        if id.trim().is_empty() || self.parts.contains_key(id) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.parts.insert(id.into(), part);
        Ok(())
    }
    fn end(&mut self, id: &str, expected: StreamPart) -> oneiron::LlmResult<()> {
        if self.parts.get(id) != Some(&expected) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.parts.insert(id.into(), StreamPart::Closed);
        Ok(())
    }
    fn validate_event(&mut self, event: &oneiron::LlmStreamEvent) -> oneiron::LlmResult<()> {
        use oneiron::LlmStreamEvent as Event;
        let invalid = match event {
            Event::TextStart { part_id } => return self.start(part_id, StreamPart::Text),
            Event::ReasoningStart { part_id, .. } => {
                return self.start(part_id, StreamPart::Reasoning);
            }
            Event::TextDelta { part_id, .. } => self.parts.get(part_id) != Some(&StreamPart::Text),
            Event::ReasoningDelta { part_id, .. } => {
                self.parts.get(part_id) != Some(&StreamPart::Reasoning)
            }
            Event::TextEnd { part_id } => return self.end(part_id, StreamPart::Text),
            Event::ReasoningEnd { part_id } => return self.end(part_id, StreamPart::Reasoning),
            Event::ToolCallStart {
                part_id,
                call_id,
                name,
            } => {
                if call_id.trim().is_empty() || name.trim().is_empty() {
                    true
                } else {
                    return self.start(
                        part_id,
                        StreamPart::Tool {
                            call_id: call_id.clone(),
                            name: name.clone(),
                        },
                    );
                }
            }
            Event::ToolCallDelta { part_id, .. } => {
                !matches!(self.parts.get(part_id), Some(StreamPart::Tool { .. }))
            }
            Event::ToolCallEnd {
                part_id,
                call_id,
                name,
                input,
            } => {
                if !input.is_object() || call_id.trim().is_empty() || name.trim().is_empty() {
                    true
                } else {
                    return self.end(
                        part_id,
                        StreamPart::Tool {
                            call_id: call_id.clone(),
                            name: name.clone(),
                        },
                    );
                }
            }
            Event::ImageStart {
                part_id,
                media_type,
            } => {
                if media_type.trim().is_empty() {
                    true
                } else {
                    return self.start(
                        part_id,
                        StreamPart::Image {
                            media_type: media_type.clone(),
                        },
                    );
                }
            }
            Event::ImageDelta { part_id, .. } => {
                !matches!(self.parts.get(part_id), Some(StreamPart::Image { .. }))
            }
            Event::ImageEnd {
                part_id,
                media_type,
                image,
            } => {
                let empty = match image {
                    oneiron::ImageContent::Url { url } => url.trim().is_empty(),
                    oneiron::ImageContent::Base64 { data } => data.trim().is_empty(),
                };
                if empty || media_type.trim().is_empty() {
                    true
                } else {
                    return self.end(
                        part_id,
                        StreamPart::Image {
                            media_type: media_type.clone(),
                        },
                    );
                }
            }
            Event::ToolResultStart { .. }
            | Event::ToolResultDelta { .. }
            | Event::ToolResultEnd { .. } => true,
            Event::Done {
                message,
                finish_reason,
                ..
            } => {
                validate_terminal(message, finish_reason)?;
                *finish_reason != oneiron::FinishReason::Cancelled
                    && self.parts.values().any(|part| *part != StreamPart::Closed)
            }
        };
        if invalid {
            Err(FatalLlmError::InvalidRequest.into())
        } else {
            Ok(())
        }
    }
}
impl futures_core::Stream for CheckedStream<'_> {
    type Item = oneiron::LlmResult<oneiron::LlmStreamEvent>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.source).poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                if let Err(error) = this.validate_event(&event) {
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(event)))
            }
            result => result,
        }
    }
}
