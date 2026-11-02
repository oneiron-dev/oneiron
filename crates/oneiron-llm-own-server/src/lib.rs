//! Own-server LlmBackend. Transport belongs to oneiron-remote; policy stays above the trait.
//! [`mesh`] is the transport to a model on another of the owner's nodes (OF-575 MESH).
mod emitted;
pub mod mesh;
use emitted::Emitted;
pub use mesh::{
    COST_DECLARED, CatalogRefresh, DEFAULT_STAGING_BYTES, LLM_ALPN, LlmMeshHandler, LlmMeshService,
    LlmNodes, MESH_PEER, MeshLlmTransport, MeshPeerProof, MeshPeerTransport, StagingBudget,
    VaultLlmNodes, advertises,
};
use oneiron::{
    BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmCatalogEntry, LlmGenerateFuture,
    LlmRequest, LlmStreamResult, ModelId, ModelLocality,
};
pub use oneiron_remote::llm::{OwnServerTransport, RemoteLlmClient};
use std::collections::BTreeMap;
use std::sync::{PoisonError, RwLock};
pub struct OwnServerBackend<T> {
    transport: T,
    /// The vault's own-server rows, as last read.
    models: RwLock<BTreeMap<ModelId, LlmCatalogEntry>>,
}
fn own_server_models(
    vault: &oneiron::Vault,
) -> oneiron::Result<BTreeMap<ModelId, LlmCatalogEntry>> {
    Ok(vault
        .model_catalog_entries(oneiron::llm::registry::ModelWireFormat::OwnServer)?
        .into_iter()
        .map(|m| (m.model.clone(), m))
        .collect())
}
impl<T: OwnServerTransport> OwnServerBackend<T> {
    pub fn from_registry(vault: &oneiron::Vault, transport: T) -> oneiron::Result<Self> {
        Ok(Self {
            transport,
            models: RwLock::new(own_server_models(vault)?),
        })
    }
    /// Reads the vault's own-server rows again, after a row was written.
    pub fn reload(&self, vault: &oneiron::Vault) -> oneiron::Result<()> {
        *self.models.write().unwrap_or_else(PoisonError::into_inner) = own_server_models(vault)?;
        Ok(())
    }
    fn admit(&self, request: &LlmRequest, stream: bool) -> oneiron::LlmResult<()> {
        if request.envelope.locality != ModelLocality::OwnServer {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.models
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&request.model)
            .ok_or(FatalLlmError::InvalidRequest)?
            .admit(request, stream)
    }
}
impl<T: OwnServerTransport> OwnServerBackend<T> {
    /// Serves exactly `models` over `transport`, without reading the vault:
    /// the rows a router built a node's routes from (FIX 3229).
    pub fn serving(transport: T, models: impl IntoIterator<Item = LlmCatalogEntry>) -> Self {
        Self {
            transport,
            models: RwLock::new(models.into_iter().map(|m| (m.model.clone(), m)).collect()),
        }
    }
}
impl OwnServerBackend<MeshLlmTransport> {
    /// Learns the models the owner's other nodes offer, writes their rows
    /// ([`MeshLlmTransport::refresh_catalog`]) and reads the rows again. The
    /// host runs it when the backend starts and when the mesh changes.
    ///
    /// # Errors
    /// A row could not be read or written.
    pub async fn refresh_from_mesh(
        &self,
        vault: &oneiron::Vault,
    ) -> oneiron::Result<CatalogRefresh> {
        let refresh = self.transport.refresh_catalog(vault).await?;
        self.reload(vault)?;
        Ok(refresh)
    }
}
/// One request to the own server per call, when the transport sends once.
impl<T: OwnServerTransport + oneiron::llm::SingleSend> oneiron::llm::SingleRouteBackend
    for OwnServerBackend<T>
{
    fn preflight(&self, request: &LlmRequest, stream: bool) -> oneiron::LlmResult<()> {
        self.admit(request, stream)
    }
}

impl<T: OwnServerTransport> LlmBackend for OwnServerBackend<T> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.models
            .read()
            .unwrap_or_else(PoisonError::into_inner)
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
            emitted: Emitted::default(),
            ended: false,
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
            // Input audio is history, never an assistant generation.
            oneiron::ContentPart::Audio { .. } => true,
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
    /// What the stream has shown its caller (FIX 8617).
    emitted: Emitted,
    /// The stream ended on a terminal of its own making: the source is not
    /// read again.
    ended: bool,
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
            // A terminal is checked whole, against what was shown
            // ([`Self::terminal`]).
            Event::Done { .. } => false,
        };
        if invalid {
            Err(FatalLlmError::InvalidRequest.into())
        } else {
            Ok(())
        }
    }
}
impl CheckedStream<'_> {
    /// The stream's terminal, checked. Once content was shown, a terminal
    /// whose message disagrees with it does not replace it, refuse it or
    /// send it again (FIX 8617): the shown output is the answer, with the
    /// provider's usage as reported, and it ends
    /// [`oneiron::FinishReason::Incomplete`]. A cancelled terminal is held
    /// to what was shown too (FIX 9324): one that disagrees ends with the
    /// shown output (its text as shown, only the tool calls that ended), the
    /// usage as reported, still [`oneiron::FinishReason::Cancelled`], so a
    /// stop stays a stop and nothing shown is taken back. A terminal-only
    /// answer, with nothing shown first, is held to its own checks alone.
    fn terminal(
        &mut self,
        message: oneiron::LlmMessage,
        usage: oneiron::LlmUsage,
        finish_reason: oneiron::FinishReason,
    ) -> oneiron::LlmResult<oneiron::LlmStreamEvent> {
        let cancelled = finish_reason == oneiron::FinishReason::Cancelled;
        let open = !cancelled && self.parts.values().any(|part| *part != StreamPart::Closed);
        if !open && !self.emitted.is_empty() && !self.emitted.agrees(&message) {
            self.ended = true;
            let finish_reason = if cancelled {
                finish_reason
            } else {
                oneiron::FinishReason::Incomplete {
                    reason: oneiron::IncompleteReason::TerminalDisagreement,
                }
            };
            return Ok(oneiron::LlmStreamEvent::Done {
                message: self.emitted.message(),
                usage,
                finish_reason,
                reply_assertions: Default::default(),
            });
        }
        validate_terminal(&message, &finish_reason)?;
        if open {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(oneiron::LlmStreamEvent::Done {
            message,
            usage,
            finish_reason,
            reply_assertions: Default::default(),
        })
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
        if this.ended {
            return Poll::Ready(None);
        }
        match std::pin::Pin::new(&mut this.source).poll_next(cx) {
            // A peer's terminal is a raw boundary: whatever records it
            // names are no evidence here, so its reply asserts none (FIX 3416).
            Poll::Ready(Some(Ok(oneiron::LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
                ..
            }))) => Poll::Ready(Some(this.terminal(message, usage, finish_reason))),
            Poll::Ready(Some(Ok(event))) => match this.validate_event(&event) {
                Ok(()) => {
                    this.emitted.note(&event);
                    Poll::Ready(Some(Ok(event)))
                }
                Err(error) => Poll::Ready(Some(Err(error))),
            },
            result => result,
        }
    }
}
