//! Configured SIWC Responses calls through the normal model/run admission.

use std::collections::BTreeMap;
use std::sync::Arc;

use futures_util::{StreamExt, stream::BoxStream};
use oneiron::llm::{
    INFERENCE_CALLS_KEY, InferenceCallReceipt, InferencePublisher, LlmCallMetadata,
    LlmEndpointFlavor, SingleRouteBackend, WorkCancel,
};
use oneiron::{
    BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmCatalogEntry, LlmError,
    LlmGenerateFuture, LlmRequest, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, ModelId,
    RetryableLlmError,
};
use oneiron_llm_openai::{
    OpenAiCompatConfig, OpenAiCompatHttpResponse, OpenAiCompatProviderStream,
    OpenAiCompatStreamFrame, OpenAiCompatTransportError, OpenAiResponsesLlmStream,
    build_openai_responses_turn, responses_event_is_terminal, responses_event_type,
};
use serde::Deserialize as _;
use serde_json::Value;

use super::http::{HttpFailure, HttpReleaseError, ProviderHttp, SseItem};
use super::output_cap::OutputCap;
use super::served::record_served_model;
use crate::config::models::{ProviderConfig, ResponseFormatWire};
use crate::runtime::seat_login::siwc::CredentialSource;

const PATH: &str = "/v1/responses";

pub(super) struct SiwcResponses {
    http: ProviderHttp,
    credentials: Arc<CredentialSource>,
    config: OpenAiCompatConfig,
    catalog: BTreeMap<ModelId, LlmCatalogEntry>,
    cap: OutputCap,
    response_format: ResponseFormatWire,
    headers: Vec<(String, String)>,
}

struct Prepared {
    bytes: Vec<u8>,
    digest: String,
}

impl SiwcResponses {
    pub(super) fn new(
        provider: &ProviderConfig,
        catalog: Vec<LlmCatalogEntry>,
    ) -> anyhow::Result<Self> {
        let selection = provider
            .siwc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing SIWC selection"))?;
        let mut headers: BTreeMap<_, _> = provider
            .headers
            .iter()
            .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
            .collect();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        Ok(Self {
            http: ProviderHttp::siwc(provider)?,
            credentials: Arc::new(CredentialSource::select(
                &selection.credential_file,
                provider.timeout_secs,
            )?),
            config: OpenAiCompatConfig::from_catalog(catalog.clone()),
            catalog: catalog
                .into_iter()
                .map(|entry| (entry.model.clone(), entry))
                .collect(),
            cap: OutputCap {
                field: "max_output_tokens",
                ceiling: provider.max_output_tokens,
                fallback: None,
            },
            response_format: provider.response_format,
            headers: headers.into_iter().collect(),
        })
    }

    fn prepare(&self, request: &LlmRequest, stream: bool) -> LlmResult<Prepared> {
        let turn = build_openai_responses_turn(&self.config, request, stream)?;
        let mut head = turn.head;
        head.insert("input".into(), Value::Array(turn.items));
        head.insert("stream".into(), Value::Bool(true));
        head.insert("store".into(), Value::Bool(false));
        let mut body = Value::Object(head);
        self.cap.apply(&mut body);
        if self.response_format == ResponseFormatWire::Omitted {
            body.as_object_mut()
                .ok_or(FatalLlmError::InvalidRequest)?
                .remove("text");
        }
        let bytes = serde_json::to_vec(&body).map_err(|_| FatalLlmError::InvalidRequest)?;
        let digest = oneiron_broker::request_digest("POST", PATH, &self.headers, &bytes);
        Ok(Prepared { bytes, digest })
    }

    fn bound(&self, request: &LlmRequest, stream: bool, digest: &str) -> LlmResult<Prepared> {
        let prepared = self.prepare(request, stream)?;
        if prepared.digest != digest {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(prepared)
    }

    async fn open<'a>(
        &'a self,
        prepared: Prepared,
        model: ModelId,
        lease: &'a BudgetLease,
        cancel: &WorkCancel,
    ) -> LlmResult<OpenAiCompatProviderStream<'a>> {
        let opening = self.credentials.open();
        let active = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(RetryableLlmError::DeviceAdmissionStopped.into()),
            result = opening => result.map_err(|_| FatalLlmError::Auth)?,
        };
        let release = || {
            if cancel.is_cancelled() {
                return Err(RetryableLlmError::DeviceAdmissionStopped.into());
            }
            self.credentials
                .release(&active)
                .map_err(|_| LlmError::from(FatalLlmError::Auth))
        };
        let publisher = InferencePublisher::begin(lease);
        let sending = self.http.post_sse_released(
            PATH,
            active.authorization(),
            prepared.bytes,
            &release,
            lease,
        );
        let events = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(RetryableLlmError::DeviceAdmissionStopped.into()),
            result = sending => result.map_err(|error| match error {
                HttpReleaseError::Release(error) => error,
                HttpReleaseError::Transport(error) => LlmError::from(OpenAiCompatTransportError::from(error)),
            })?,
        };
        Ok(Box::pin(futures_util::stream::unfold(
            Frames {
                events: Box::pin(events),
                publisher,
                model,
                closed: false,
            },
            Frames::next,
        )))
    }

    async fn generate_prepared(
        &self,
        prepared: Prepared,
        model: ModelId,
        lease: &BudgetLease,
    ) -> LlmResult<oneiron::LlmResponse> {
        let cancel = lease
            .work_context()
            .map(|work| work.cancel)
            .unwrap_or_default();
        let provider = self.open(prepared, model.clone(), lease, &cancel).await?;
        let decoding = OpenAiResponsesLlmStream::new(provider).into_response();
        let mut response = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(RetryableLlmError::DeviceAdmissionStopped.into()),
            result = decoding => result?,
        };
        response.usage.bind_inference_model(&model);
        Ok(response)
    }

    fn decoded<'a>(
        &'a self,
        prepared: Prepared,
        model: ModelId,
        lease: &'a BudgetLease,
    ) -> LlmStream<'a> {
        let cancel = lease
            .work_context()
            .map(|work| work.cancel)
            .unwrap_or_default();
        let opening = async move {
            let provider = self.open(prepared, model.clone(), lease, &cancel).await?;
            let decoded = OpenAiResponsesLlmStream::new(provider);
            Ok::<_, LlmError>(LlmStream::new(futures_util::stream::unfold(
                Some(decoded),
                move |state| {
                    let cancel = cancel.clone();
                    let model = model.clone();
                    async move {
                        let mut decoded = state?;
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => Some((Err(RetryableLlmError::DeviceAdmissionStopped.into()), None)),
                            event = decoded.next() => event.map(|event| {
                                let event = event.map(|mut event| {
                                    if let LlmStreamEvent::Done { usage, .. } = &mut event {
                                        usage.bind_inference_model(&model);
                                    }
                                    event
                                });
                                (event, Some(decoded))
                            }),
                        }
                    }
                },
            )))
        };
        LlmStream::new(
            futures_util::stream::once(opening).flat_map(|result| match result {
                Ok(stream) => stream.left_stream(),
                Err(error) => {
                    futures_util::stream::once(std::future::ready(Err(error))).right_stream()
                }
            }),
        )
    }
}

impl LlmBackend for SiwcResponses {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.catalog
            .get(model)
            .is_some_and(|entry| entry.supports(&capability))
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let prepared = self.prepare(&request, false)?;
            self.generate_prepared(prepared, request.model, lease).await
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let prepared = self.prepare(&request, true)?;
        Ok(self.decoded(prepared, request.model, lease))
    }
}

impl SingleRouteBackend for SiwcResponses {
    fn preflight(&self, request: &LlmRequest, stream: bool) -> LlmResult<()> {
        self.prepare(request, stream).map(drop)
    }

    fn request_digest(&self, request: &LlmRequest, stream: bool) -> LlmResult<Option<String>> {
        Ok(Some(self.prepare(request, stream)?.digest))
    }

    fn dispatch_digest(
        &self,
        request: &LlmRequest,
        stream: bool,
        admitted: Option<&str>,
    ) -> LlmResult<Option<String>> {
        let prepared = self.prepare(request, stream)?;
        if admitted.is_some_and(|digest| digest != prepared.digest) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(Some(prepared.digest))
    }

    fn generate_bound<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
        digest: &str,
    ) -> LlmGenerateFuture<'a> {
        let prepared = self.bound(&request, false, digest);
        Box::pin(async move {
            self.generate_prepared(prepared?, request.model, lease)
                .await
        })
    }

    fn stream_bound<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
        digest: &str,
    ) -> LlmStreamResult<'a> {
        Ok(self.decoded(self.bound(&request, true, digest)?, request.model, lease))
    }
}

struct Frames {
    events: BoxStream<'static, Result<SseItem, HttpFailure>>,
    publisher: InferencePublisher,
    model: ModelId,
    closed: bool,
}

impl Frames {
    async fn next(
        mut self,
    ) -> Option<(
        Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>,
        Self,
    )> {
        if self.closed {
            return None;
        }
        let next = self.events.next().await?;
        let frame = match next {
            Err(error) => {
                self.closed = true;
                Err(error.into())
            }
            Ok(SseItem::Status(reply)) => {
                self.closed = true;
                Ok(OpenAiCompatStreamFrame::Status(OpenAiCompatHttpResponse {
                    status: reply.status,
                    headers: reply.headers,
                    body: reply.body,
                }))
            }
            Ok(SseItem::Event(event)) => match serde_json::from_str::<Value>(&event.data) {
                Err(_) => {
                    self.closed = true;
                    Err(OpenAiCompatTransportError::StreamCut)
                }
                Ok(mut chunk) => {
                    let terminal = responses_event_is_terminal(&chunk);
                    let finished = matches!(
                        responses_event_type(&chunk),
                        "response.completed" | "response.incomplete"
                    );
                    if let Some(response) = chunk.get_mut("response") {
                        let served = response.get("model").cloned();
                        record_served_model(response.get_mut("usage"), served);
                        if let Some(records) = response
                            .get("usage")
                            .and_then(|usage| usage.get(INFERENCE_CALLS_KEY))
                            .and_then(Value::as_array)
                            && let Some(mut receipt) = records
                                .iter()
                                .filter_map(|record| InferenceCallReceipt::deserialize(record).ok())
                                .next_back()
                        {
                            receipt.model = Some(self.model.clone());
                            if finished {
                                self.publisher.finish(receipt);
                            } else {
                                self.publisher.partial(receipt);
                            }
                        }
                    }
                    self.closed = terminal;
                    if terminal {
                        let metadata = LlmCallMetadata {
                            endpoint: LlmEndpointFlavor::OpenAiResponsesHttp,
                            response_id: chunk
                                .get("response")
                                .and_then(|response| response.get("id"))
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            previous_response_id: None,
                            store: Some(false),
                        };
                        Ok(OpenAiCompatStreamFrame::ChunkWithMetadata { chunk, metadata })
                    } else {
                        Ok(OpenAiCompatStreamFrame::Chunk(chunk))
                    }
                }
            },
        };
        Some((frame, self))
    }
}
