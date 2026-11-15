//! Configured SIWC Responses calls through the normal model/run admission.
//!
//! The offer's login is one model seat (SEAT-PARK-MODEL-STEP-PATH): a lapsed
//! login and a spent usage window name that seat on the refusal, so a Dreamer
//! step the offer refuses parks on the seat's wait.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use futures_util::{StreamExt, stream::BoxStream};
use oneiron::dreamer_runner::ModelSeatId;
use oneiron::llm::SpentKind;
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

/// The model seat of the SIWC offer whose credential file is
/// `credential_file`: the file's absolute path, as its credential source
/// reads it, digested under the SIWC offer seat domain.
///
/// # Errors
/// The path has no absolute form, or the digest helper refuses.
pub(crate) fn siwc_offer_seat(credential_file: &Path) -> anyhow::Result<ModelSeatId> {
    oneiron::dispatch_byoa::siwc_offer_seat_id(&std::path::absolute(credential_file)?)
        .map_err(|error| anyhow::anyhow!("SIWC offer seat: {error}"))
}

/// A refusal an SIWC offer's call met, naming the offer's `seat`: a failed
/// login (the vendor's 401 or 403) is the seat's lapsed login, and a spent
/// usage window is the seat's window. Every other refusal is unchanged.
pub(crate) fn seat_refusal(seat: ModelSeatId, error: LlmError) -> LlmError {
    match error {
        LlmError::Fatal(FatalLlmError::Auth) => FatalLlmError::SeatSignedOut { seat }.into(),
        LlmError::Retryable(RetryableLlmError::QuotaSpent {
            kind: SpentKind::Window,
            retry_after,
            resets_at,
            seat: None,
        }) => RetryableLlmError::QuotaSpent {
            kind: SpentKind::Window,
            retry_after,
            resets_at,
            seat: Some(seat),
        }
        .into(),
        other => other,
    }
}

pub(super) struct SiwcResponses {
    http: ProviderHttp,
    credentials: Arc<CredentialSource>,
    /// The login's model seat, which its lapsed login and spent window name.
    seat: ModelSeatId,
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
            seat: siwc_offer_seat(&selection.credential_file)?,
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
            result = opening => result.map_err(|_| FatalLlmError::SeatSignedOut { seat: self.seat })?,
        };
        let release = || {
            lease.check_dispatch_release()?;
            if cancel.is_cancelled() {
                return Err(RetryableLlmError::DeviceAdmissionStopped.into());
            }
            self.credentials
                .release(&active)
                .map_err(|_| LlmError::from(FatalLlmError::SeatSignedOut { seat: self.seat }))
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
        let provider = self
            .open(prepared, model.clone(), lease, &cancel)
            .await
            .map_err(|error| seat_refusal(self.seat, error))?;
        let decoding = OpenAiResponsesLlmStream::new(provider).into_response();
        let mut response = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(RetryableLlmError::DeviceAdmissionStopped.into()),
            result = decoding => result.map_err(|error| seat_refusal(self.seat, error))?,
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
        let seat = self.seat;
        LlmStream::new(
            futures_util::stream::once(opening)
                .flat_map(|result| match result {
                    Ok(stream) => stream.left_stream(),
                    Err(error) => {
                        futures_util::stream::once(std::future::ready(Err(error))).right_stream()
                    }
                })
                .map(move |event| event.map_err(|error| seat_refusal(seat, error))),
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

    fn model_seat(&self) -> Option<ModelSeatId> {
        Some(self.seat)
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
