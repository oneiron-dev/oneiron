//! The OpenAI-compatible transport: any `/v1/chat/completions` server.
use std::sync::Arc;

use futures_util::StreamExt;
use oneiron::BudgetLease;
use oneiron::llm::returned_model_wire_id;
use oneiron_llm_openai::{
    OpenAiCompatFuture, OpenAiCompatHttpRequest, OpenAiCompatHttpResponse,
    OpenAiCompatProviderStream, OpenAiCompatStreamFrame, OpenAiCompatTransport,
    OpenAiCompatTransportError,
};
use serde_json::Value as JsonValue;

use super::cache_usage::carry_chat_evidence;
use super::http::{HttpFailure, ProviderHttp, SseItem};
use super::llama_identity::{AnsweringIdentity, LlamaIdentityResolver};
use super::output_cap::OutputCap;
use super::served::record_served_model;
use crate::config::models::ResponseFormatWire;

pub(super) struct OpenAiHttp {
    pub(super) http: ProviderHttp,
    pub(super) cap: OutputCap,
    pub(super) response_format: ResponseFormatWire,
    /// Where a house llama.cpp answer's launch alias resolves to the identity
    /// of the process that answered (FIX 7895).
    pub(super) identities: Arc<LlamaIdentityResolver>,
}

impl OpenAiHttp {
    /// The identity `returned`, an answer's own top-level `model`, names on
    /// this route, whose configured wire id is `target`: `None` unless it is
    /// a house llama.cpp launch alias.
    async fn answering(
        &self,
        returned: Option<&str>,
        target: Option<&str>,
    ) -> Option<AnsweringIdentity> {
        self.identities.resolve(&self.http, returned, target).await
    }
}

/// One `.send()` per call over [`ProviderHttp`], which follows no redirect
/// and never resends: a run's gate may wrap this transport's adapter.
impl oneiron::llm::SingleSend for OpenAiHttp {}

impl From<HttpFailure> for OpenAiCompatTransportError {
    fn from(failure: HttpFailure) -> Self {
        match failure {
            HttpFailure::Timeout => Self::Timeout,
            HttpFailure::Connection => Self::Connection,
            HttpFailure::StreamCut => Self::StreamCut,
            HttpFailure::Malformed | HttpFailure::EventTooLarge | HttpFailure::BodyTooLarge => {
                Self::Server
            }
        }
    }
}

impl OpenAiCompatTransport for OpenAiHttp {
    fn execute<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiCompatFuture<'a> {
        Box::pin(async move {
            let mut body = request.body;
            self.cap.apply(&mut body);
            send_format(self.response_format, &mut body);
            let target = configured_target(&body);
            let mut reply = self
                .http
                .post_json(&request.path, &request.headers, &body)
                .await?;
            let answering = match reply.body.get("model").and_then(JsonValue::as_str) {
                Some(returned) if (200..300).contains(&reply.status) => {
                    self.answering(Some(returned), target.as_deref()).await
                }
                _ => None,
            };
            carry_reply_evidence(
                reply.status,
                &mut reply.body,
                target.as_deref(),
                answering.as_ref(),
            );
            Ok(OpenAiCompatHttpResponse {
                status: reply.status,
                headers: reply.headers,
                body: reply.body,
            })
        })
    }

    fn stream<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> Result<OpenAiCompatProviderStream<'a>, OpenAiCompatTransportError> {
        let mut body = request.body;
        self.cap.apply(&mut body);
        send_format(self.response_format, &mut body);
        let target = configured_target(&body);
        let events = self.http.post_sse(&request.path, &request.headers, &body);
        let frames = futures_util::stream::unfold(
            Frames {
                transport: self,
                target,
                answering: None,
                events: Box::pin(events),
                served: None,
                saw_usage: false,
                finished: false,
                closed: false,
            },
            Frames::next,
        );
        Ok(Box::pin(frames))
    }
}

/// A provider set to `response_format = "none"` is sent no
/// `response_format`; the engine still checks the answer against the call's
/// schema, as it does when the schema went out.
pub(super) fn send_format(wire: ResponseFormatWire, body: &mut JsonValue) {
    if wire == ResponseFormatWire::Omitted
        && let Some(body) = body.as_object_mut()
    {
        body.remove("response_format");
    }
}

/// The configured wire id a call sends as its `model`: the route's target,
/// which a house llama.cpp launch alias in its answer stands for.
fn configured_target(body: &JsonValue) -> Option<String> {
    body.get("model")
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
}

/// The model label a reply's `returned` model gives, on a call whose
/// configured wire id is `target`: that id when it is a house llama.cpp
/// launch alias (FIX 7895), else as it came. The alias itself stays on the
/// reply for its cache evidence.
fn served_label(returned: &JsonValue, target: Option<&str>) -> JsonValue {
    match (returned.as_str(), target) {
        (Some(returned), Some(target)) => {
            JsonValue::String(returned_model_wire_id(returned, target).to_owned())
        }
        _ => returned.clone(),
    }
}

/// Stamps the model a reply names into its usage, as a label of the call's
/// configured wire id `target`.
///
/// A proxy may answer under its own spelling of the model (a login prefix
/// stripped, say). Record what it said; never reject on it. A 2xx reply
/// without usage (or with a null one) gets one carrying only that name; the
/// adapter reads its absent counts as zero, as it would anyway.
pub(super) fn carry_served_model(status: u16, body: &mut JsonValue, target: Option<&str>) {
    let served = body
        .get("model")
        .map(|returned| served_label(returned, target));
    if (200..300).contains(&status)
        && served.is_some()
        && let Some(body) = body.as_object_mut()
        && body.get("usage").is_none_or(JsonValue::is_null)
    {
        body.insert("usage".into(), JsonValue::Object(Default::default()));
    }
    record_served_model(body.get_mut("usage"), served);
}

/// A whole chat reply as the adapter reads it, plain or brokered: the model
/// it names as a label of the configured `target`, the engine's timings and
/// the llama.cpp receipt `answering`, its own alias's identity, names (FIX
/// 7895, 8314), all in its usage.
pub(super) fn carry_reply_evidence(
    status: u16,
    body: &mut JsonValue,
    target: Option<&str>,
    answering: Option<&AnsweringIdentity>,
) {
    carry_served_model(status, body, target);
    carry_timings(body);
    carry_chat_evidence(body, answering);
}

/// Copies an engine's own timings into its usage.
///
/// llama-server and the house EXL3 server report their prefill and decode
/// timings as a top-level `timings` object beside `usage`, on a plain reply
/// and on a stream's last chunk. The adapter keeps only `usage`, so the
/// object goes in as `usage.timings` and reaches the answer's raw provider
/// usage. A usage that already holds `timings` keeps its own; a body with no
/// usage object is left as it came.
fn carry_timings(body: &mut JsonValue) {
    let Some(timings) = body.get("timings").cloned().filter(JsonValue::is_object) else {
        return;
    };
    if let Some(JsonValue::Object(usage)) = body.get_mut("usage") {
        usage.entry("timings").or_insert(timings);
    }
}

/// The stream as the adapter reads it, with the served model on its usage.
///
/// A usage chunk may omit `model`, so it takes the last one named. A stream
/// that finished but sent no usage at all gets one choices-free chunk
/// carrying only that name at `[DONE]` or EOF: the adapter's own end of
/// stream, with the counts it would read as zero anyway. A stream cut before
/// any finish gets nothing, so it still ends as a cut.
///
/// The receipt's identity is what this stream's own last `model` names
/// (FIX 7895), never another stream's or a discovered one. Each chunk with a
/// usage object, a usage-only last chunk included, gets the llama.cpp
/// receipt its timings or that alias give (FIX 8314); the adapter keeps the
/// last usage it reads, so a request's receipt is read once.
struct Frames<'a, S> {
    transport: &'a OpenAiHttp,
    /// The configured wire id the call sent.
    target: Option<String>,
    /// The last top-level `model` this stream's chunks named, as it came.
    answering: Option<String>,
    events: std::pin::Pin<Box<S>>,
    served: Option<JsonValue>,
    saw_usage: bool,
    finished: bool,
    closed: bool,
}

type Frame = Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>;

impl<S> Frames<'_, S>
where
    S: futures_util::Stream<Item = Result<SseItem, HttpFailure>>,
{
    async fn next(mut self) -> Option<(Frame, Self)> {
        if self.closed {
            return None;
        }
        let item = match self.events.next().await {
            Some(Ok(SseItem::Event(event))) if event.data.trim() == "[DONE]" => None,
            other => other,
        };
        let Some(item) = item else {
            self.closed = true;
            let mut carrier = self.carrier()?;
            let answering = self
                .transport
                .answering(self.answering.as_deref(), self.target.as_deref())
                .await;
            carry_chat_evidence(&mut carrier, answering.as_ref());
            return Some((Ok(OpenAiCompatStreamFrame::Chunk(carrier)), self));
        };
        let frame = self.frame(item).await;
        Some((frame, self))
    }

    async fn frame(&mut self, item: Result<SseItem, HttpFailure>) -> Frame {
        match item? {
            SseItem::Status(reply) => {
                Ok(OpenAiCompatStreamFrame::Status(OpenAiCompatHttpResponse {
                    status: reply.status,
                    headers: reply.headers,
                    body: reply.body,
                }))
            }
            SseItem::Event(event) => {
                let mut chunk: JsonValue = serde_json::from_str(&event.data)
                    .map_err(|_| OpenAiCompatTransportError::StreamCut)?;
                if let Some(model) = chunk.get("model") {
                    self.answering = model.as_str().map(str::to_owned);
                    self.served = Some(served_label(model, self.target.as_deref()));
                }
                self.saw_usage |= chunk.get("usage").is_some_and(JsonValue::is_object);
                self.finished |= chunk
                    .get("choices")
                    .and_then(JsonValue::as_array)
                    .is_some_and(|choices| {
                        choices
                            .iter()
                            .any(|choice| !choice["finish_reason"].is_null())
                    });
                carry_timings(&mut chunk);
                // Only a chunk with usage gets a receipt.
                let answering = if chunk.get("usage").is_some_and(JsonValue::is_object) {
                    self.transport
                        .answering(self.answering.as_deref(), self.target.as_deref())
                        .await
                } else {
                    None
                };
                carry_chat_evidence(&mut chunk, answering.as_ref());
                record_served_model(chunk.get_mut("usage"), self.served.clone());
                Ok(OpenAiCompatStreamFrame::Chunk(chunk))
            }
        }
    }

    /// A finished stream's usage chunk when it sent none, carrying the
    /// served model; its caller adds the receipt its launch alias gives.
    fn carrier(&self) -> Option<JsonValue> {
        if !self.finished || self.saw_usage {
            return None;
        }
        let mut usage = JsonValue::Object(serde_json::Map::new());
        record_served_model(Some(&mut usage), Some(self.served.clone()?));
        Some(serde_json::json!({"choices": [], "usage": usage}))
    }
}
