//! The OpenAI-compatible transport: any `/v1/chat/completions` server.
use futures_util::StreamExt;
use oneiron::BudgetLease;
use oneiron_llm_openai::{
    OpenAiCompatFuture, OpenAiCompatHttpRequest, OpenAiCompatHttpResponse,
    OpenAiCompatProviderStream, OpenAiCompatStreamFrame, OpenAiCompatTransport,
    OpenAiCompatTransportError,
};
use serde_json::Value as JsonValue;

use super::http::{HttpFailure, ProviderHttp, SseItem};
use super::output_cap::OutputCap;
use super::served::record_served_model;
use crate::config::models::ResponseFormatWire;

pub(super) struct OpenAiHttp {
    pub(super) http: ProviderHttp,
    pub(super) cap: OutputCap,
    pub(super) response_format: ResponseFormatWire,
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
            let mut reply = self
                .http
                .post_json(&request.path, &request.headers, &body)
                .await?;
            carry_served_model(reply.status, &mut reply.body);
            carry_timings(&mut reply.body);
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
        let events = self.http.post_sse(&request.path, &request.headers, &body);
        let frames = futures_util::stream::unfold(
            Frames {
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

/// Stamps the model a reply names into its usage.
///
/// A proxy may answer under its own spelling of the model (a login prefix
/// stripped, say). Record what it said; never reject on it. A 2xx reply
/// without usage (or with a null one) gets one carrying only that name; the
/// adapter reads its absent counts as zero, as it would anyway.
pub(super) fn carry_served_model(status: u16, body: &mut JsonValue) {
    let served = body.get("model").cloned();
    if (200..300).contains(&status)
        && served.is_some()
        && let Some(body) = body.as_object_mut()
        && body.get("usage").is_none_or(JsonValue::is_null)
    {
        body.insert("usage".into(), JsonValue::Object(Default::default()));
    }
    record_served_model(body.get_mut("usage"), served);
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
struct Frames<S> {
    events: std::pin::Pin<Box<S>>,
    served: Option<JsonValue>,
    saw_usage: bool,
    finished: bool,
    closed: bool,
}

type Frame = Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>;

impl<S> Frames<S>
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
            let carrier = self.carrier()?;
            return Some((Ok(carrier), self));
        };
        let frame = self.frame(item);
        Some((frame, self))
    }

    fn frame(&mut self, item: Result<SseItem, HttpFailure>) -> Frame {
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
                    self.served = Some(model.clone());
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
                record_served_model(chunk.get_mut("usage"), self.served.clone());
                Ok(OpenAiCompatStreamFrame::Chunk(chunk))
            }
        }
    }

    fn carrier(&self) -> Option<OpenAiCompatStreamFrame> {
        if !self.finished || self.saw_usage {
            return None;
        }
        let mut usage = JsonValue::Object(serde_json::Map::new());
        record_served_model(Some(&mut usage), Some(self.served.clone()?));
        Some(OpenAiCompatStreamFrame::Chunk(
            serde_json::json!({"choices": [], "usage": usage}),
        ))
    }
}
