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
use super::served::record_served_model;

pub(super) struct OpenAiHttp(pub(super) ProviderHttp);

impl From<HttpFailure> for OpenAiCompatTransportError {
    fn from(failure: HttpFailure) -> Self {
        match failure {
            HttpFailure::Timeout => Self::Timeout,
            HttpFailure::Connection => Self::Connection,
            HttpFailure::StreamCut => Self::StreamCut,
            HttpFailure::Malformed => Self::Server,
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
            let mut reply = self
                .0
                .post_json(&request.path, &request.headers, &request.body)
                .await?;
            // A proxy may answer under its own spelling of the model (a login
            // prefix stripped, say). Record what it said; never reject on it.
            // A reply without usage gets one carrying only that name; the
            // adapter reads its absent counts as zero, as it would anyway.
            let served = reply.body.get("model").cloned();
            if (200..300).contains(&reply.status)
                && served.is_some()
                && let Some(body) = reply.body.as_object_mut()
            {
                body.entry("usage")
                    .or_insert_with(|| JsonValue::Object(Default::default()));
            }
            record_served_model(reply.body.get_mut("usage"), served);
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
        let events = self
            .0
            .post_sse(&request.path, &request.headers, &request.body);
        let frames = events
            .take_while(|item| {
                let done =
                    matches!(item, Ok(SseItem::Event(event)) if event.data.trim() == "[DONE]");
                std::future::ready(!done)
            })
            // The usage chunk may omit `model`; it takes the last one named.
            // Only chunks that already carry usage are stamped: usage on a
            // chunk without choices is the adapter's end of stream.
            .scan(None::<JsonValue>, |served, item| {
                std::future::ready(Some(frame(item, served)))
            });
        Ok(Box::pin(frames))
    }
}

fn frame(
    item: Result<SseItem, HttpFailure>,
    served: &mut Option<JsonValue>,
) -> Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError> {
    match item? {
        SseItem::Status(reply) => Ok(OpenAiCompatStreamFrame::Status(OpenAiCompatHttpResponse {
            status: reply.status,
            headers: reply.headers,
            body: reply.body,
        })),
        SseItem::Event(event) => {
            let mut chunk: JsonValue = serde_json::from_str(&event.data)
                .map_err(|_| OpenAiCompatTransportError::StreamCut)?;
            if let Some(model) = chunk.get("model") {
                *served = Some(model.clone());
            }
            record_served_model(chunk.get_mut("usage"), served.clone());
            Ok(OpenAiCompatStreamFrame::Chunk(chunk))
        }
    }
}
