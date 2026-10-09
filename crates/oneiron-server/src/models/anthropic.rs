//! The Anthropic-compatible transport: any `/v1/messages` server.
use futures_util::StreamExt;
use oneiron::BudgetLease;
use oneiron_llm_anthropic::{
    AnthropicMessagesFuture, AnthropicMessagesHttpRequest, AnthropicMessagesHttpResponse,
    AnthropicMessagesProviderStream, AnthropicMessagesStreamFrame, AnthropicMessagesTransport,
    AnthropicMessagesTransportError,
};
use serde_json::Value as JsonValue;

use super::http::{HttpFailure, ProviderHttp, SseItem};
use super::output_cap::OutputCap;
use super::served::record_served_model;

pub(super) struct AnthropicHttp {
    pub(super) http: ProviderHttp,
    pub(super) cap: OutputCap,
}

/// The Messages API requires `max_tokens`; this is sent when neither the
/// caller nor the provider entry names one.
pub(super) const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 4_096;

impl AnthropicHttp {
    fn with_output_cap(&self, mut body: JsonValue) -> JsonValue {
        self.cap.apply(&mut body);
        body
    }
}

impl From<HttpFailure> for AnthropicMessagesTransportError {
    fn from(failure: HttpFailure) -> Self {
        match failure {
            HttpFailure::Timeout => Self::Timeout,
            HttpFailure::Connection => Self::Connection,
            HttpFailure::StreamCut => Self::StreamCut,
            HttpFailure::Malformed | HttpFailure::EventTooLarge => Self::Server,
        }
    }
}

impl AnthropicMessagesTransport for AnthropicHttp {
    fn execute<'a>(
        &'a self,
        request: AnthropicMessagesHttpRequest,
        _lease: &'a BudgetLease,
    ) -> AnthropicMessagesFuture<'a> {
        Box::pin(async move {
            let body = self.with_output_cap(request.body);
            let mut reply = self
                .http
                .post_json(&request.path, &request.headers, &body)
                .await?;
            // A reply without usage (or with a null one) gets one carrying
            // only the served model; the adapter reads its absent counts as
            // zero, as it would anyway.
            if (200..300).contains(&reply.status) {
                carry_served_model(&mut reply.body);
            }
            Ok(AnthropicMessagesHttpResponse {
                status: reply.status,
                headers: reply.headers,
                body: reply.body,
            })
        })
    }

    fn stream<'a>(
        &'a self,
        request: AnthropicMessagesHttpRequest,
        _lease: &'a BudgetLease,
    ) -> Result<AnthropicMessagesProviderStream<'a>, AnthropicMessagesTransportError> {
        let body = self.with_output_cap(request.body);
        let events = self.http.post_sse(&request.path, &request.headers, &body);
        let frames = events.map(|item| match item? {
            SseItem::Status(reply) => Ok(AnthropicMessagesStreamFrame::Status(
                AnthropicMessagesHttpResponse {
                    status: reply.status,
                    headers: reply.headers,
                    body: reply.body,
                },
            )),
            SseItem::Event(event) => {
                let mut data: JsonValue = serde_json::from_str(&event.data)
                    .map_err(|_| AnthropicMessagesTransportError::StreamCut)?;
                // `message_start`: later `message_delta` usage extends the
                // usage it opens, so the served model rides to the end.
                if let Some(message) = data.get_mut("message") {
                    carry_served_model(message);
                }
                Ok(AnthropicMessagesStreamFrame::Event(data))
            }
        });
        Ok(Box::pin(frames))
    }
}

/// Stamps the model `message` names into its usage, opening an empty usage
/// object when it has none (or a null one), as the OpenAI-compatible
/// transport does.
fn carry_served_model(message: &mut JsonValue) {
    let Some(served) = message.get("model").cloned() else {
        return;
    };
    let Some(message) = message.as_object_mut() else {
        return;
    };
    let usage = message
        .entry("usage")
        .or_insert_with(|| JsonValue::Object(Default::default()));
    if usage.is_null() {
        *usage = JsonValue::Object(Default::default());
    }
    record_served_model(Some(usage), Some(served));
}
