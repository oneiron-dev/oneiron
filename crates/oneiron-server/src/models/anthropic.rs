//! The Anthropic-compatible transport: any `/v1/messages` server.
use std::collections::BTreeMap;

use futures_util::StreamExt;
use oneiron::BudgetLease;
use oneiron::llm::{
    CacheIdentity, INFERENCE_CALLS_KEY, InferenceCallReceipt, InferencePublisher, ModelId,
    WorkerBuildEvidence, WorkerDescriptor, WorkerKind,
};
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
    pub(super) engine_models: BTreeMap<String, ModelId>,
}

/// One `.send()` per call over [`ProviderHttp`], which follows no redirect
/// and never resends: a run's gate may wrap this transport's adapter.
impl oneiron::llm::SingleSend for AnthropicHttp {}

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
            HttpFailure::Malformed
            | HttpFailure::EventTooLarge
            | HttpFailure::BodyTooLarge
            | HttpFailure::OutOfMemory => Self::Server,
        }
    }
}

impl AnthropicMessagesTransport for AnthropicHttp {
    fn execute<'a>(
        &'a self,
        request: AnthropicMessagesHttpRequest,
        lease: &'a BudgetLease,
    ) -> AnthropicMessagesFuture<'a> {
        Box::pin(async move {
            let body = self.with_output_cap(request.body);
            let mut inference = InferenceUsage::new(
                lease,
                body.get("model")
                    .and_then(JsonValue::as_str)
                    .and_then(|wire| self.engine_models.get(wire))
                    .cloned(),
            );
            let mut reply = self
                .http
                .post_json(&request.path, &request.headers, &body)
                .await?;
            // A reply without usage (or with a null one) gets one carrying
            // only the served model; the adapter reads its absent counts as
            // zero, as it would anyway.
            // A failed HTTP response can still name work the worker measured.
            inference.record(reply.body.get_mut("usage"));
            if (200..300).contains(&reply.status) {
                carry_served_model(&mut reply.body);
                inference.finish();
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
        lease: &'a BudgetLease,
    ) -> Result<AnthropicMessagesProviderStream<'a>, AnthropicMessagesTransportError> {
        let body = self.with_output_cap(request.body);
        let mut inference = InferenceUsage::new(
            lease,
            body.get("model")
                .and_then(JsonValue::as_str)
                .and_then(|wire| self.engine_models.get(wire))
                .cloned(),
        );
        let mut closed = false;
        let events = self.http.post_sse(&request.path, &request.headers, &body);
        let frames = events.map(move |item| {
            let item = match item {
                Ok(item) => item,
                Err(error) => {
                    closed = true;
                    return Err(error.into());
                }
            };
            match item {
                SseItem::Status(mut reply) => {
                    if !closed {
                        inference.record(reply.body.get_mut("usage"));
                    }
                    closed = true;
                    Ok(AnthropicMessagesStreamFrame::Status(
                        AnthropicMessagesHttpResponse {
                            status: reply.status,
                            headers: reply.headers,
                            body: reply.body,
                        },
                    ))
                }
                SseItem::Event(event) => {
                    let mut data: JsonValue = match serde_json::from_str(&event.data) {
                        Ok(data) => data,
                        Err(_) => {
                            closed = true;
                            return Err(AnthropicMessagesTransportError::StreamCut);
                        }
                    };
                    // `message_start`: later `message_delta` usage extends the
                    // usage it opens, so the served model rides to the end.
                    if let Some(message) = data.get_mut("message") {
                        carry_served_model(message);
                    }
                    if !closed {
                        match data.get("type").and_then(JsonValue::as_str) {
                            Some("message_start") => inference.record(
                                data.get_mut("message")
                                    .and_then(|message| message.get_mut("usage")),
                            ),
                            Some("message_delta") => inference.record(data.get_mut("usage")),
                            Some("message_stop") => {
                                inference.finish();
                                closed = true;
                            }
                            Some("error") => {
                                inference.record(data.get_mut("usage"));
                                closed = true;
                            }
                            _ => {}
                        }
                    }
                    Ok(AnthropicMessagesStreamFrame::Event(data))
                }
            }
        });
        Ok(Box::pin(frames))
    }
}

/// One physical send's native counts and the calls its usage names. Dropping
/// this state leaves each call's last partial measurement on the lease.
struct InferenceUsage {
    lease: BudgetLease,
    calls: Vec<ObservedCall>,
    model: Option<ModelId>,
    input: Option<u64>,
    cache_read: Option<u64>,
    cache_creation: Option<u64>,
    output: Option<u64>,
    native_slots: BTreeMap<usize, usize>,
    saw_native_key: bool,
}

struct ObservedCall {
    publisher: InferencePublisher,
    measured: Option<InferenceCallReceipt>,
}

impl InferenceUsage {
    fn new(lease: &BudgetLease, model: Option<ModelId>) -> Self {
        Self {
            lease: lease.clone(),
            calls: vec![ObservedCall {
                publisher: InferencePublisher::begin(lease),
                measured: None,
            }],
            model,
            input: None,
            cache_read: None,
            cache_creation: None,
            output: None,
            native_slots: BTreeMap::new(),
            saw_native_key: false,
        }
    }

    fn record(&mut self, usage: Option<&mut JsonValue>) {
        let Some(usage) = usage.and_then(JsonValue::as_object_mut) else {
            return;
        };
        for (key, count) in [
            ("input_tokens", &mut self.input),
            ("cache_read_input_tokens", &mut self.cache_read),
            ("cache_creation_input_tokens", &mut self.cache_creation),
            ("output_tokens", &mut self.output),
        ] {
            if let Some(value) = usage.get(key) {
                *count = value.as_u64();
            }
        }
        // Compatible servers may already carry richer native receipts. Keep
        // that list and its raw fields; do not add another for the same send.
        if let Some(records) = usage.get_mut(INFERENCE_CALLS_KEY) {
            self.saw_native_key = true;
            let Some(records) = records.as_array_mut() else {
                return;
            };
            for (native_index, record) in records.iter_mut().enumerate() {
                let Ok(mut receipt) =
                    serde_json::from_value::<InferenceCallReceipt>(record.clone())
                else {
                    continue;
                };
                let Some(record) = record.as_object_mut() else {
                    continue;
                };
                match &self.model {
                    Some(model) => {
                        record.insert(
                            "model".to_owned(),
                            JsonValue::String(model.as_str().to_owned()),
                        );
                    }
                    None => {
                        record.remove("model");
                    }
                }
                receipt.model.clone_from(&self.model);
                // The first valid native member replaces the synthetic fallback.
                // Native positions retain their assigned slots on later updates.
                let slot = if let Some(&slot) = self.native_slots.get(&native_index) {
                    slot
                } else {
                    let slot = if self.native_slots.is_empty() {
                        0
                    } else {
                        self.calls.len()
                    };
                    self.native_slots.insert(native_index, slot);
                    slot
                };
                self.publish(slot, receipt);
            }
            return;
        }
        if self.saw_native_key {
            return;
        }
        // Anthropic reports uncached input separately. A complete logical
        // total needs all three actual counts, with no zero-filled defaults.
        let logical_prompt_tokens = match (self.input, self.cache_read, self.cache_creation) {
            (Some(input), Some(read), Some(creation)) => input
                .checked_add(read)
                .and_then(|total| total.checked_add(creation)),
            _ => None,
        };
        if logical_prompt_tokens.is_none()
            && self.output.is_none()
            && self.calls[0].measured.is_none()
        {
            return;
        }
        let receipt = InferenceCallReceipt {
            logical_prompt_tokens,
            output_tokens: self.output,
            ..InferenceCallReceipt::unmeasured(
                self.model.clone(),
                WorkerDescriptor {
                    kind: WorkerKind::Unknown,
                    identity: CacheIdentity::default(),
                    build_evidence: WorkerBuildEvidence::Unknown,
                },
            )
        };
        if let Ok(record) = serde_json::to_value(&receipt) {
            usage.insert(
                INFERENCE_CALLS_KEY.to_owned(),
                JsonValue::Array(vec![record]),
            );
            self.publish(0, receipt);
        }
    }

    fn publish(&mut self, slot: usize, receipt: InferenceCallReceipt) {
        while self.calls.len() <= slot {
            self.calls.push(ObservedCall {
                publisher: InferencePublisher::begin(&self.lease),
                measured: None,
            });
        }
        let call = &mut self.calls[slot];
        call.publisher.partial(receipt.clone());
        call.measured = Some(receipt);
    }

    fn finish(&self) {
        // The lower decoder also finishes when no delta named a stop reason.
        for call in &self.calls {
            if let Some(receipt) = &call.measured {
                call.publisher.finish(receipt.clone());
            }
        }
    }
}

/// Stamps the model `message` names into its usage, opening an empty usage
/// object when it has none (or a null one), as the OpenAI-compatible
/// transport does.
pub(super) fn carry_served_model(message: &mut JsonValue) {
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
