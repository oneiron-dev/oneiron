//! The Gemini API's chat transport (FIX 1816): a `gemini` provider's chat
//! rungs send `generateContent` and `streamGenerateContent` through
//! [`GeminiBackend`], as the other provider kinds send their own wires. The
//! key rides as `x-goog-api-key`. A `key_secret` provider's chat goes
//! through the credential broker's `GeminiGenerate` call; its media calls go
//! through the broker already.
use std::collections::BTreeMap;
use std::sync::Arc;

use futures_util::StreamExt;
use oneiron::llm::{
    CacheIdentity, INFERENCE_CALLS_KEY, InferenceCallReceipt, InferencePublisher, ModelId,
    SingleRouteBackend, WorkerBuildEvidence, WorkerDescriptor, WorkerKind,
};
use oneiron::{BudgetLease, FatalLlmError, LlmCatalogEntry, LlmResult};
use oneiron_llm_gemini::{
    GeminiBackend, GeminiFrame, GeminiFuture, GeminiHttpRequest, GeminiHttpResponse,
    GeminiProviderStream, GeminiTransport,
};
use serde_json::Value as JsonValue;

use super::http::{KeyStyle, ProviderHttp, SseItem};
use super::output_cap::OutputCap;
use super::rerank::transport;
use crate::config::models::ProviderConfig;

/// One Gemini provider's chat client.
pub(super) struct GeminiHttp {
    http: ProviderHttp,
    pub(super) cap: OutputCap,
    engine_models: BTreeMap<String, ModelId>,
}

/// One `.send()` per call over [`ProviderHttp`], which follows no redirect
/// and never resends: a run's gate may wrap this transport's adapter.
impl oneiron::llm::SingleSend for GeminiHttp {}

impl GeminiHttp {
    fn inference_model(&self, path: &str) -> Option<ModelId> {
        let (wire, _) = path.strip_prefix("/v1beta/models/")?.split_once(':')?;
        self.engine_models.get(wire).cloned()
    }
}

impl GeminiTransport for GeminiHttp {
    fn execute<'a>(
        &'a self,
        mut request: GeminiHttpRequest,
        lease: &'a BudgetLease,
    ) -> GeminiFuture<'a> {
        Box::pin(async move {
            if let Some(generation) = request.body.get_mut("generationConfig") {
                self.cap.apply(generation);
            }
            let mut inference = InferenceUsage::new(lease, self.inference_model(&request.path));
            let mut reply = self
                .http
                .post_json(&request.path, &BTreeMap::new(), &request.body)
                .await
                .map_err(transport)?;
            // Failed responses can still carry native work measurements.
            inference.record(reply.body.get_mut("usageMetadata"));
            if (200..300).contains(&reply.status) {
                inference.finish();
            }
            Ok(GeminiHttpResponse {
                status: reply.status,
                body: reply.body,
            })
        })
    }

    fn stream<'a>(
        &'a self,
        mut request: GeminiHttpRequest,
        lease: &'a BudgetLease,
    ) -> LlmResult<GeminiProviderStream<'a>> {
        if let Some(generation) = request.body.get_mut("generationConfig") {
            self.cap.apply(generation);
        }
        let mut inference = InferenceUsage::new(lease, self.inference_model(&request.path));
        let mut closed = false;
        let events = self
            .http
            .post_sse(&request.path, &BTreeMap::new(), &request.body);
        let frames = events.map(move |item| -> LlmResult<GeminiFrame> {
            let item = match item {
                Ok(item) => item,
                Err(error) => {
                    closed = true;
                    return Err(transport(error));
                }
            };
            match item {
                SseItem::Status(mut reply) => {
                    if !closed {
                        inference.record(reply.body.get_mut("usageMetadata"));
                    }
                    // The lower decoder continues past a successful Status.
                    closed |= !(200..300).contains(&reply.status);
                    Ok(GeminiFrame::Status(GeminiHttpResponse {
                        status: reply.status,
                        body: reply.body,
                    }))
                }
                SseItem::Event(event) => {
                    let mut chunk: JsonValue = match serde_json::from_str(&event.data) {
                        Ok(chunk) => chunk,
                        Err(_) => {
                            closed = true;
                            return Err(FatalLlmError::EmptyResponse.into());
                        }
                    };
                    if !closed {
                        inference.record(chunk.get_mut("usageMetadata"));
                        if chunk
                            .get("candidates")
                            .and_then(JsonValue::as_array)
                            .and_then(|candidates| candidates.first())
                            .and_then(|candidate| candidate.get("finishReason"))
                            .and_then(JsonValue::as_str)
                            .is_some()
                        {
                            inference.finish();
                            closed = true;
                        }
                    }
                    Ok(GeminiFrame::Chunk(chunk))
                }
            }
        });
        Ok(Box::pin(frames))
    }
}

/// The calls this send's usage names, retained on the lease if it fails or
/// is dropped. Native list positions stay stable across usage updates.
struct InferenceUsage {
    lease: BudgetLease,
    calls: Vec<ObservedCall>,
    model: Option<ModelId>,
    prompt: Option<u64>,
    candidates: Option<u64>,
    thoughts: Option<u64>,
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
            prompt: None,
            candidates: None,
            thoughts: None,
            native_slots: BTreeMap::new(),
            saw_native_key: false,
        }
    }

    fn record(&mut self, usage: Option<&mut JsonValue>) {
        let Some(usage) = usage.and_then(JsonValue::as_object_mut) else {
            return;
        };
        for (key, count) in [
            ("promptTokenCount", &mut self.prompt),
            ("candidatesTokenCount", &mut self.candidates),
            ("thoughtsTokenCount", &mut self.thoughts),
        ] {
            if let Some(value) = usage.get(key) {
                *count = value.as_u64();
            }
        }
        // Preserve a compatible server's richer records and their raw fields.
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
        // Prompt already includes cached input. Candidates and thoughts are
        // separate output counts; neither missing field is a measured zero.
        let output_tokens = self
            .candidates
            .zip(self.thoughts)
            .and_then(|(candidates, thoughts)| candidates.checked_add(thoughts));
        if self.prompt.is_none() && output_tokens.is_none() && self.calls[0].measured.is_none() {
            return;
        }
        let receipt = InferenceCallReceipt {
            logical_prompt_tokens: self.prompt,
            output_tokens,
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
        for call in &self.calls {
            if let Some(receipt) = &call.measured {
                call.publisher.finish(receipt.clone());
            }
        }
    }
}

/// The chat backend of `provider` over the models its chat rungs name,
/// `catalog`. `None` when no chat rung names it, or its key is a
/// `key_secret` one.
pub(super) fn chat_backend(
    provider: &ProviderConfig,
    catalog: Vec<LlmCatalogEntry>,
    cap: OutputCap,
) -> anyhow::Result<Option<Arc<dyn SingleRouteBackend>>> {
    if catalog.is_empty() || provider.key_secret.is_some() {
        return Ok(None);
    }
    // The adapter owns the versioned paths: the base is the API's origin.
    let mut provider = provider.clone();
    provider.base_url = provider
        .base_url
        .strip_suffix("/v1beta")
        .unwrap_or(&provider.base_url)
        .to_owned();
    let http = ProviderHttp::new(&provider, KeyStyle::Named("x-goog-api-key"))?;
    let engine_models = catalog
        .iter()
        .filter_map(|entry| {
            entry
                .metadata
                .get("wire_model")?
                .as_str()
                .map(|wire| (wire.to_owned(), entry.model.clone()))
        })
        .collect();
    Ok(Some(Arc::new(GeminiBackend::from_catalog(
        catalog,
        GeminiHttp {
            http,
            cap,
            engine_models,
        },
    ))))
}
