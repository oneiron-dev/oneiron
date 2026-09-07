use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::{
    BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, FinishReason,
    LlmBackend, LlmError, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, RetryableLlmError, TierPrecedence,
};
use oneiron::voice_cascade::PartialEnrichment;
use serde::Deserialize;
use serde_json::json;

use super::HostError;
use crate::runtime::{RuntimeConfig, RuntimeProviderKind, RuntimeRole, RuntimeRouteState};

const MAX_PROMPT_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_ITEMS: usize = 16;
const MAX_ITEM_BYTES: usize = 128;
const MAX_OUTPUT_TOKENS: u64 = 512;
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct TinyExtractor {
    pub(super) backend: Arc<dyn LlmBackend>,
    pub(super) budget: BudgetGuard,
    model: ModelId,
    locality: ModelLocality,
    prompt: String,
}

impl TinyExtractor {
    pub(super) fn new(
        runtime: &RuntimeConfig,
        backend: Arc<dyn LlmBackend>,
        budget: BudgetGuard,
        prompt: String,
    ) -> Result<Self, HostError> {
        let route = runtime.route_for_role(RuntimeRole::Summarizer);
        if route.state != RuntimeRouteState::Available
            || prompt.trim().is_empty() || prompt.len() > MAX_PROMPT_BYTES
        {
            return Err(HostError::InvalidRequest);
        }
        let model = ModelId::new(route.model).map_err(|_| HostError::InvalidRequest)?;
        let locality = match route.provider_kind {
            RuntimeProviderKind::Local => ModelLocality::OnDevice,
            RuntimeProviderKind::ByoCloud => ModelLocality::ThirdParty,
            RuntimeProviderKind::OneironCloud => ModelLocality::OwnServer,
        };
        Ok(Self { backend, budget, model, locality, prompt })
    }

    fn request(&self, text: &str) -> LlmRequest {
        let list = json!({
            "type": "array", "maxItems": MAX_ITEMS,
            "items": {"type": "string", "minLength": 1, "maxLength": MAX_ITEM_BYTES}
        });
        LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                purpose: CallPurpose::Extraction,
                class: CallClass::BestEffort,
                tier: TierPrecedence {
                    per_call: Some(ModelTierRef("tiny".to_owned())),
                    vault_policy: None,
                    purpose_default: None,
                    global_default: ModelTierRef("tiny".to_owned()),
                },
                response_format: ResponseFormat::Json { schema: json!({
                    "type": "object", "additionalProperties": false,
                    "required": ["entity_labels", "salient_terms"],
                    "properties": {"entity_labels": list, "salient_terms": list}
                }) },
                locality: self.locality,
            },
            messages: vec![
                LlmMessage { role: LlmMessageRole::System, content: vec![ContentPart::Text {
                    text: self.prompt.clone(),
                }] },
                LlmMessage { role: LlmMessageRole::User, content: vec![ContentPart::Text {
                    text: json!({"text": text}).to_string(),
                }] },
            ],
            tools: Vec::new(),
            params: BTreeMap::from([("max_output_tokens".to_owned(), json!(MAX_OUTPUT_TOKENS))]),
            provider_options: BTreeMap::new(),
        }
    }

    pub(super) async fn extract(&self, text: &str) -> Result<PartialEnrichment, HostError> {
        let request = self.request(text);
        let admission = self.budget.admit_for_request(&request).map_err(LlmError::from)?;
        let mut lease = OpenLease { budget: &self.budget, lease: Some(admission.lease) };
        let response = tokio::time::timeout(
            PROVIDER_TIMEOUT,
            self.backend.generate(request, lease.lease.as_ref().ok_or(HostError::Stopped)?),
        ).await.map_err(|_| LlmError::from(RetryableLlmError::Timeout))??;
        // Account for actual provider work even when its output is malformed or
        // the originating observation became stale. Never claim cancellation is
        // proof of zero upstream spend; no usage is invented for errors/drops.
        self.budget.settle_per_call(
            lease.lease.as_ref().ok_or(HostError::Stopped)?, &response.usage,
        ).map_err(LlmError::from)?;
        lease.lease = None;
        validate_response(response)
    }
}

/// Releases the real reservation on error, timeout or future cancellation.
struct OpenLease<'a> {
    budget: &'a BudgetGuard,
    lease: Option<BudgetLease>,
}

impl Drop for OpenLease<'_> {
    fn drop(&mut self) {
        if let Some(lease) = &self.lease {
            let _ = self.budget.abort(lease);
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Extraction {
    entity_labels: Vec<String>,
    salient_terms: Vec<String>,
}

fn validate_response(response: LlmResponse) -> Result<PartialEnrichment, HostError> {
    if response.finish_reason != FinishReason::Stop || response.message.role != LlmMessageRole::Assistant {
        return Err(HostError::InvalidResponse);
    }
    let [ContentPart::Text { text }] = response.message.content.as_slice() else {
        return Err(HostError::InvalidResponse);
    };
    if text.len() > MAX_RESPONSE_BYTES {
        return Err(HostError::InvalidResponse);
    }
    let extraction: Extraction = serde_json::from_str(text).map_err(|_| HostError::InvalidResponse)?;
    for items in [&extraction.entity_labels, &extraction.salient_terms] {
        if items.len() > MAX_ITEMS || items.iter().any(|item| {
            item.trim().is_empty() || item.len() > MAX_ITEM_BYTES || item.chars().any(char::is_control)
        }) {
            return Err(HostError::InvalidResponse);
        }
    }
    // Empty arrays are a legitimate successful extraction, not a token fallback.
    Ok(PartialEnrichment {
        entity_labels: extraction.entity_labels,
        salient_terms: extraction.salient_terms,
        query_vector: None,
    })
}
