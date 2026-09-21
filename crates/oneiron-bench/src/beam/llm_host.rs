//! Host-owned HTTP transport for the shipped LlmBackend adapter.
use super::{BeamError, BeamResult, model_usage::PriceTable, report_model::CostComponentReport};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ContentPart, LlmBackend, LlmCatalogEntry, LlmMessage, LlmMessageRole, LlmRequest, ModelId,
    ModelLocality, ModelTierRef, PinnedModelConfig, ResponseFormat, TierPrecedence,
    llm::{
        LlmCatalogCost,
        registry::{ModelRegistryRow, ModelWireFormat},
    },
};
use oneiron_llm_openai::{
    OpenAiCompatBackend, OpenAiCompatConfig, OpenAiCompatFuture, OpenAiCompatHttpRequest,
    OpenAiCompatHttpResponse, OpenAiCompatProviderStream, OpenAiCompatTransport,
    OpenAiCompatTransportError,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelPin {
    pub model_id: ModelId,
    pub provider_model: String,
    pub max_tokens: u64,
    pub temperature: f64,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostConfig {
    pub endpoint: String,
    pub api_key_env: Option<String>,
    pub token_budget: u64,
    pub prices: PriceTable,
}
struct HttpTransport {
    client: reqwest::Client,
    endpoint: String,
    models: BTreeMap<String, String>,
}
impl OpenAiCompatTransport for HttpTransport {
    fn execute<'a>(
        &'a self,
        mut request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiCompatFuture<'a> {
        Box::pin(async move {
            let name = request.body["model"]
                .as_str()
                .ok_or(OpenAiCompatTransportError::Server)?;
            let pinned = self
                .models
                .get(name)
                .ok_or(OpenAiCompatTransportError::Server)?;
            request.body["model"] = serde_json::Value::String(pinned.clone());
            let response = self
                .client
                .post(&self.endpoint)
                .json(&request.body)
                .send()
                .await
                .map_err(|error| {
                    if error.is_timeout() {
                        OpenAiCompatTransportError::Timeout
                    } else {
                        OpenAiCompatTransportError::Connection
                    }
                })?;
            let status = response.status().as_u16();
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|_| OpenAiCompatTransportError::Server)?;
            if (200..300).contains(&status)
                && (body["model"].as_str() != Some(pinned.as_str()) || !body["usage"].is_object())
            {
                return Err(OpenAiCompatTransportError::Server);
            }
            Ok(OpenAiCompatHttpResponse {
                status,
                headers: BTreeMap::new(),
                body,
            })
        })
    }
    fn stream<'a>(
        &'a self,
        _request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> Result<OpenAiCompatProviderStream<'a>, OpenAiCompatTransportError> {
        Err(OpenAiCompatTransportError::Server)
    }
}
#[derive(Debug, Clone, Serialize)]
pub(super) struct ModelCallReceipt {
    pub model: ModelId,
    pub purpose: CallPurpose,
    pub request_hash: String,
    pub usage: oneiron::LlmUsage,
    pub elapsed_us: u64,
}
pub(super) struct ModelSession {
    receipts: std::cell::RefCell<Vec<ModelCallReceipt>>,
    backend: Box<dyn LlmBackend>,
    runtime: tokio::runtime::Runtime,
    guard: BudgetGuard,
    pins: PinnedModelConfig,
    pub prices: PriceTable,
}
impl ModelSession {
    pub(super) fn connect(config: HostConfig, models: &[ModelPin]) -> BeamResult<Self> {
        let url =
            reqwest::Url::parse(&config.endpoint).map_err(|_| refusal("invalid LLM endpoint"))?;
        let loopback = url
            .host_str()
            .is_some_and(|h| matches!(h, "localhost" | "127.0.0.1" | "[::1]" | "::1"));
        if (!loopback && url.scheme() != "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
        {
            return Err(refusal(
                "LLM endpoint requires HTTPS (except loopback), and no URL credentials",
            ));
        }
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(name) = &config.api_key_env {
            let key = std::env::var(name)
                .map_err(|_| refusal("LLM key environment variable is missing"))?;
            let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
                .map_err(|_| refusal("invalid authorization value"))?;
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|_| refusal("LLM HTTP client creation failed"))?;
        let mut mappings = BTreeMap::new();
        let mut catalog = Vec::new();
        for pin in models {
            if pin.provider_model.is_empty()
                || pin.max_tokens == 0
                || !pin.temperature.is_finite()
                || !(0.0..=2.0).contains(&pin.temperature)
                || !config.prices.models.contains_key(&pin.model_id)
            {
                return Err(refusal("model pin, params or price missing"));
            }
            if let Some(previous) =
                mappings.insert(pin.model_id.name().to_owned(), pin.provider_model.clone())
                && previous != pin.provider_model
            {
                return Err(refusal("ambiguous model revision mapping"));
            }
            catalog.push(LlmCatalogEntry {
                model: pin.model_id.clone(),
                display_name: pin.provider_model.clone(),
                locality: ModelLocality::ThirdParty,
                context_window_tokens: 1_000_000,
                max_output_tokens: Some(pin.max_tokens),
                cost: None,
                capabilities: Vec::new(),
                metadata: BTreeMap::new(),
            });
        }
        // Load only this run's pinned models through the adapter's registry door.
        let registry_dir = tempfile::tempdir()?;
        let registry =
            oneiron::Vault::open(registry_dir.path(), super::util::beam_vault_config())?;
        for mut entry in catalog {
            let price = &config.prices.models[&entry.model];
            entry.cost = Some(LlmCatalogCost {
                input_per_million: price.input_per_million.to_string(),
                output_per_million: price.output_per_million.to_string(),
                cache_read_per_million: Some(price.cache_read_per_million.to_string()),
                cache_write_per_million: Some(price.cache_write_per_million.to_string()),
            });
            registry.put_model_registry_row(&ModelRegistryRow {
                version: 1,
                wire: ModelWireFormat::OpenaiCompat,
                catalog: entry,
                scores: BTreeMap::new(),
                fetched_at: BTreeMap::new(),
            })?;
        }
        let backend = OpenAiCompatBackend::new(
            OpenAiCompatConfig::from_registry(&registry)?,
            HttpTransport {
                client,
                endpoint: config.endpoint,
                models: mappings,
            },
        );
        Self::with_backend(
            Box::new(backend),
            config.prices,
            models,
            config.token_budget,
        )
    }
    pub(super) fn with_backend(
        backend: Box<dyn LlmBackend>,
        prices: PriceTable,
        models: &[ModelPin],
        budget: u64,
    ) -> BeamResult<Self> {
        Ok(Self {
            backend,
            prices,
            receipts: std::cell::RefCell::new(Vec::new()),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            guard: BudgetGuard::new("beam-model-run", budget, BudgetExhaustionPolicy::Suspend),
            pins: PinnedModelConfig {
                allowed: models
                    .iter()
                    .map(|m| m.model_id.clone())
                    .collect::<BTreeSet<_>>(),
                background_tier_enabled: false,
            },
        })
    }
    pub(super) fn receipts(&self) -> Vec<ModelCallReceipt> {
        self.receipts.borrow().clone()
    }
    pub(super) fn reserve_calls(&self, count: usize) -> BeamResult<Vec<BudgetLease>> {
        let mut leases = Vec::new();
        for _ in 0..count {
            match self.guard.admit() {
                Ok(admission) => leases.push(admission.lease),
                Err(_) => {
                    for lease in &leases {
                        let _ = self.guard.abort(lease);
                    }
                    return Err(refusal("judge budget denied before any call"));
                }
            }
        }
        Ok(leases)
    }
    pub(super) fn invoke(
        &self,
        pin: &ModelPin,
        purpose: CallPurpose,
        system: &str,
        user: &str,
    ) -> BeamResult<(String, CostComponentReport)> {
        self.invoke_with_lease(pin, purpose, system, user, None)
    }
    pub(super) fn invoke_with_lease(
        &self,
        pin: &ModelPin,
        purpose: CallPurpose,
        system: &str,
        user: &str,
        lease: Option<&BudgetLease>,
    ) -> BeamResult<(String, CostComponentReport)> {
        let request = LlmRequest {
            model: pin.model_id.clone(),
            envelope: CallEnvelope {
                scope: Default::default(),
                purpose,
                class: CallClass::BestEffort,
                tier: TierPrecedence {
                    per_call: None,
                    vault_policy: None,
                    purpose_default: None,
                    global_default: ModelTierRef("eval-pinned".into()),
                },
                response_format: ResponseFormat::Text,
                locality: ModelLocality::ThirdParty,
            },
            messages: vec![
                message(LlmMessageRole::System, system),
                message(LlmMessageRole::User, user),
            ],
            tools: Vec::new(),
            params: BTreeMap::from([
                ("temperature".into(), serde_json::json!(pin.temperature)),
                (
                    "max_completion_tokens".into(),
                    serde_json::json!(pin.max_tokens),
                ),
            ]),
            provider_options: BTreeMap::new(),
        };
        self.pins
            .admit(&request)
            .map_err(|_| refusal("model is not in the admitted pin set"))?;
        let lease = match lease {
            Some(lease) => lease.clone(),
            None => {
                self.guard
                    .admit_for_request(&request)
                    .map_err(|_| refusal("model budget denied"))?
                    .lease
            }
        };
        let request_hash = request.canonical_hash_hex()?;
        let purpose = request.envelope.purpose.clone();
        let started = Instant::now();
        let response = match self
            .runtime
            .block_on(self.backend.generate(request, &lease))
        {
            Ok(response) => response,
            Err(_) => {
                self.guard
                    .abort(&lease)
                    .map_err(|_| refusal("budget abort failed"))?;
                return Err(refusal("model call failed"));
            }
        };
        self.guard
            .settle_per_call(&lease, &response.usage)
            .map_err(|_| refusal("budget settlement failed"))?;
        self.receipts.borrow_mut().push(ModelCallReceipt {
            model: pin.model_id.clone(),
            purpose,
            request_hash,
            usage: response.usage.clone(),
            elapsed_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        });
        let cost = self.prices.cost(
            &pin.model_id,
            &response.usage,
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        )?;
        if response.finish_reason != oneiron::FinishReason::Stop {
            return Err(refusal("model response did not finish normally"));
        }
        let text = response
            .message
            .content
            .iter()
            .filter_map(|p| {
                if let ContentPart::Text { text } = p {
                    Some(text.as_str())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("");
        if text.trim().is_empty() {
            return Err(refusal("model returned no text"));
        }
        Ok((text, cost))
    }
}
fn message(role: LlmMessageRole, text: &str) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text: text.into() }],
    }
}
fn refusal(reason: &str) -> BeamError {
    BeamError::Comparability {
        reason: reason.into(),
    }
}
