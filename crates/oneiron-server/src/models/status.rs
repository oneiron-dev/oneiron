//! What the model runtime built, for the owner-facing status route.
use oneiron::ModelId;
use oneiron::llm::manifest::ModelRole;
use serde::Serialize;

use crate::config::models::{ModelRef, ProviderConfig, ProviderKind, role_key};

/// Every provider and seat the config named, and whether each can serve.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ModelsStatus {
    /// False when the config has no `[models]` section at all.
    pub configured: bool,
    pub providers: Vec<ProviderStatus>,
    pub seats: Vec<SeatStatus>,
}

impl ModelsStatus {
    pub(super) fn unconfigured() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderStatus {
    pub name: String,
    pub kind: &'static str,
    pub base_url: String,
    pub locality: oneiron::ModelLocality,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn kind_name(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::OpenaiCompat => "openai-compat",
        ProviderKind::AnthropicCompat => "anthropic-compat",
        ProviderKind::LocalOpenaiCompat => "local-openai-compat",
        ProviderKind::Oneironer => "oneironer",
    }
}

impl ProviderStatus {
    fn with(
        name: &str,
        provider: &ProviderConfig,
        state: &'static str,
        reason: Option<String>,
    ) -> Self {
        Self {
            name: name.to_owned(),
            kind: kind_name(provider.kind),
            base_url: provider.base_url.clone(),
            locality: provider.locality,
            state,
            reason,
        }
    }

    pub(super) fn ready(name: &str, provider: &ProviderConfig) -> Self {
        Self::with(name, provider, "ready", None)
    }

    /// A tagger entry: accepted config whose consumer is the tagger slot's
    /// worker, not the LLM slot.
    pub(super) fn without_consumer(name: &str, provider: &ProviderConfig) -> Self {
        Self::with(
            name,
            provider,
            "no_consumer",
            Some(
                "tagger providers are served by the tagger slot worker, not this server build"
                    .into(),
            ),
        )
    }

    pub(super) fn unavailable(
        name: &str,
        provider: &ProviderConfig,
        error: &anyhow::Error,
    ) -> Self {
        Self::with(name, provider, "unavailable", Some(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeatState {
    Ready,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct SeatStatus {
    pub role: String,
    /// The single model id the engine pins for this seat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seat_model: Option<String>,
    pub state: SeatState,
    pub rungs: Vec<RungStatus>,
}

impl SeatStatus {
    pub(super) fn new(
        role: ModelRole,
        seat_model: Option<&ModelId>,
        state: SeatState,
        rungs: Vec<RungStatus>,
    ) -> Self {
        Self {
            role: role_key(role),
            seat_model: seat_model.map(ToString::to_string),
            state,
            rungs,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RungStatus {
    pub provider: String,
    /// The provider's own spelling of the model.
    pub model: String,
    /// The id raw `/v1/llm` calls name this model by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_model: Option<String>,
    pub locality: oneiron::ModelLocality,
    pub available: bool,
}

impl RungStatus {
    pub(super) fn new(model: &ModelRef, provider: &ProviderConfig) -> Self {
        Self {
            provider: model.provider.clone(),
            model: model.model.clone(),
            engine_model: super::engine_model_id(model, provider)
                .ok()
                .map(|id| id.to_string()),
            locality: provider.locality,
            available: true,
        }
    }
}
