//! The one provider abstraction: `[models]` in, one backend per seat out.
//!
//! Every provider kind is reached over HTTP through the matching adapter
//! crate (`oneiron-llm-openai` for OpenAI-compatible and local servers,
//! `oneiron-llm-anthropic` for Anthropic-compatible ones). Each role's ladder
//! becomes a [`LadderBackend`] behind one seat model id, so the engine pins a
//! single identity while the ladder falls back across rungs.
//!
//! Building never fails the server: a provider that cannot start (its key
//! variable unset, say) drops out of its ladders and the reason shows in
//! [`ModelsStatus`]. Everything that needs no model keeps working.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::manifest::ModelRole;
use oneiron::{LlmBackend, ModelId, ModelLocality};
use oneiron_llm_anthropic::{AnthropicMessagesBackend, AnthropicMessagesConfig};
use oneiron_llm_openai::{OpenAiCompatBackend, OpenAiCompatConfig};

use crate::config::models::{ModelRef, ModelsConfig, ProviderConfig, ProviderKind, role_key};

mod anthropic;
mod catalog;
mod http;
mod ladder;
mod openai;
mod output_cap;
mod role_route;
mod router;
mod served;
mod sse;
mod status;
#[cfg(test)]
mod tests;

pub use role_route::{RoleCall, RoleRefusal, RoleRoute};
pub use router::ModelRouter;
pub use status::{ModelsStatus, ProviderStatus, RungStatus, SeatState, SeatStatus};

use catalog::{catalog_entry, engine_model_id, locality_rank};
use ladder::{LadderBackend, LadderRung};
use output_cap::OutputCap;

/// One filled seat: the ladder backend, the single model id the engine
/// pins for it, and the widest route any of its rungs may take.
#[derive(Clone)]
pub struct Seat {
    pub role: ModelRole,
    pub model: ModelId,
    pub locality: ModelLocality,
    pub backend: Arc<dyn LlmBackend>,
    /// Each rung on its own, keyed by its engine model id, so a call the
    /// vault's manifest binds to one rung's model keeps that rung's prompt.
    rungs: BTreeMap<ModelId, Arc<dyn LlmBackend>>,
}

impl Seat {
    /// The rung that serves `model`, alone and with its prompt.
    fn rung(&self, model: &ModelId) -> Option<Arc<dyn LlmBackend>> {
        self.rungs.get(model).cloned()
    }
}

/// Every seat the config fills, plus a router over every configured model.
pub struct ModelRuntime {
    seats: BTreeMap<ModelRole, Seat>,
    router: Option<Arc<ModelRouter>>,
    status: ModelsStatus,
}

impl ModelRuntime {
    /// No `[models]`: no seat, no router.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            seats: BTreeMap::new(),
            router: None,
            status: ModelsStatus::unconfigured(),
        }
    }

    #[must_use]
    pub fn build(config: Option<&ModelsConfig>) -> Self {
        let Some(config) = config else {
            return Self::unconfigured();
        };
        let mut status = ModelsStatus::default();
        let mut built = BTreeMap::new();
        for (name, provider) in &config.providers {
            match build_provider(name, provider, config) {
                Ok(Some(backend)) => {
                    built.insert(name.clone(), backend);
                    status.providers.push(ProviderStatus::ready(name, provider));
                }
                Ok(None) => status
                    .providers
                    .push(ProviderStatus::without_consumer(name, provider)),
                Err(error) => {
                    tracing::warn!(provider = %name, %error, "model provider unavailable");
                    status
                        .providers
                        .push(ProviderStatus::unavailable(name, provider, &error));
                }
            }
        }
        let mut router = ModelRouter::default();
        for (name, provider) in &built {
            for model in referenced_models(config, name) {
                if let Ok(id) = engine_model_id(&model, &config.providers[name]) {
                    router.insert(id, config.providers[name].locality, provider.clone());
                }
            }
        }
        let mut seats = BTreeMap::new();
        for (role, ladder) in &config.roles {
            let mut rungs = Vec::new();
            let mut rung_status = Vec::new();
            for (position, rung) in ladder.iter().enumerate() {
                let provider = &config.providers[&rung.model.provider];
                let mut entry = RungStatus::new(&rung.model, provider);
                match (
                    built.get(&rung.model.provider),
                    engine_model_id(&rung.model, provider),
                ) {
                    (Some(built), Ok(model)) if provider.kind.generates() => {
                        rungs.push(LadderRung {
                            provider: rung.model.provider.clone(),
                            position,
                            model,
                            wire_model: rung.model.model.clone(),
                            prompt: rung.prompt.clone(),
                            backend: built.clone(),
                        });
                    }
                    _ => entry.available = false,
                }
                rung_status.push(entry);
            }
            let state = if rungs.is_empty() {
                SeatState::Unavailable
            } else {
                SeatState::Ready
            };
            if let Some(seat) = seat_for(*role, ladder_locality(&rungs, config), rungs) {
                router.insert(seat.model.clone(), seat.locality, seat.backend.clone());
                status.seats.push(SeatStatus::new(
                    *role,
                    Some(&seat.model),
                    state,
                    rung_status,
                ));
                seats.insert(*role, seat);
            } else {
                status
                    .seats
                    .push(SeatStatus::new(*role, None, state, rung_status));
            }
        }
        status.configured = true;
        Self {
            seats,
            router: (!router.is_empty()).then(|| Arc::new(router)),
            status,
        }
    }

    /// The seat for `role`, when at least one of its rungs can serve.
    #[must_use]
    pub fn seat(&self, role: ModelRole) -> Option<&Seat> {
        self.seats.get(&role)
    }

    /// A backend over every configured model and seat, for raw calls that
    /// name their model. `None` when nothing is configured.
    #[must_use]
    pub fn router(&self) -> Option<Arc<ModelRouter>> {
        self.router.clone()
    }

    #[must_use]
    pub fn status(&self) -> &ModelsStatus {
        &self.status
    }
}

fn build_provider(
    name: &str,
    provider: &ProviderConfig,
    config: &ModelsConfig,
) -> anyhow::Result<Option<Arc<dyn LlmBackend>>> {
    let catalog = referenced_models(config, name)
        .iter()
        .map(|model| catalog_entry(model, provider))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let backend: Arc<dyn LlmBackend> = match provider.kind {
        ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat => {
            let http = http::ProviderHttp::new(provider, http::KeyStyle::Bearer)?;
            Arc::new(OpenAiCompatBackend::new(
                OpenAiCompatConfig::from_catalog(catalog),
                openai::OpenAiHttp {
                    http,
                    cap: OutputCap {
                        field: provider.output_limit_field.key(),
                        ceiling: provider.max_output_tokens,
                        fallback: None,
                    },
                },
            ))
        }
        ProviderKind::AnthropicCompat => {
            let http = http::ProviderHttp::new(provider, http::KeyStyle::ApiKeyHeader)?;
            Arc::new(AnthropicMessagesBackend::new(
                AnthropicMessagesConfig::from_catalog(catalog),
                anthropic::AnthropicHttp {
                    http,
                    cap: OutputCap {
                        field: "max_tokens",
                        ceiling: provider.max_output_tokens,
                        fallback: Some(anthropic::DEFAULT_MAX_OUTPUT_TOKENS),
                    },
                },
            ))
        }
        // The tagger slot's worker is the consumer of this kind; it never
        // answers generate calls, so no LLM backend is built for it.
        ProviderKind::Oneironer => return Ok(None),
    };
    Ok(Some(backend))
}

/// Every model some ladder names on `provider`, once each.
fn referenced_models(config: &ModelsConfig, provider: &str) -> Vec<ModelRef> {
    let mut models: Vec<ModelRef> = config
        .roles
        .values()
        .flatten()
        .filter(|rung| rung.model.provider == provider)
        .map(|rung| rung.model.clone())
        .collect();
    models.sort();
    models.dedup();
    models
}

/// The widest route any rung may take: what an egress check must assume.
fn ladder_locality(rungs: &[LadderRung], config: &ModelsConfig) -> ModelLocality {
    rungs
        .iter()
        .filter_map(|rung| config.providers.get(&rung.provider))
        .map(|provider| provider.locality)
        .max_by_key(|locality| locality_rank(*locality))
        .unwrap_or(ModelLocality::OwnServer)
}

/// The seat id names the role and a digest of its rungs, so a changed
/// ladder is a new identity and memoized steps never cross configs.
fn seat_for(role: ModelRole, locality: ModelLocality, rungs: Vec<LadderRung>) -> Option<Seat> {
    if rungs.is_empty() {
        return None;
    }
    let mut digest = blake3::Hasher::new();
    for rung in &rungs {
        digest.update(rung.model.as_str().as_bytes());
        digest.update(&[0]);
        digest.update(rung.wire_model.as_bytes());
        digest.update(&[0]);
        digest.update(rung.prompt.as_deref().unwrap_or_default().as_bytes());
        digest.update(&[0xff]);
    }
    let revision = &digest.finalize().to_hex()[..12];
    let model = ModelId::new(format!("seat/{}@{revision}", role_key(role))).ok()?;
    let mut alone: BTreeMap<ModelId, Arc<dyn LlmBackend>> = BTreeMap::new();
    for rung in &rungs {
        alone.entry(rung.model.clone()).or_insert_with(|| {
            Arc::new(LadderBackend::new(rung.model.clone(), vec![rung.clone()]))
        });
    }
    Some(Seat {
        role,
        model: model.clone(),
        locality,
        backend: Arc::new(LadderBackend::new(model, rungs)),
        rungs: alone,
    })
}
