//! The one provider abstraction: `[models]` in, one backend per seat out.
//!
//! Every provider kind is reached over HTTP through the matching adapter
//! crate (`oneiron-llm-openai` for OpenAI-compatible and local servers,
//! `oneiron-llm-anthropic` for Anthropic-compatible ones). Each role's ladder
//! becomes an `OfferLadder` behind one seat model id, so the engine pins a
//! single identity while the ladder falls back across rungs.
//!
//! No caller reaches a provider backend: a call goes through a ladder under a
//! run admission, which admits each rung it reaches on a one-use permit and
//! sends it through the run's gate for that rung's offer (ARCH-0053
//! `#run-admission`).
//!
//! Building never fails the server: a provider that cannot start (its key
//! variable unset, say) drops out of its ladders and the reason shows in
//! [`ModelsStatus`]. Everything that needs no model keeps working.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::SingleRouteBackend;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{
    BudgetLine, HostAccount, LeaseUnit, RunAdmission, RunDeclaration, RunReceiptSink,
};
use oneiron::{BudgetGuard, ModelId, ModelLocality};
use oneiron_llm_anthropic::{AnthropicMessagesBackend, AnthropicMessagesConfig};
use oneiron_llm_openai::{OpenAiCompatBackend, OpenAiCompatConfig};

use crate::config::models::{ModelRef, ModelsConfig, ProviderConfig, ProviderKind, role_key};

mod anthropic;
mod broker;
mod catalog;
mod declared;
mod driven;
mod http;
mod ladder;
mod offer;
mod openai;
mod output_cap;
mod raw;
mod receipts;
mod role_route;
mod router;
mod run_backend;
mod served;
mod sse;
mod status;
#[cfg(test)]
mod tests;

pub use broker::{BROKER_EFFECTOR, KeyDoor, VaultKeyDoor};
pub use declared::DeclaredRun;
pub use ladder::OfferLadder;
pub use offer::ServedOffer;
pub(crate) use raw::{InjectedRuns, RawInference};
pub(crate) use receipts::ServerReceipts;
pub use receipts::{LoggedReceipts, RUN_RECEIPT_TARGET};
pub use role_route::{RoleCall, RoleRefusal, RoleRoute};
pub use router::ModelRouter;
pub use run_backend::RunBackend;
pub use status::{ModelsStatus, ProviderStatus, RungStatus, SeatState, SeatStatus};

use catalog::{catalog_entry, engine_model_id, locality_rank};
use ladder::LadderRung;
use offer::provider_offer;
use output_cap::OutputCap;

/// One filled seat: its ladder, the single model id the engine pins for it,
/// and the widest route any of its rungs may take.
#[derive(Clone)]
pub struct Seat {
    pub role: ModelRole,
    pub model: ModelId,
    pub locality: ModelLocality,
    pub ladder: Arc<OfferLadder>,
    /// Each rung on its own, keyed by its engine model id, so a call the
    /// vault's manifest binds to one rung's model keeps that rung's prompt.
    rungs: BTreeMap<ModelId, Arc<OfferLadder>>,
}

impl Seat {
    /// The rung that serves `model`, alone and with its prompt.
    fn rung(&self, model: &ModelId) -> Option<Arc<OfferLadder>> {
        self.rungs.get(model).cloned()
    }
}

/// Every seat the config fills, plus a router over every configured model,
/// and where the runs their calls are admitted under write their receipts.
pub struct ModelRuntime {
    seats: BTreeMap<ModelRole, Seat>,
    router: Option<Arc<ModelRouter>>,
    status: ModelsStatus,
    receipts: Arc<dyn RunReceiptSink>,
}

impl ModelRuntime {
    /// No `[models]`: no seat, no router.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            seats: BTreeMap::new(),
            router: None,
            status: ModelsStatus::unconfigured(),
            receipts: Arc::new(LoggedReceipts),
        }
    }

    /// Writes the receipts of every run this runtime admits to `receipts`
    /// instead of the log.
    #[must_use]
    pub fn with_receipts(mut self, receipts: Arc<dyn RunReceiptSink>) -> Self {
        self.receipts = receipts;
        self
    }

    /// A run that declares nothing, on a meter its host built (see
    /// [`undeclared_run`]), with this runtime's receipts.
    #[must_use]
    pub fn undeclared_run(&self, run: impl Into<String>, meter: BudgetGuard) -> RunAdmission {
        undeclared_run(run, meter, Arc::clone(&self.receipts))
    }

    /// A declared run (ARCH-0053 `#run-declaration`) on its own line, over
    /// this runtime's models: its teachers, connectors and budget, as the host
    /// that starts it states them. `host` is the account whose allocation
    /// pays host-paid offers. Its paid keys must sit at T0 unless the owner
    /// allowed an offer at T1; a `key_env` key is at T1.
    #[must_use]
    pub fn declared_run(
        &self,
        run: impl Into<String>,
        declaration: RunDeclaration,
        host: Option<Arc<HostAccount>>,
    ) -> DeclaredRun {
        DeclaredRun::new(
            RunAdmission::new(run, declaration, host, Arc::clone(&self.receipts)),
            self.router.clone(),
        )
    }

    #[must_use]
    pub fn build(config: Option<&ModelsConfig>) -> Self {
        Self::build_with_keys(config, None)
    }

    /// [`build`](Self::build), with the custody door a `key_secret`
    /// provider's calls read their key at. Without one, such a provider is
    /// unavailable.
    #[must_use]
    pub fn build_with_keys(config: Option<&ModelsConfig>, keys: Option<Arc<dyn KeyDoor>>) -> Self {
        let Some(config) = config else {
            return Self::unconfigured();
        };
        let mut status = ModelsStatus::default();
        let mut built = BTreeMap::new();
        // One broker for every `key_secret` provider, made only if one exists.
        let brokered = config
            .providers
            .values()
            .any(|provider| provider.key_secret.is_some() && provider.kind.generates());
        let site =
            brokered.then(|| broker::BrokerSite::new(config).map_err(|error| error.to_string()));
        for (name, provider) in &config.providers {
            match build_provider(name, provider, config, site.as_ref(), keys.as_ref()) {
                Ok(Some(backend)) => {
                    let broker = backend.broker_isolation();
                    built.insert(name.clone(), backend);
                    status
                        .providers
                        .push(ProviderStatus::ready(name, provider, broker));
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
        for (name, backend) in &built {
            let provider = &config.providers[name];
            for model in referenced_models(config, name) {
                if let Some(rung) = rung(name, provider, backend, &model, 0, None) {
                    router.insert(
                        rung.model.clone(),
                        provider.locality,
                        Arc::new(OfferLadder::bare(rung)),
                    );
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
                let served = built
                    .get(&rung.model.provider)
                    .filter(|_| provider.kind.generates())
                    .and_then(|backend| {
                        self::rung(
                            &rung.model.provider,
                            provider,
                            backend,
                            &rung.model,
                            position,
                            rung.prompt.clone(),
                        )
                    });
                match served {
                    Some(served) => rungs.push(served),
                    None => entry.available = false,
                }
                rung_status.push(entry);
            }
            let state = if rungs.is_empty() {
                SeatState::Unavailable
            } else {
                SeatState::Ready
            };
            if let Some(seat) = seat_for(*role, ladder_locality(&rungs, config), rungs) {
                router.insert(seat.model.clone(), seat.locality, Arc::clone(&seat.ladder));
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
            receipts: Arc::new(LoggedReceipts),
        }
    }

    /// The seat for `role`, when at least one of its rungs can serve.
    #[must_use]
    pub fn seat(&self, role: ModelRole) -> Option<&Seat> {
        self.seats.get(&role)
    }

    /// Every configured model and seat by id, for raw calls that name their
    /// model. `None` when nothing is configured.
    #[must_use]
    pub fn router(&self) -> Option<Arc<ModelRouter>> {
        self.router.clone()
    }

    #[must_use]
    pub fn status(&self) -> &ModelsStatus {
        &self.status
    }
}

/// A run that declares nothing, on a meter its host built: the vault's
/// budget policy for one actor's turn or step, or a route's own line. Each
/// call reserves the meter's own reservation, takes a one-use permit bound to
/// its offer, route and locality, and nothing else is checked: no allowlist,
/// no teachers.
#[must_use]
pub fn undeclared_run(
    run: impl Into<String>,
    meter: BudgetGuard,
    receipts: Arc<dyn RunReceiptSink>,
) -> RunAdmission {
    let line = BudgetLine {
        limit_units: meter.read().limit_units,
        reserve_units: meter.reserve_units(),
        unit: LeaseUnit::tokens(),
    };
    RunAdmission::with_meter(run, RunDeclaration::undeclared(line), meter, None, receipts)
}

/// One provider's wire backend. Each sends one request per call (its
/// transport is `SingleSend`, or the credential broker for a `key_secret`
/// key), so a run's gate can wrap it.
fn build_provider(
    name: &str,
    provider: &ProviderConfig,
    config: &ModelsConfig,
    site: Option<&Result<broker::BrokerSite, String>>,
    keys: Option<&Arc<dyn KeyDoor>>,
) -> anyhow::Result<Option<Arc<dyn SingleRouteBackend>>> {
    let catalog = referenced_models(config, name)
        .iter()
        .map(|model| catalog_entry(model, provider))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if provider.key_secret.is_some() && provider.kind.generates() {
        let site = site
            .ok_or_else(|| anyhow::anyhow!("no credential broker was made"))?
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        return Ok(Some(Arc::new(broker::broker_backend(
            provider,
            catalog,
            output_cap(provider),
            site,
            keys,
        )?)));
    }
    let backend: Arc<dyn SingleRouteBackend> = match provider.kind {
        ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat => {
            let http = http::ProviderHttp::new(provider, http::KeyStyle::Bearer)?;
            Arc::new(OpenAiCompatBackend::new(
                OpenAiCompatConfig::from_catalog(catalog),
                openai::OpenAiHttp {
                    http,
                    cap: output_cap(provider),
                    response_format: provider.response_format,
                },
            ))
        }
        ProviderKind::AnthropicCompat => {
            let http = http::ProviderHttp::new(provider, http::KeyStyle::ApiKeyHeader)?;
            Arc::new(AnthropicMessagesBackend::new(
                AnthropicMessagesConfig::from_catalog(catalog),
                anthropic::AnthropicHttp {
                    http,
                    cap: output_cap(provider),
                },
            ))
        }
        // The tagger slot's worker is the consumer of this kind; it never
        // answers generate calls, so no LLM backend is built for it.
        ProviderKind::Oneironer => return Ok(None),
    };
    Ok(Some(backend))
}

/// The output ceiling a provider's wire carries.
fn output_cap(provider: &ProviderConfig) -> OutputCap {
    match provider.kind {
        ProviderKind::AnthropicCompat => OutputCap {
            field: "max_tokens",
            ceiling: provider.max_output_tokens,
            fallback: Some(anthropic::DEFAULT_MAX_OUTPUT_TOKENS),
        },
        _ => OutputCap {
            field: provider.output_limit_field.key(),
            ceiling: provider.max_output_tokens,
            fallback: None,
        },
    }
}

/// `model` on `provider` as a rung at `position`: the offer a run admits its
/// calls under, over the provider's backend. `None` when the model has no
/// engine id or the provider's URL no route.
fn rung(
    name: &str,
    provider: &ProviderConfig,
    backend: &Arc<dyn SingleRouteBackend>,
    model: &ModelRef,
    position: usize,
    prompt: Option<String>,
) -> Option<LadderRung> {
    let id = engine_model_id(model, provider).ok()?;
    let binding = match provider_offer(provider, id.clone()) {
        Ok(binding) => binding,
        Err(error) => {
            tracing::warn!(provider = %name, %error, "model has no offer route");
            return None;
        }
    };
    Some(LadderRung {
        provider: name.to_owned(),
        position,
        model: id,
        wire_model: model.model.clone(),
        prompt,
        offer: ServedOffer {
            binding,
            backend: Arc::clone(backend),
        },
    })
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
    let mut alone: BTreeMap<ModelId, Arc<OfferLadder>> = BTreeMap::new();
    for rung in &rungs {
        alone
            .entry(rung.model.clone())
            .or_insert_with(|| Arc::new(OfferLadder::seat(rung.model.clone(), vec![rung.clone()])));
    }
    Some(Seat {
        role,
        model: model.clone(),
        locality,
        ladder: Arc::new(OfferLadder::seat(model, rungs)),
        rungs: alone,
    })
}
