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
use std::collections::{BTreeMap, BTreeSet};
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
mod cooldown;
mod decision_read;
mod declared;
mod driven;
#[cfg(test)]
mod fallback_tests;
mod forward;
mod hosted_speech;
mod http;
#[cfg(test)]
mod kept_on_device_tests;
mod ladder;
mod media;
mod offer;
mod openai;
pub(crate) mod outbound_wait;
mod output_cap;
mod raw;
mod receipts;
mod rerank;
mod role_route;
mod router;
mod run_backend;
mod served;
mod sse;
mod status;
#[cfg(test)]
mod tests;
mod voice;
mod voxcpm2_speech;
mod walk;

pub use broker::{BROKER_EFFECTOR, KeyDoor, VaultKeyDoor};
use cooldown::FallbackRung;
pub use cooldown::{OfferCooldowns, QuotaChoice, QuotaFallback, QuotaQuestion};
pub use decision_read::DecisionReadDoor;
pub use declared::DeclaredRun;
pub use hosted_speech::HostedCloner;
pub use ladder::OfferLadder;
pub use media::{MediaRow, MediaRuntime, MediaTicket};
pub use offer::ServedOffer;
pub(crate) use raw::{InjectedRuns, RawInference};
pub(crate) use receipts::ServerReceipts;
pub use receipts::{LoggedReceipts, RUN_RECEIPT_TARGET};
pub(crate) use rerank::{rerank_request, rerank_scores};
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
    host: Option<Arc<HostAccount>>,
    /// The house model's decision read (`[models.decision_read]`).
    decision_read: Option<DecisionReadDoor>,
    /// The roles whose work never leaves the device.
    stays_on_device: BTreeSet<ModelRole>,
    /// The `ai.*` media seats (`[models.media]`).
    media: MediaRuntime,
    /// Where offers refused for a limit rest, and the owner's quota
    /// questions about the parked ones.
    rests: Arc<OfferCooldowns>,
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
            host: None,
            decision_read: None,
            stays_on_device: BTreeSet::new(),
            media: MediaRuntime::empty(),
            rests: OfferCooldowns::unkept(),
        }
    }

    /// Writes the receipts of every run this runtime admits to `receipts`
    /// instead of the log.
    #[must_use]
    pub fn with_receipts(mut self, receipts: Arc<dyn RunReceiptSink>) -> Self {
        self.media.set_receipts(Arc::clone(&receipts));
        self.receipts = receipts;
        self
    }

    /// The live vault allocation used by every run this runtime serves.
    #[must_use]
    pub fn with_host_account(mut self, host: Arc<HostAccount>) -> Self {
        self.media.set_host_account(Arc::clone(&host));
        self.host = Some(host);
        self
    }

    pub(crate) fn host_account(&self) -> Option<Arc<HostAccount>> {
        self.host.clone()
    }

    /// A run that declares nothing, on a meter its host built (see
    /// [`undeclared_run`]), with this runtime's receipts.
    #[must_use]
    pub fn undeclared_run(&self, run: impl Into<String>, meter: BudgetGuard) -> RunAdmission {
        undeclared_run(run, meter, self.host.clone(), Arc::clone(&self.receipts))
    }

    /// A declared run (ARCH-0053 `#run-declaration`) on its own line, over
    /// this runtime's models: its teachers, connectors and budget, as the host
    /// that starts it states them. `host` is the account whose allocation
    /// pays host-paid offers; `None` uses this runtime's live host account.
    /// Its paid keys must sit at T0 unless the owner
    /// allowed an offer at T1; a `key_env` key is at T1.
    #[must_use]
    pub fn declared_run(
        &self,
        run: impl Into<String>,
        declaration: RunDeclaration,
        host: Option<Arc<HostAccount>>,
    ) -> DeclaredRun {
        DeclaredRun::new(
            RunAdmission::new(
                run,
                declaration,
                host.or_else(|| self.host.clone()),
                Arc::clone(&self.receipts),
            ),
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
        Self::build_hosted(config, keys, OfferCooldowns::unkept())
    }

    /// [`build_with_keys`](Self::build_with_keys), with where an offer a
    /// provider refused for a quota or a limit rests until its reset.
    #[must_use]
    pub fn build_hosted(
        config: Option<&ModelsConfig>,
        keys: Option<Arc<dyn KeyDoor>>,
        rests: Arc<OfferCooldowns>,
    ) -> Self {
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
        // The reranker's rungs speak `/v1/rerank`, not chat: each provider
        // that serves one gets a rerank client beside its chat backend.
        let mut rerankers = BTreeMap::new();
        for (name, provider) in &config.providers {
            let models = reranker_models(config, name);
            if models.is_empty() || !provider.kind.reranks() {
                continue;
            }
            match build_reranker(provider, &models) {
                Ok(backend) => {
                    rerankers.insert(name.clone(), backend);
                }
                Err(error) => {
                    tracing::warn!(provider = %name, %error, "reranker provider unavailable");
                }
            }
        }
        let mut router = ModelRouter::default();
        // Each chat model the router serves is one a parked offer's calls
        // may fall back to, once the owner names it (`use_fallback`).
        let mut fallbacks = Vec::new();
        for (rerank, backends) in [(false, &built), (true, &rerankers)] {
            for (name, backend) in backends {
                let provider = &config.providers[name];
                let models = if rerank {
                    reranker_models(config, name)
                } else {
                    referenced_models(config, name)
                };
                for model in models {
                    if let Some(rung) = rung(name, provider, backend, &model, 0, None, rerank)
                        // A model that also serves a chat role keeps its raw
                        // chat route; the reranker reaches it through its seat.
                        && !(rerank && router.served(&rung.model).is_some())
                    {
                        let ladder = Arc::new(OfferLadder::bare(rung, Arc::clone(&rests)));
                        if !rerank {
                            fallbacks.push(FallbackRung {
                                provider: name.clone(),
                                model: ladder.model().clone(),
                                ladder: Arc::downgrade(&ladder),
                            });
                        }
                        router.insert(ladder.model().clone(), provider.locality, ladder);
                    }
                }
            }
        }
        rests.offer_fallbacks(fallbacks);
        let mut seats = BTreeMap::new();
        for (role, ladder) in &config.roles {
            let mut rungs = Vec::new();
            let mut rung_status = Vec::new();
            // A seat whose work never leaves the device has no rung off it,
            // first or as a fallback.
            let stays = config.stays_on_device.contains(role);
            for (position, rung) in ladder.iter().enumerate() {
                let provider = &config.providers[&rung.model.provider];
                let mut entry = RungStatus::new(&rung.model, provider);
                let rerank = *role == ModelRole::Reranker;
                let backends = if rerank { &rerankers } else { &built };
                let served = backends
                    .get(&rung.model.provider)
                    .filter(|_| provider.kind.generates())
                    .filter(|_| !(stays && provider.locality == ModelLocality::ThirdParty))
                    .and_then(|backend| {
                        self::rung(
                            &rung.model.provider,
                            provider,
                            backend,
                            &rung.model,
                            position,
                            rung.prompt.clone(),
                            rerank,
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
            if let Some(seat) = seat_for(
                *role,
                ladder_locality(&rungs, config),
                rungs,
                Arc::clone(&rests),
            ) {
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
        let media = MediaRuntime::build(config, &rests, &mut status.seats);
        status.configured = true;
        // A read blocks on the runtime its reader was built on; a build with
        // none has no reader.
        let decision_read = tokio::runtime::Handle::try_current()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| decision_read::bind(config, runtime))
            .unwrap_or_else(|error| {
                if config.decision_read.is_some() {
                    tracing::warn!(%error, "decision read unavailable");
                }
                None
            });
        Self {
            seats,
            router: (!router.is_empty()).then(|| Arc::new(router)),
            status,
            receipts: Arc::new(LoggedReceipts),
            host: None,
            decision_read,
            stays_on_device: config.stays_on_device.clone(),
            media,
            rests,
        }
    }

    /// The house model's decision read, when `[models.decision_read]` binds
    /// one.
    #[must_use]
    pub fn decision_read(&self) -> Option<&DecisionReadDoor> {
        self.decision_read.as_ref()
    }

    /// The `ai.*` media seats: image, video, speech, transcription and
    /// embedding.
    #[must_use]
    pub fn media(&self) -> &MediaRuntime {
        &self.media
    }

    /// Hears each stable recovery of an offer whose provider was down
    /// (OF-305), for the memory work its outage stopped.
    #[must_use]
    pub fn recoveries(&self) -> tokio::sync::watch::Receiver<u64> {
        self.rests.recoveries()
    }

    /// The owner's open quota questions (OF-305): each offer parked on a
    /// spent usage window or spent credit, and the choices it offers.
    #[must_use]
    pub fn quota_questions(&self) -> Vec<QuotaQuestion> {
        self.rests.questions()
    }

    /// The owner's answer to quota question `id`; a top-up or pay-as-you-go
    /// puts its offer back in rotation now, and `use_fallback` sends its
    /// calls to `fallback`, one of the question's fallbacks, while it is
    /// parked. `false` when no such question is open, it offers no such
    /// choice, or it offers no such fallback.
    pub fn answer_quota(
        &self,
        id: &str,
        choice: QuotaChoice,
        fallback: Option<&str>,
    ) -> oneiron::Result<bool> {
        self.rests.answer(id, choice, fallback)
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

    /// [`Self::status`] with each built rung's live health, and each seat's
    /// state worked out from it (OF-305). A seat whose offers' providers are
    /// down shows Down, and one with an offer on probation shows Recovering.
    /// A limit hold shows on its rung, apart from the outage state. Read-only:
    /// it takes no probation slot, probes nothing and rebuilds nothing.
    #[must_use]
    pub fn live_status(&self) -> ModelsStatus {
        let mut status = self.status.clone();
        for seat in &mut status.seats {
            let ladder = self
                .seats
                .iter()
                .find(|(role, _)| role_key(**role) == seat.role)
                .map(|(_, built)| &built.ladder)
                .or_else(|| self.media.seat_ladder(&seat.role));
            if let Some(ladder) = ladder {
                seat.live(ladder.health());
            }
        }
        status
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
    host: Option<Arc<HostAccount>>,
    receipts: Arc<dyn RunReceiptSink>,
) -> RunAdmission {
    let line = BudgetLine {
        limit_units: meter.read().limit_units,
        reserve_units: meter.reserve_units(),
        unit: LeaseUnit::tokens(),
    };
    RunAdmission::with_meter(run, RunDeclaration::undeclared(line), meter, host, receipts)
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
        // answers generate calls, so no LLM backend is built for it. A
        // speech provider's only client is its media rung's.
        ProviderKind::Oneironer
        | ProviderKind::Cartesia
        | ProviderKind::Elevenlabs
        | ProviderKind::Voxcpm2 => {
            return Ok(None);
        }
    };
    Ok(Some(backend))
}

/// The rerank client for `provider`'s reranker `models`.
fn build_reranker(
    provider: &ProviderConfig,
    models: &[ModelRef],
) -> anyhow::Result<Arc<dyn SingleRouteBackend>> {
    // The credential broker sends chat calls only. A rerank call sent without
    // it would carry no key, while its offer says the broker holds one.
    if provider.key_secret.is_some() {
        anyhow::bail!(
            "a reranker cannot use a key_secret key yet: the credential broker sends chat calls only"
        );
    }
    let http = http::ProviderHttp::new(provider, http::KeyStyle::Bearer)?;
    let wire_models = models
        .iter()
        .map(|model| Ok((engine_model_id(model, provider)?, model.model.clone())))
        .collect::<anyhow::Result<_>>()?;
    Ok(Arc::new(rerank::RerankBackend::new(http, wire_models)))
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
    rerank: bool,
) -> Option<LadderRung> {
    let id = engine_model_id(model, provider).ok()?;
    let binding = match provider_offer(provider, id.clone(), rerank) {
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
        media: None,
    })
}

/// Every model some chat-speaking ladder names on `provider`, once each.
fn referenced_models(config: &ModelsConfig, provider: &str) -> Vec<ModelRef> {
    role_models(config, provider, |role| role != ModelRole::Reranker)
}

/// Every model the reranker's ladder names on `provider`, once each.
fn reranker_models(config: &ModelsConfig, provider: &str) -> Vec<ModelRef> {
    role_models(config, provider, |role| role == ModelRole::Reranker)
}

fn role_models(
    config: &ModelsConfig,
    provider: &str,
    roles: impl Fn(ModelRole) -> bool,
) -> Vec<ModelRef> {
    let mut models: Vec<ModelRef> = config
        .roles
        .iter()
        .filter(|(role, _)| roles(**role))
        .flat_map(|(_, ladder)| ladder)
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
fn seat_for(
    role: ModelRole,
    locality: ModelLocality,
    rungs: Vec<LadderRung>,
    rests: Arc<OfferCooldowns>,
) -> Option<Seat> {
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
            .or_insert_with(|| Arc::new(OfferLadder::pinned(rung.clone(), Arc::clone(&rests))));
    }
    Some(Seat {
        role,
        model: model.clone(),
        locality,
        ladder: Arc::new(OfferLadder::seat(model, rungs, rests)),
        rungs: alone,
    })
}
