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
    BudgetLine, HostAccount, LeaseUnit, PayerPerson, RunAdmission, RunAttribution, RunDeclaration,
    RunReceiptSink,
};
use oneiron::{BudgetGuard, LlmCatalogEntry, ModelId, ModelLocality};
use oneiron_llm_anthropic::{AnthropicMessagesBackend, AnthropicMessagesConfig};
use oneiron_llm_openai::{OpenAiCompatBackend, OpenAiCompatConfig};

use crate::config::models::{ModelRef, ModelsConfig, ProviderConfig, ProviderKind, role_key};

mod anthropic;
mod broker;
mod broker_context;
mod broker_media;
mod cache_usage;
mod catalog;
mod cooldown;
mod decision_read;
mod declared;
#[cfg(feature = "mesh")]
mod discovered;
mod driven;
#[cfg(test)]
mod fallback_tests;
mod family;
mod forward;
mod gemini_chat;
mod gemini_media;
mod host_budgets;
mod hosted_speech;
mod http;
#[cfg(test)]
mod kept_on_device_tests;
mod ladder;
pub(crate) mod launch_price;
mod llama_identity;
mod media;
#[cfg(unix)]
mod native_exl3;
mod offer;
mod openai;
pub(crate) mod outbound_wait;
mod output_cap;
mod raw;
// FIX 462: realtime voice sessions on a voice-loop run.
mod realtime_voice;
mod receipts;
mod rerank;
mod responses_socket;
mod role_route;
mod router;
mod run_backend;
mod runtime;
mod served;
pub(crate) mod soniox;
mod source_admission;
mod sse;
mod status;
#[cfg(test)]
mod tests;
mod token_ratio;
mod training;
mod voice;
mod voxcpm2_speech;
mod walk;
mod worker_host;

pub use broker::{BROKER_EFFECTOR, KeyDoor, VaultKeyDoor};
pub(crate) use broker_context::BrokerContext;
use cooldown::FallbackRung;
pub use cooldown::{OfferCooldowns, QuotaChoice, QuotaFallback, QuotaQuestion};
pub use decision_read::DecisionReadDoor;
pub use declared::DeclaredRun;
#[cfg(feature = "mesh")]
pub(crate) use discovered::MeshRoutes;
pub(crate) use host_budgets::ModelHostBudgets;
pub use hosted_speech::{HostedCloner, VendorVoice};
pub(crate) use http::{codec_token, encode_request_body, mark_cloud_node};
pub use ladder::{CallDeadline, OfferLadder};
pub(crate) use media::RungVoices;
pub use media::{MediaRow, MediaRuntime, MediaTicket};
pub use offer::{OfferEndpoint, ServedOffer};
pub(crate) use raw::{InjectedRuns, RawInference, funded_run};
pub use realtime_voice::{RealtimeVoiceRung, RealtimeVoiceSession, RealtimeWire, VOICE_LOOP_RUN};
pub(crate) use receipts::ServerReceipts;
pub use receipts::{LoggedReceipts, RUN_RECEIPT_TARGET};
pub(crate) use rerank::{
    RerankLine, RerankOutcome, RerankStop, on_line, rerank_outcome, rerank_request,
};
pub(crate) use responses_socket::ResponsesContext;
pub use role_route::{RoleCall, RoleRefusal, RoleRoute};
pub use router::ModelRouter;
pub use run_backend::RunBackend;
pub(crate) use source_admission::{SourceAdmission, SourceOffer};
pub use status::{
    DeviceDeclarationStatus, DeviceExecutorStatus, DevicePressureStatus, DeviceRowStatus,
    DeviceStatus, DiscoveredStatus, ModelsStatus, ProviderStatus, RungStatus, SeatState,
    SeatStatus, SnapshotReceipt, SnapshotSkips, SnapshotStatus,
};
pub use token_ratio::TokenRatios;
pub(crate) use worker_host::{install_snapshot_runtime, permit_worker_launch};
// DESIGN-V2 R2: a committed chat reply reaches the session coordinator; R3:
// with what a snapshot of it is kept and restored under.
pub(crate) use worker_host::{
    AuthorityVerdict, CheckpointAuthority, ReplyCommit, RestoreClaim, SnapshotScope,
    reply_committed, turn_admitted,
};

use catalog::{catalog_entry, engine_model_id, locality_rank, model_family};
use ladder::{LadderRung, SeatScope, Wire};
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

    /// Each rung's engine model id and the prompt it prepends, in ladder
    /// order: every model a call on the seat may be served on.
    pub(crate) fn rung_models(&self) -> Vec<(ModelId, Option<String>)> {
        self.ladder
            .rung_models()
            .map(|(model, prompt)| (model.clone(), prompt.map(str::to_owned)))
            .collect()
    }

    /// The owner-named fallback rungs a parked call on this seat may use.
    pub(crate) fn fallback_rung_models(&self) -> Vec<(ModelId, Option<String>)> {
        self.ladder.fallback_rung_models()
    }
}

/// Every seat the config fills, plus a router over every configured model,
/// and where the runs their calls are admitted under write their receipts.
pub struct ModelRuntime {
    seats: BTreeMap<ModelRole, Seat>,
    router: Option<Arc<ModelRouter>>,
    /// The router the raw routes call: the configured one, else an empty one
    /// that only the models the owner's other nodes offer fill (FIX 3229).
    raw_router: Arc<ModelRouter>,
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
    /// Counts each catalog model's tokenizer on the fixed passage (OF-577).
    token_ratios: Option<Arc<TokenRatios>>,
    /// The trainer connectors `[models.training]` names (FIX 7263).
    training: crate::config::models::TrainingSettings,
    /// The vault's model byte budgets its media rungs and mesh routes hold
    /// their bytes on (FIX 9321, FIX 9323).
    budgets: ModelHostBudgets,
    /// This server's Responses state, which its socket pools hold (FIX 9516).
    responses: ResponsesContext,
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
    raw::funded_run(run, meter, host, receipts, None)
}

/// One provider's wire backend. Each sends one request per call (its
/// transport is `SingleSend`, or the credential broker for a `key_secret`
/// key), so a run's gate can wrap it. A chat route resolves a house
/// llama.cpp answer's launch alias through `identities`.
fn build_provider(
    name: &str,
    provider: &ProviderConfig,
    config: &ModelsConfig,
    site: Option<&Result<broker::BrokerSite, String>>,
    keys: Option<&Arc<dyn KeyDoor>>,
    identities: &Arc<llama_identity::LlamaIdentityResolver>,
    responses: &ResponsesContext,
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
            let sockets = provider
                .responses_socket
                .map(|socket| {
                    responses_socket::ResponsesSockets::new(
                        provider,
                        &http.url("/v1/responses"),
                        socket.max_age_secs,
                        responses.clone(),
                    )
                })
                .transpose()?;
            // Only an own server reads the host's solo marker (INF 1).
            let solo = provider.kind == ProviderKind::LocalOpenaiCompat;
            let engine_models: BTreeMap<String, ModelId> = catalog
                .iter()
                .filter_map(|entry| {
                    entry
                        .metadata
                        .get("wire_model")?
                        .as_str()
                        .map(|wire| (wire.to_owned(), entry.model.clone()))
                })
                .collect();
            let config = OpenAiCompatConfig::from_catalog(catalog).with_solo_admission(solo);
            let transport = openai::OpenAiHttp {
                http,
                cap: output_cap(provider),
                response_format: provider.response_format,
                identities: Arc::clone(identities),
                engine_models,
            };
            // A provider a managed EXL3 worker of this process is bound to
            // calls that worker over its native socket (DESIGN-V2 §8); every
            // other call, and every other provider, stays on HTTP as before.
            #[cfg(unix)]
            let native = native_exl3::NativeExl3Transport::bind(name, sockets.is_some(), transport);
            #[cfg(unix)]
            let transport = match native {
                Ok(native) => {
                    let chat = OpenAiCompatBackend::new(config, native);
                    return Ok(Some(Arc::new(chat)));
                }
                Err(transport) => transport,
            };
            let chat = OpenAiCompatBackend::new(config, transport);
            // A provider that serves Responses over a socket holds one by
            // default (ARCH-0081 §5); its chat HTTP path is the fallback.
            match sockets {
                Some(sockets) => Arc::new(responses_socket::OpenAiSessions {
                    chat,
                    sockets,
                    cap: OutputCap {
                        field: "max_output_tokens",
                        ..output_cap(provider)
                    },
                    response_format: provider.response_format,
                }),
                None => Arc::new(chat),
            }
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
        // A gemini provider's chat rungs send the Gemini API's own wire
        // (FIX 1816); one that serves media seats only gets none.
        ProviderKind::Gemini => return gemini_chat::chat_backend(provider, catalog),
        // The tagger slot's worker is the consumer of this kind; it never
        // answers generate calls, so no LLM backend is built for it. A
        // media-only provider's only client is its media rung's.
        ProviderKind::Oneironer
        | ProviderKind::Cartesia
        | ProviderKind::Elevenlabs
        | ProviderKind::Voxcpm2
        | ProviderKind::Soniox => {
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
            "a reranker cannot use a key_secret key yet: the credential broker has no rerank shape"
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
            endpoint: OfferEndpoint::configured(binding.locality),
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
    scope: SeatScope,
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
        alone.entry(rung.model.clone()).or_insert_with(|| {
            Arc::new(OfferLadder::pinned(rung.clone(), Arc::clone(&rests)).scoped(scope))
        });
    }
    Some(Seat {
        role,
        model: model.clone(),
        locality,
        ladder: Arc::new(OfferLadder::seat(model, rungs, rests).scoped(scope)),
        rungs: alone,
    })
}
