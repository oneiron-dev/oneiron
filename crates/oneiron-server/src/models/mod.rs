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

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{
    BudgetLine, HostAccount, LeaseUnit, PayerPerson, RunAdmission, RunAttribution, RunDeclaration,
    RunReceiptSink,
};
use oneiron::llm::{SingleRouteBackend, WorkerKind};
use oneiron::{BudgetGuard, LlmCatalogEntry, ModelId, ModelLocality};
use oneiron_llm_anthropic::{AnthropicMessagesBackend, AnthropicMessagesConfig};
use oneiron_llm_openai::{OpenAiCompatBackend, OpenAiCompatConfig};

use crate::config::models::{ModelRef, ModelsConfig, ProviderConfig, ProviderKind, role_key};

mod anthropic;
mod broker;
mod broker_context;
mod broker_media;
mod broker_responses;
mod cache_usage;
mod catalog;
mod cooldown;
mod decision_read;
mod declared;
#[cfg(feature = "mesh")]
mod discovered;
// FIX 14975: each trained drafter version evaluated, activated and rolled
// back, on evaluator incarnations of the vault's own row.
#[cfg(unix)]
mod drafter_evaluator;
mod drafter_serving;
mod drafter_training;
mod driven;
mod exl3_evidence;
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
// FIX 15702: a seat's model door, its key read at the custody door per call.
mod seat_model;
// FIX 15702 slice 3: each of its calls admitted and settled on the claim's run.
mod seat_model_admission;
mod served;
mod siwc_responses;
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
pub(crate) use http::{codec_token, encode_request_body, is_cloud_node, mark_cloud_node};
pub(crate) use ladder::{AnsweringRung, ModelCallBinding};
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
pub(crate) use seat_model::{SeatKeyDoor, SeatModelAnswer, SeatModelRefusal, send_seat_model};
pub(crate) use seat_model_admission::{SeatModelCall, SeatModelMeter};
pub(crate) use source_admission::{SourceAdmission, SourceOffer};
pub use status::{
    DeviceDeclarationStatus, DeviceExecutorStatus, DevicePressureStatus, DeviceRowStatus,
    DeviceStatus, DiscoveredStatus, ModelsStatus, PreparedTailStatus, ProviderStatus, RungStatus,
    SeatState, SeatStatus, SnapshotReceipt, SnapshotSkips, SnapshotStatus, TaggerRuntimeStatus,
    TaggerStatus,
};
pub use token_ratio::TokenRatios;
pub(crate) use worker_host::{
    install_snapshot_runtime, permit_worker_launch, session_allocations_for_vault,
};
// FIX 14976: each served vault's drafter bindings, served on this process's
// own managed EXL3 worker.
pub use drafter_serving::VaultLoadSet;
pub(crate) use drafter_serving::{drafter_retrain_target, install_drafter_serving};
// FIX 14974: a drafter training job's place on its target's device work line.
pub(crate) use drafter_training::DrafterTrainingSlot;
// FIX 14975: each trained version evaluated, activated and rolled back.
#[cfg(unix)]
pub(crate) use drafter_evaluator::start_drafter_evaluations;

/// Off Unix no worker answers the evaluator op (FIX 14975): nothing is
/// evaluated, and nothing activates.
#[cfg(not(unix))]
pub(crate) fn start_drafter_evaluations(_vault: &Arc<oneiron::Vault>) {}

// DESIGN-V2 R2: a committed chat reply reaches the session coordinator; R3:
// with what a snapshot of it is kept and restored under.
pub(crate) use worker_host::{
    AuthorityVerdict, CheckpointAuthority, NextTail, NextTurnSource, ReplyCommit, RestoreClaim,
    SnapshotScope, reply_committed, reply_committed_preparing, turn_admitted,
};

use catalog::{catalog_entry, engine_model_id, locality_rank, model_family};
use ladder::{LadderRung, SeatScope, Wire};
use offer::{native_local_offer, provider_offer};
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
    /// The seat's on-device view (I2-LOCAL): each rung a managed worker this
    /// server supervises serves over its native channel, as that on-device
    /// offer alone, in ladder order, under an on-device ceiling no owner's
    /// fallback passes. `None` when no rung has such an offer.
    on_device: Option<Arc<OfferLadder>>,
    /// Each rung of the on-device view on its own, keyed as `rungs` is.
    on_device_rungs: BTreeMap<ModelId, Arc<OfferLadder>>,
}

impl Seat {
    /// The rung that serves `model`, alone and with its prompt.
    fn rung(&self, model: &ModelId) -> Option<Arc<OfferLadder>> {
        self.rungs.get(model).cloned()
    }

    /// The rung that serves `model` for a call routed at `route`, alone and
    /// with its prompt: on device, only its on-device offer (I2-LOCAL).
    fn rung_at(&self, model: &ModelId, route: ModelLocality) -> Option<Arc<OfferLadder>> {
        if route == ModelLocality::OnDevice {
            self.on_device_rungs.get(model).cloned()
        } else {
            self.rung(model)
        }
    }

    /// This seat with its on-device view over `rungs`: the on-device offers
    /// of those of its rungs that have one, in ladder order (I2-LOCAL).
    fn with_on_device_view(
        mut self,
        rungs: Vec<LadderRung>,
        rests: &Arc<OfferCooldowns>,
        scope: SeatScope,
    ) -> Self {
        if rungs.is_empty() {
            return self;
        }
        let scope = SeatScope {
            locality_ceiling: Some(ModelLocality::OnDevice),
            ..scope
        };
        for rung in &rungs {
            self.on_device_rungs
                .entry(rung.model.clone())
                .or_insert_with(|| {
                    Arc::new(OfferLadder::pinned(rung.clone(), Arc::clone(rests)).scoped(scope))
                });
        }
        self.on_device = Some(Arc::new(
            OfferLadder::seat(self.model.clone(), rungs, Arc::clone(rests)).scoped(scope),
        ));
        self
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
    /// Config-bound managed workers whose local weight files the Coach can read.
    stock_weights: BTreeMap<String, worker_host::StockWeights>,
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
    posture: oneiron::HostingPrivacyPosture,
) -> anyhow::Result<Option<Arc<dyn SingleRouteBackend>>> {
    let catalog = referenced_models(config, name)
        .iter()
        .map(|model| catalog_entry(model, provider))
        .collect::<anyhow::Result<Vec<_>>>()?;
    // Only the EXL3 server reads the host's solo marker (INF 1); a provider
    // no EXL3 worker row binds (the llama fallback among them) is never
    // sent a field only EXL3 knows (FIX 6976).
    let solo = provider.kind == ProviderKind::LocalOpenaiCompat
        && config
            .workers
            .iter()
            .any(|row| row.kind == WorkerKind::Exl3 && row.binding.provider == name);
    if let Some(siwc) = &provider.siwc {
        oneiron::dispatch_byoa::check_seat_placement(
            oneiron::dispatch_byoa::OfficialSeatRoute::SignInWithChatGpt,
            posture,
            oneiron::dispatch_byoa::SeatPlacementApproval {
                openai_hosted_plan: siwc.openai_hosted_plan_approved,
                ..Default::default()
            },
            true,
        )?;
        return Ok(Some(Arc::new(siwc_responses::SiwcResponses::new(
            provider, catalog,
        )?)));
    }
    if provider.key_secret.is_some() && provider.kind.generates() {
        let site = site
            .ok_or_else(|| anyhow::anyhow!("no credential broker was made"))?
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        if provider.kind == ProviderKind::OpenaiCompat && provider.responses_socket.is_some() {
            let config = OpenAiCompatConfig::from_catalog(catalog.clone());
            let original_catalog = catalog
                .iter()
                .map(|entry| (entry.model.clone(), entry.clone()))
                .collect();
            return Ok(Some(Arc::new(broker_responses::BrokerResponses::new(
                broker::broker_backend(provider, catalog, output_cap(provider), solo, site, keys)?,
                config,
                original_catalog,
                responses.clone(),
                OutputCap {
                    field: "max_output_tokens",
                    ..output_cap(provider)
                },
                provider.response_format,
            ))));
        }
        return Ok(Some(Arc::new(broker::broker_backend(
            provider,
            catalog,
            output_cap(provider),
            solo,
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
            // The external chat workers bound at construction (FIX 9200): exact
            // row-and-provider matches only, so a later reconfiguration never
            // retargets this transport's captured workers.
            let external_workers = worker_host::external_workers(name, provider, &config.workers);
            let config = OpenAiCompatConfig::from_catalog(catalog).with_solo_admission(solo);
            let transport = openai::OpenAiHttp {
                http,
                cap: output_cap(provider),
                response_format: provider.response_format,
                identities: Arc::clone(identities),
                engine_models,
                external_workers,
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
            Arc::new(AnthropicMessagesBackend::new(
                AnthropicMessagesConfig::from_catalog(catalog),
                anthropic::AnthropicHttp {
                    http,
                    cap: output_cap(provider),
                    engine_models,
                },
            ))
        }
        // A gemini provider's chat rungs send the Gemini API's own wire
        // (FIX 1816); one with no chat rung gets none.
        ProviderKind::Gemini => {
            return gemini_chat::chat_backend(provider, catalog, output_cap(provider));
        }
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
    anyhow::ensure!(
        provider.siwc.is_none(),
        "SIWC credentials serve Responses, not reranking"
    );
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
        ProviderKind::Gemini => OutputCap {
            field: "maxOutputTokens",
            ceiling: provider.max_output_tokens,
            fallback: None,
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

/// A provider's on-device alternative (I2-LOCAL): one chat backend over the
/// native channels of the managed EXL3 workers bound to it and nothing else,
/// and the id of the worker that serves each wire model.
#[cfg_attr(not(unix), allow(dead_code))]
struct NativeLocal {
    backend: Arc<dyn SingleRouteBackend>,
    workers: BTreeMap<String, String>,
}

/// `provider`'s on-device alternative (I2-LOCAL), when managed EXL3 workers
/// this process launches serve some of its chat models over a native channel
/// whose peer is checked against the supervised child. Free and paid work
/// alike (FIX 14889): each offer over it keeps the provider offer's payer,
/// key custody and rates, so a paid provider's on-device call is charged as
/// its own-server call is ([`offer::native_local_offer`]). Its backend is the
/// provider's chat adapter over [`native_exl3::NativeLocalTransport`], for
/// those models alone, so the request mapping, output cap and response format
/// are the provider's own; the native channel carries the request body and
/// no key, since it is checked against the child instead. A key the provider
/// holds still makes its calls paid. `None` otherwise: the provider's own
/// backend serves every call, at its own locality, as it always has. A
/// provider holding a Responses socket keeps its socket and HTTP path, as
/// its own transport does.
#[cfg(unix)]
fn build_native_local(
    name: &str,
    provider: &ProviderConfig,
    config: &ModelsConfig,
) -> Option<NativeLocal> {
    let chat = matches!(
        provider.kind,
        ProviderKind::OpenaiCompat | ProviderKind::LocalOpenaiCompat
    );
    if !chat || provider.responses_socket.is_some() {
        return None;
    }
    let routes = worker_host::native_local_routes(name, provider, &config.workers);
    let catalog: Vec<LlmCatalogEntry> = referenced_models(config, name)
        .iter()
        .filter(|model| routes.contains_key(&model.model))
        .filter_map(|model| catalog_entry(model, provider).ok())
        .map(|entry| LlmCatalogEntry {
            locality: ModelLocality::OnDevice,
            ..entry
        })
        .collect();
    if catalog.is_empty() {
        return None;
    }
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
    let workers = routes
        .iter()
        .map(|(wire, route)| (wire.clone(), route.worker.spec().worker_id.clone()))
        .collect();
    // Every route is a managed EXL3 worker's, so the solo marker goes as it
    // does on the provider's own transport (INF 1).
    let solo = provider.kind == ProviderKind::LocalOpenaiCompat;
    let shaping = native_exl3::NativeShaping::new(
        output_cap(provider),
        provider.response_format,
        engine_models,
    );
    let transport = native_exl3::NativeLocalTransport::new(routes, shaping);
    let adapter = OpenAiCompatConfig::from_catalog(catalog).with_solo_admission(solo);
    Some(NativeLocal {
        backend: Arc::new(OpenAiCompatBackend::new(adapter, transport)),
        workers,
    })
}

/// No native channel exists off Unix, so no provider has an on-device
/// alternative.
#[cfg(not(unix))]
fn build_native_local(
    _name: &str,
    _provider: &ProviderConfig,
    _config: &ModelsConfig,
) -> Option<NativeLocal> {
    None
}

/// `model` on `provider` over `native` alone, as a rung at `position`: the
/// on-device alternative of the rung [`rung`] builds for it (I2-LOCAL), with
/// the same model id, wire model and prompt. `None` when no supervised native
/// worker serves its wire model.
fn native_rung(
    name: &str,
    provider: &ProviderConfig,
    native: &NativeLocal,
    model: &ModelRef,
    position: usize,
    prompt: Option<String>,
) -> Option<LadderRung> {
    if !native.workers.contains_key(&model.model) {
        return None;
    }
    let id = engine_model_id(model, provider).ok()?;
    let offer = match native_local_offer(provider, id.clone(), &model.model, native) {
        Ok(offer) => offer,
        Err(error) => {
            tracing::warn!(provider = %name, %error, "model has no on-device offer");
            return None;
        }
    };
    Some(LadderRung {
        provider: name.to_owned(),
        position,
        model: id,
        wire_model: model.model.clone(),
        prompt,
        offer,
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
        on_device: None,
        on_device_rungs: BTreeMap::new(),
    })
}
