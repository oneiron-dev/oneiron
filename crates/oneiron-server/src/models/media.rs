//! The `ai.*` media seats (`[models.media]`): one ladder per operation, each
//! rung an OpenAI-compatible provider's media wire. A media call goes down
//! its seat's ladder on the same walk as a text call: each rung it reaches
//! is admitted on its own permit, sent through the run's media gate and
//! settled in token units on its own (ARCH-0053 `#run-admission`); an offer
//! refused for a limit rests and the call goes to the next. A video call is
//! a job: its permit is held while the provider renders and settled when
//! the job ends.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaCaps, MediaJobState, MediaRequest, MediaResponse, MediaVoice,
    Modality,
};
use oneiron::llm::run_admission::{
    HostAccount, MediaGate, OfferBinding, PayerPerson, RunAdmission, RunOverageSource, RunPermit,
    RunReceiptSink,
};
use oneiron::llm::{SingleRouteBackend, SingleSend, VoiceBackendBinding};
use oneiron::voice_cascade::media::BankVoiceBinding;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, FatalLlmError, LlmBackend, LlmCatalogEntry,
    LlmError, LlmGenerateFuture, LlmRequest, LlmResult, LlmStreamResult, ModelId, ModelLocality,
    ModelTierRef, Vault,
};
use oneiron_llm_openai::{
    OpenAiMediaBackend, OpenAiMediaBody, OpenAiMediaHttpRequest, OpenAiMediaHttpResponse,
    OpenAiMediaMethod, OpenAiMediaTransport, OpenAiMediaTransportFuture,
};
use serde::Serialize;

use crate::config::models::{ModelRef, ModelsConfig, ProviderConfig, ProviderKind};

use super::broker::{BrokerSite, KeyDoor};
use super::broker_media::broker_media_backend;
use super::catalog::{catalog_entry, engine_model_id};
use super::cooldown::{FallbackRung, OfferCooldowns, ProbePermit};
use super::gemini_media::gemini_backend;
use super::host_budgets::ModelHostBudgets;
use super::hosted_speech::{CARTESIA_VERSION, HostedCloner, HostedSpeech, HostedWire};
use super::http::{KeyStyle, MediaSend, ProviderHttp};
use super::ladder::{LadderRung, OfferLadder, PendingReceipt, SeatScope, Wire};
use super::offer::{ServedOffer, clone_connector, media_offer};
use super::raw::funded_run;
use super::rerank::transport;
use super::soniox::{self, SonioxRung};
use super::status::{RungHealth, RungStatus, SeatState, SeatStatus};
use super::voxcpm2_speech::VoxCpm2Speech;
use super::walk::provider_down;
use super::{LoggedReceipts, ladder_locality, undeclared_run};

// FIX 3208: the video jobs an agent asked for under the owner's ai.video Grant.
mod asked_jobs;
mod bindings;
mod booked;
mod calls;
mod construction;
mod fit;
// FIX 9511, 9513: a job's end and its delete, in one order.
mod job_lifecycle;
mod jobs;
mod options;
// FIX 465, 2248, 2962: a submit kept before it is sent, and keyed replays.
mod replay;
// FIX 780, 6083: a program's media jobs on its run's line.
mod run_line;
// FIX 1816: a video job charged by its length.
mod video_length;
// FIX 9517: every reference upload under the bank's current reference.
mod voice_reference;

use jobs::{JobRow, JobStore, KeptJob, erased_poll, submit_stamps};
use run_line::{JobLine, ProgramLine};
pub(in crate::models) use video_length::requested_video_ms;
pub(in crate::models) use voice_reference::{AdmittedReference, VoiceReferenceUploadGuard};

/// The run every media call is admitted under, one run per call.
const MEDIA_RUN: &str = "ai-media";

/// A media rung's own side: the media wire it sends through, and the row
/// that says what it serves.
#[derive(Clone)]
pub(super) struct MediaRung {
    pub(super) backend: Arc<dyn MediaBackend>,
    pub(super) row: LlmCatalogEntry,
    pub(super) caps: MediaCaps,
}

/// What a media call down a ladder came to: an answer, or a job the
/// provider runs on, with the permit that pays for it.
pub(super) enum MediaAnswer {
    Done(MediaResponse),
    Job(HeldJob),
}

/// A submitted job, its permit held open until the job ends.
pub(super) struct HeldJob {
    pub(super) gate: MediaGate,
    pub(super) permit: Option<RunPermit>,
    /// Its offer's health permit, held while the job runs: a recovering
    /// offer's one probation request (OF-305). The job's end reports to it,
    /// and dropping the job frees it.
    pub(super) probe: Option<ProbePermit>,
    /// The served receipt its answer carries, when its ladder stamps one.
    pub(super) receipt: Option<PendingReceipt>,
    pub(super) provider_job: String,
    pub(super) model: ModelId,
    pub(super) operation: AiOperation,
    pub(super) caps: MediaCaps,
    /// Its end was paid already, by a permit a restart ended before the
    /// vault kept that end (FIX 2963): its end settles with no charge.
    pub(super) paid: bool,
    /// The clip length its call asked for, charged when its clips state
    /// none (FIX 1816).
    pub(super) requested_video_ms: Option<u64>,
}

impl HeldJob {
    /// Where the job stands. A job that ended settles its permit: an answer
    /// pays its usage, a failure its reservation. Its end also counts toward
    /// its offer's health: an answer toward recovery, and a provider that
    /// was down as one more failure in a row. An answer carries the ladder's
    /// served receipt.
    async fn poll(&mut self) -> LlmResult<MediaJobState> {
        let Some(permit) = &self.permit else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        let mut state = self
            .gate
            .poll(&self.model, &self.provider_job, permit.lease())
            .await?;
        match &mut state {
            MediaJobState::Done { response } => {
                self.charge_requested_length(response);
                let units = response.usage.token_units(self.operation, &self.caps);
                let source = if response.usage.is_provider_counted() {
                    RunOverageSource::ProviderReported
                } else {
                    RunOverageSource::Counted
                };
                if self.paid {
                    self.hand_off();
                } else if let Some(permit) = self.permit.take()
                    && let Err(denied) =
                        permit.settle_media(units, response.usage.inference_calls(), source)
                {
                    tracing::error!(%denied, "a media job's settlement was refused");
                }
                if let Some(probe) = self.probe.take() {
                    probe.answered();
                }
                if let Some(receipt) = &self.receipt {
                    let raw = std::mem::take(&mut response.usage.raw_provider);
                    response.usage.raw_provider = receipt.stamp(raw);
                }
            }
            MediaJobState::Failed { error } => {
                self.settle_failed();
                if let Some(probe) = self.probe.take()
                    && provider_down(error)
                {
                    probe.down();
                }
            }
            MediaJobState::Queued | MediaJobState::Running { .. } => {}
        }
        Ok(state)
    }

    /// Stops the job at its provider. A stop the provider confirmed
    /// settles its permit: the job went out, so it pays its reservation. A
    /// stop that failed, or whose outcome is unknown, keeps the permit and
    /// the probation slot (FIX 9513): the job may still run and bill, and
    /// stays this permit's to poll or stop again.
    async fn cancel(&mut self) -> LlmResult<()> {
        let Some(permit) = &self.permit else {
            return Ok(());
        };
        self.gate
            .cancel(&self.model, &self.provider_job, permit.lease())
            .await?;
        self.settle_failed();
        Ok(())
    }

    /// Settles the permit of a job that failed or was stopped: it pays its
    /// reservation, unless its end was paid already (FIX 2963).
    fn settle_failed(&mut self) {
        if self.paid {
            return self.hand_off();
        }
        if let Some(permit) = self.permit.take()
            && let Err(denied) = permit.settle(oneiron::llm::run_admission::CallOutcome::Failed)
        {
            tracing::error!(%denied, "a media job's settlement was refused");
        }
    }

    /// Ends the permit with no charge: the job's end was paid already.
    fn hand_off(&mut self) {
        if let Some(permit) = self.permit.take()
            && let Err(denied) = permit.hand_off_media()
        {
            tracing::error!(%denied, "a paid media job's permit was not ended");
        }
    }
}

/// A media rung's chat side: it answers no chat call. A media rung walks
/// the same ladder as a chat rung, and only its media gate sends.
struct NoChat;

/// One provider's media HTTP leg: one request per call, as every exchange
/// over [`ProviderHttp`].
struct MediaHttp {
    http: ProviderHttp,
}

/// One operation's seat: its ladder behind one seat id, each rung alone by
/// its own id, and the rows its rungs serve.
struct MediaSeat {
    model: ModelId,
    locality: ModelLocality,
    ladder: Arc<OfferLadder>,
    rungs: BTreeMap<ModelId, Arc<OfferLadder>>,
    rows: Vec<MediaRow>,
    /// The voice tiers its rungs serve: each tier's one rung, by its id.
    tiers: BTreeMap<ModelTierRef, ModelId>,
}

/// A banked voice's live bindings for one speech call (FIX 1746): each rung
/// the call may reach whose target held a current clone or reference of the
/// voice when the call was admitted, in ladder order. Host-only. The call
/// goes out on a rung in that rung's own binding, never in another's, and a
/// rung absent here never takes it, so an outage moves the call only to a
/// target that already holds the voice. Nothing here clones a voice or asks
/// for consent.
pub(crate) struct RungVoices {
    vault: Arc<Vault>,
    bound: Vec<(ModelId, BankVoiceBinding)>,
    /// Where in `bound` the binding the call last went out in sits.
    sent: AtomicUsize,
}

/// One row `GET /v1/ai/options` lists: a model that serves an operation,
/// where it runs and what it takes.
#[derive(Clone, Debug, Serialize)]
pub struct MediaRow {
    pub operation: AiOperation,
    /// The id a call names to take this row alone; the seat's id takes its
    /// whole ladder.
    pub model: String,
    pub seat_model: String,
    pub provider: String,
    pub wire_model: String,
    pub locality: ModelLocality,
    pub inputs: BTreeSet<Modality>,
    pub outputs: BTreeSet<Modality>,
    pub native_rates: Vec<oneiron::llm::media::NativeRate>,
    pub max_references: usize,
    /// The machine id of the owner's node that offers the row, when the mesh
    /// discovered it (FIX 3229): a raw call names it by `model`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

/// A media call's job, as its caller polls it.
#[derive(Clone, Debug, Serialize)]
pub struct MediaTicket {
    pub job: String,
    pub model: String,
    pub operation: AiOperation,
}

/// A job a poll or a cancel reaches: held here running, held here ended
/// with an end the vault has not kept yet, or ended and kept.
#[derive(Clone)]
enum Held {
    /// Its submit is out and its provider has not answered (FIX 2248): the
    /// model it named, for a repeat's ticket. A poll reads it queued.
    Submitting(ModelId),
    /// A submit a restart cut short before its provider answered, whose
    /// wire dedupes by its key: its next poll sends it again under that key
    /// to learn the job it started (FIX 2248).
    Unsent(Box<JobRow>),
    Running(Arc<tokio::sync::Mutex<HeldJob>>),
    /// Its end, answered from here while each poll writes it again: its
    /// permit is spent, so it is never polled or paid for again.
    Unkept(MediaJobState),
    Ended(MediaJobState),
}

/// Every media seat the config fills, their meter, and the jobs they run.
pub struct MediaRuntime {
    seats: BTreeMap<AiOperation, MediaSeat>,
    meter: Option<BudgetGuard>,
    receipts: Arc<dyn RunReceiptSink>,
    host: Option<Arc<HostAccount>>,
    /// The jobs held here: running, or ended and not kept yet.
    jobs: Mutex<BTreeMap<String, Held>>,
    /// Where the jobs are kept, so a restart loses none (FIX-LIST 465).
    store: Option<JobStore>,
    /// Each job seat's rungs, by engine id: the rung a kept job is taken up
    /// on again after a restart.
    job_rungs: BTreeMap<ModelId, LadderRung>,
    /// The offers' health, which a job taken up again reports its end to.
    rests: Option<Arc<OfferCooldowns>>,
    /// The render targets (provider names) that render from a banked
    /// identity's reference clip on each call and keep no clone.
    reference_targets: BTreeSet<String>,
    /// The hosted render targets (provider names) that clone a banked
    /// identity, by name.
    cloners: BTreeMap<String, Arc<HostedCloner>>,
    /// The transcribe rungs that hear live (soniox), by engine id.
    live_asr: BTreeMap<String, Arc<SonioxRung>>,
    /// The guard each reference-rendering backend asks before an upload,
    /// bound to the runtime's vault (FIX 9517).
    voice_refs: VoiceReferenceUploadGuard,
    /// The line a program's run spends its media calls on (FIX 780, 6083),
    /// which its jobs are taken up on again after a restart.
    program_line: ProgramLine,
}

impl MediaRuntime {
    /// The ladder that serves `request`: its seat's, or one rung alone.
    fn ladder(&self, request: &MediaRequest) -> LlmResult<Arc<OfferLadder>> {
        let seat = self
            .seats
            .get(&request.operation)
            .ok_or(FatalLlmError::InvalidRequest)?;
        if request.model == seat.model {
            return Ok(Arc::clone(&seat.ladder));
        }
        seat.rungs
            .get(&request.model)
            .cloned()
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }

    /// The call down its ladder; a job's submit goes out under `submit_key`
    /// (FIX 2248).
    fn walk<'a>(
        &'a self,
        request: MediaRequest,
        voices: Option<&'a RungVoices>,
        payer: Option<PayerPerson>,
        sources: Option<Vec<oneiron::EntityId>>,
        submit_key: Option<String>,
    ) -> LlmResult<impl std::future::Future<Output = LlmResult<MediaAnswer>> + Send + 'a> {
        let ladder = self.ladder(&request)?;
        let run = self.media_run(payer, sources)?.submit_keyed(submit_key);
        // A media call's one deadline is its caller's (FIX 8134): no host
        // wait ends it before an offer it waits for is back.
        let deadline = super::CallDeadline::Open;
        Ok(async move { ladder.media_by(&run, request, None, voices, deadline).await })
    }

    /// A run of its own on the media meter, for one call or stream, billed
    /// to `payer` when a room pays for it (FIX 805): each permit binds the
    /// PERSON and account its caller resolved before the call. `None` is
    /// the vault owner's run. Its permits carry `sources`, the rows its
    /// caller read the request from (FIX 11311); `None` when they are not
    /// known whole.
    fn media_run(
        &self,
        payer: Option<PayerPerson>,
        sources: Option<Vec<oneiron::EntityId>>,
    ) -> LlmResult<RunAdmission> {
        let meter = self.meter.clone().ok_or(FatalLlmError::InvalidRequest)?;
        Ok(funded_run(
            MEDIA_RUN,
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
            payer,
        )
        .sourced(sources))
    }

    async fn run_in(
        &self,
        request: MediaRequest,
        voices: Option<&RungVoices>,
        payer: Option<PayerPerson>,
        sources: Option<Vec<oneiron::EntityId>>,
    ) -> LlmResult<MediaResponse> {
        let run = self.media_run(payer, sources)?;
        self.run_admitted(&run, request, voices, None).await
    }

    /// Job `id`, held here or kept in the vault. A kept job that has not
    /// ended is taken up again here, once: a poll racing this one finds it
    /// held. Its row is read while no delete drops it (FIX 9511), so a job
    /// a delete dropped is never taken up again.
    fn held(&self, id: &str) -> LlmResult<Held> {
        let mut jobs = self.lock_jobs();
        if let Some(held) = jobs.get(id) {
            return Ok(held.clone());
        }
        // A replayed call's kept answer and a held write are no jobs.
        if replay::is_replay(id) || jobs::is_held_write(id) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        // A held write of the job goes in place first (FIX 2963).
        let kept = self
            .store
            .as_ref()
            .and_then(|store| {
                store.flush(id);
                store.get(id)
            })
            .ok_or(FatalLlmError::InvalidRequest)?;
        // An erased job is never taken up, resumed or resubmitted (KS-2B2).
        let Some(row) = kept.live() else {
            return Ok(Held::Ended(erased_poll(id)));
        };
        if let Some(state) = row.ended {
            return Ok(Held::Ended(state));
        }
        // Its submit was cut short before its provider answered (FIX 2248).
        if row.provider_job.is_none() {
            return Ok(self.unsent(id, row));
        }
        let job = Held::Running(Arc::new(tokio::sync::Mutex::new(self.take_up(id, &row)?)));
        jobs.insert(id.to_owned(), job.clone());
        Ok(job)
    }

    /// Takes up every kept job a restart left running, so each one's
    /// reservation is back on the meter before a new call can spend it. A
    /// job that cannot be taken up stays kept, and its next poll tries again.
    fn take_up_kept(&self) {
        let Some(store) = &self.store else {
            return;
        };
        // Each held write goes in place first (FIX 2963), so no job whose
        // end was kept, or paid, is taken up as a running one.
        for ticket in store.held_tickets() {
            store.flush(&ticket);
        }
        for ticket in store.tickets() {
            if jobs::is_held_write(&ticket) {
                continue;
            }
            // A replayed call's kept answer is no job: it only expires.
            if replay::is_replay(&ticket) {
                replay::reclaim_replay(store, &ticket);
                continue;
            }
            if let Err(error) = self.held(&ticket) {
                tracing::warn!(%error, %ticket, "a kept media job was not taken up");
            }
        }
    }

    /// The end job `id` holds here, or its row keeps; its erased end once
    /// an erase took it, whose end held here goes (KS-2B2).
    fn ended(&self, id: &str) -> LlmResult<MediaJobState> {
        let kept = self.store.as_ref().and_then(|store| store.get(id));
        if kept.as_ref().is_some_and(KeptJob::erased) {
            self.lock_jobs().remove(id);
            return Ok(erased_poll(id));
        }
        if let Some(Held::Unkept(state)) = self.lock_jobs().get(id) {
            return Ok(state.clone());
        }
        kept.and_then(KeptJob::live)
            .and_then(|row| row.ended)
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }

    /// A job a restart left running, taken up again on the rung that took
    /// it: a permit admitted afresh on this runtime's meter for the call
    /// its caller sent, and started for the job's polls without a new
    /// submit. It carries the served receipt it went out with, and its end
    /// counts toward its offer's health as a sent request's does: a
    /// recovering offer's one probation request when that slot is free. It
    /// bills the payer its submit bound, whoever polls it, on the line its
    /// submit spent on: a program's run's, else the media meter (FIX 780,
    /// 6083). A job whose rung left the config cannot be taken up.
    fn take_up(&self, ticket: &str, row: &JobRow) -> LlmResult<HeldJob> {
        let rung = self
            .job_rungs
            .get(&row.model)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let media = rung.media.as_ref().ok_or(FatalLlmError::InvalidRequest)?;
        let provider_job = row
            .provider_job
            .clone()
            .ok_or(FatalLlmError::InvalidRequest)?;
        let mut bound = row.request.clone();
        bound.model = rung.model.clone();
        bound.envelope.locality = rung.offer.binding.locality;
        let run = self.job_run(ticket, row)?;
        let selector = Some(row.request.model.as_str());
        let permit = run.admit_media(selector, &bound, &rung.offer.binding)?;
        let gate = run.media_gate(Arc::clone(&media.backend), &rung.offer.binding);
        gate.resume(&bound, &provider_job, permit.lease())?;
        // A resting offer, or one whose probation request is out, takes no
        // report from it.
        let probe = self
            .rests
            .as_ref()
            .and_then(|rests| rests.try_probe(&rung.offer.binding, &rung.wire_model).ok());
        Ok(HeldJob {
            gate,
            permit: Some(permit),
            probe,
            receipt: row.receipt.clone(),
            provider_job,
            model: rung.model.clone(),
            operation: row.operation,
            caps: media.caps.clone(),
            paid: row.paid,
            requested_video_ms: requested_video_ms(&row.request),
        })
    }

    fn lock_jobs(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Held>> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What a text call of `model` on `ladder` takes and gives: text, and an
/// image or audio input when every rung of the ladder takes one.
fn text_caps(ladder: &OfferLadder, model: &ModelId) -> MediaCaps {
    let mut caps = MediaCaps::for_operation(AiOperation::Text);
    for (capability, modality) in [
        (oneiron::LlmCapability::ImageInput, Modality::Image),
        (oneiron::LlmCapability::AudioInput, Modality::Audio),
    ] {
        if ladder.supports(model, &capability) {
            caps.inputs.insert(modality);
        }
    }
    caps
}

/// One media client per provider some media seat names, each serving the
/// models those seats name on it. A `key_secret` provider's client sends
/// through the credential broker.
fn media_backends(
    config: &ModelsConfig,
    site: Option<&Result<BrokerSite, String>>,
    keys: Option<&Arc<dyn KeyDoor>>,
    voice_refs: &VoiceReferenceUploadGuard,
) -> BTreeMap<String, Arc<dyn MediaBackend>> {
    let mut models: BTreeMap<&str, BTreeMap<ModelId, String>> = BTreeMap::new();
    for model in config.media.seats.values().flat_map(|seat| &seat.rungs) {
        let provider = &config.providers[&model.provider];
        if let Ok(id) = engine_model_id(model, provider) {
            models
                .entry(model.provider.as_str())
                .or_default()
                .insert(id, model.model.clone());
        }
    }
    let mut backends = BTreeMap::new();
    for (name, wire_models) in models {
        let provider = &config.providers[name];
        let built: anyhow::Result<Arc<dyn MediaBackend>> = match provider.kind {
            _ if provider.key_secret.is_some() => {
                broker_media_backend(name, provider, wire_models, site, keys)
            }
            ProviderKind::Cartesia => {
                ProviderHttp::new(&cartesia(provider), KeyStyle::ApiKeyHeader).map(|http| {
                    Arc::new(HostedSpeech {
                        http,
                        wire: HostedWire::Cartesia,
                        models: wire_models,
                    }) as Arc<dyn MediaBackend>
                })
            }
            ProviderKind::Elevenlabs => ProviderHttp::new(provider, KeyStyle::Named("xi-api-key"))
                .map(|http| {
                    Arc::new(HostedSpeech {
                        http,
                        wire: HostedWire::ElevenLabs,
                        models: wire_models,
                    }) as Arc<dyn MediaBackend>
                }),
            ProviderKind::Voxcpm2 => {
                // The worker's paths sit at its root, and it takes no call
                // without its bearer credential. It is on loopback, so no
                // environment proxy may carry the refs elsewhere.
                let mut provider = provider.clone();
                provider.base_url = provider.base_url.trim_end_matches('/').to_owned();
                if provider.key_env.is_none() {
                    Err(anyhow::anyhow!(
                        "a voxcpm2 worker takes a bearer credential; set key_env"
                    ))
                } else {
                    ProviderHttp::direct(&provider, KeyStyle::Bearer).map(|http| {
                        Arc::new(VoxCpm2Speech {
                            http,
                            models: wire_models,
                            target: name.to_owned(),
                            locality: provider.locality,
                            voice_refs: voice_refs.clone(),
                        }) as Arc<dyn MediaBackend>
                    })
                }
            }
            ProviderKind::Gemini => gemini_backend(provider, wire_models),
            // It hears live only, through `open_voice_asr`; never the
            // OpenAI-compatible wire below.
            ProviderKind::Soniox => soniox::live_backend(provider),
            _ => ProviderHttp::new(provider, KeyStyle::Bearer).map(|http| {
                Arc::new(OpenAiMediaBackend::new(
                    MediaHttp { http },
                    wire_models,
                    provider.base_url.clone(),
                )) as Arc<dyn MediaBackend>
            }),
        };
        match built {
            Ok(backend) => {
                backends.insert(name.to_owned(), backend);
            }
            Err(error) => {
                tracing::warn!(provider = %name, %error, "media provider unavailable");
            }
        }
    }
    backends
}

/// `provider` as Cartesia takes it: every call names its API version.
fn cartesia(provider: &ProviderConfig) -> ProviderConfig {
    let mut provider = provider.clone();
    if !provider
        .headers
        .keys()
        .any(|header| header.eq_ignore_ascii_case("cartesia-version"))
    {
        provider
            .headers
            .insert("Cartesia-Version".into(), CARTESIA_VERSION.into());
    }
    provider
}

/// The clone wire of each configured hosted speech provider, by name, its
/// replies holding their bytes on `budgets` (FIX 9321).
fn voice_cloners(
    config: &ModelsConfig,
    budgets: &ModelHostBudgets,
) -> BTreeMap<String, Arc<HostedCloner>> {
    let mut cloners = BTreeMap::new();
    for (name, provider) in &config.providers {
        let built = match provider.kind {
            ProviderKind::Cartesia => {
                ProviderHttp::new(&cartesia(provider), KeyStyle::ApiKeyHeader)
                    .map(|http| (http, HostedWire::Cartesia))
            }
            ProviderKind::Elevenlabs => ProviderHttp::new(provider, KeyStyle::Named("xi-api-key"))
                .map(|http| (http, HostedWire::ElevenLabs)),
            _ => continue,
        };
        // Each clone call is admitted as the provider's clone connector.
        let connector = match clone_connector(provider, name) {
            Ok(connector) => connector,
            Err(error) => {
                tracing::warn!(provider = %name, %error, "voice clone wire unavailable");
                continue;
            }
        };
        match built {
            Ok((http, wire)) => {
                cloners.insert(
                    name.clone(),
                    Arc::new(HostedCloner {
                        http,
                        wire,
                        locality: provider.locality,
                        connector,
                        budgets: budgets.clone(),
                    }),
                );
            }
            Err(error) => {
                tracing::warn!(provider = %name, %error, "voice clone wire unavailable");
            }
        }
    }
    cloners
}

/// `model` on `provider` as a media rung at `position` for `operation`, its
/// calls' replies holding their bytes on `budgets` (FIX 9321).
fn media_rung(
    provider: &ProviderConfig,
    backend: &Arc<dyn MediaBackend>,
    model: &ModelRef,
    position: usize,
    operation: AiOperation,
    caps: &MediaCaps,
    budgets: &ModelHostBudgets,
) -> Option<LadderRung> {
    let row = catalog_entry(model, provider).ok()?.with_media(caps);
    let binding = match media_offer(provider, row.model.clone(), operation) {
        Ok(binding) => binding,
        Err(error) => {
            tracing::warn!(provider = %model.provider, %error, "media model has no offer route");
            return None;
        }
    };
    Some(LadderRung {
        provider: model.provider.clone(),
        position,
        model: row.model.clone(),
        wire_model: model.model.clone(),
        prompt: None,
        offer: ServedOffer {
            endpoint: super::OfferEndpoint::configured(binding.locality),
            binding,
            backend: Arc::new(NoChat),
        },
        media: Some(MediaRung {
            // Its calls hold their replies' bytes until each answer leaves
            // the adapter (FIX 8615), on the vault's line (FIX 9321).
            backend: Arc::new(booked::BookedReplies(Arc::clone(backend), budgets.clone())),
            row,
            caps: caps.clone(),
        }),
    })
}

/// The seat id names the operation and a digest of its rungs, so a changed
/// ladder is a new identity.
fn media_seat_model(operation: AiOperation, rungs: &[LadderRung]) -> Option<ModelId> {
    let mut digest = blake3::Hasher::new();
    for rung in rungs {
        digest.update(rung.model.as_str().as_bytes());
        digest.update(&[0]);
        digest.update(rung.wire_model.as_bytes());
        digest.update(&[0xff]);
    }
    let revision = &digest.finalize().to_hex()[..12];
    ModelId::new(format!("seat/media-{}@{revision}", operation.as_str())).ok()
}

impl MediaRuntime {
    /// Opens one bounded `ai.transcribe` stream (live partials) on a run of
    /// its own on the media meter: one permit for the whole stream,
    /// reserving `bound_ms` of audio, started at its rung's media gate
    /// before any audio leaves. As a [`HeldJob`] holds a job's permit to its
    /// end, the lease holds the stream's: it meters the audio its wire sends
    /// and settles when the stream ends or is cancelled. The stream bills
    /// `payer` as [`Self::run`]'s call does.
    pub fn open_stream(
        &self,
        request: MediaRequest,
        bound_ms: u64,
        payer: Option<PayerPerson>,
        sources: Option<Vec<oneiron::EntityId>>,
    ) -> LlmResult<oneiron::llm::run_admission::MediaStreamLease> {
        if request.operation != AiOperation::Transcribe || bound_ms == 0 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let ladder = self.ladder(&request)?;
        let run = self.media_run(payer, sources)?;
        ladder.open_media_stream(&run, request, bound_ms)
    }
}

/// The seconds a direct media call no offer answered waits before it calls
/// again when none of its offers rests for a known time (FIX 3194).
const PROVIDER_UNAVAILABLE_RETRY_SECS: u64 = 5;

/// When a direct media call no offer answered may call again (FIX 3194).
/// Nothing keeps the call: this is its caller's hint, from the rests of the
/// offers that could have served it.
pub(crate) struct RetryHint {
    /// Each offer that could serve the call, with the model it sends.
    pub(super) offers: Vec<(OfferBinding, String)>,
    pub(super) rests: Option<Arc<OfferCooldowns>>,
}
