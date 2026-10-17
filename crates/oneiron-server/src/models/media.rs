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
use oneiron::llm::run_admission::{HostAccount, MediaGate, RunPermit, RunReceiptSink};
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
use super::hosted_speech::{CARTESIA_VERSION, HostedCloner, HostedSpeech, HostedWire};
use super::http::{KeyStyle, MediaSend, ProviderHttp};
use super::ladder::{LadderRung, OfferLadder, PendingReceipt, SeatScope, Wire};
use super::offer::{ServedOffer, media_offer};
use super::rerank::transport;
use super::soniox::{self, SonioxRung};
use super::status::{RungHealth, RungStatus, SeatState, SeatStatus};
use super::voxcpm2_speech::VoxCpm2Speech;
use super::walk::provider_down;
use super::{LoggedReceipts, ladder_locality, undeclared_run};

mod jobs;

use jobs::{JobRow, JobStore};

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
                let units = response.usage.token_units(self.operation, &self.caps);
                if let Some(permit) = self.permit.take()
                    && let Err(denied) = permit.settle_media(units)
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

    /// Stops the job at its provider. It went out, so it pays its
    /// reservation.
    async fn cancel(&mut self) -> LlmResult<()> {
        let Some(permit) = &self.permit else {
            return Ok(());
        };
        let stopped = self
            .gate
            .cancel(&self.model, &self.provider_job, permit.lease())
            .await;
        self.settle_failed();
        stopped
    }

    fn settle_failed(&mut self) {
        if let Some(permit) = self.permit.take()
            && let Err(denied) = permit.settle(oneiron::llm::run_admission::CallOutcome::Failed)
        {
            tracing::error!(%denied, "a media job's settlement was refused");
        }
    }
}

/// A media rung's chat side: it answers no chat call. A media rung walks
/// the same ladder as a chat rung, and only its media gate sends.
struct NoChat;

impl SingleSend for NoChat {}

impl LlmBackend for NoChat {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async { Err(LlmError::from(FatalLlmError::InvalidRequest)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

impl SingleRouteBackend for NoChat {
    fn preflight(&self, _request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// One provider's media HTTP leg: one request per call, as every exchange
/// over [`ProviderHttp`].
struct MediaHttp {
    http: ProviderHttp,
}

impl OpenAiMediaTransport for MediaHttp {
    fn execute<'a>(
        &'a self,
        request: OpenAiMediaHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiMediaTransportFuture<'a> {
        Box::pin(async move {
            let send = match (request.method, request.body) {
                (OpenAiMediaMethod::Get, OpenAiMediaBody::Empty) => MediaSend::Get,
                (OpenAiMediaMethod::Delete, OpenAiMediaBody::Empty) => MediaSend::Delete,
                (OpenAiMediaMethod::Post, OpenAiMediaBody::Json(body)) => MediaSend::Json(body),
                (OpenAiMediaMethod::Post, OpenAiMediaBody::Multipart { fields, files }) => {
                    let mut form = reqwest::multipart::Form::new();
                    for (name, value) in fields {
                        form = form.text(name, value);
                    }
                    for file in files {
                        let part = reqwest::multipart::Part::bytes(file.bytes)
                            .file_name(file.filename)
                            .mime_str(&file.media_type)
                            .map_err(|_| FatalLlmError::InvalidRequest)?;
                        form = form.part(file.name, part);
                    }
                    MediaSend::Multipart(form)
                }
                _ => return Err(FatalLlmError::InvalidRequest.into()),
            };
            let reply = self
                .http
                .send_media(&request.path, send)
                .await
                .map_err(transport)?;
            Ok::<_, LlmError>(OpenAiMediaHttpResponse {
                status: reply.status,
                headers: reply.headers,
                body: reply.body,
            })
        })
    }
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

impl RungVoices {
    /// The bindings `bound` takes, or `None` when no rung holds the voice.
    pub(crate) fn new(vault: Arc<Vault>, bound: Vec<(ModelId, BankVoiceBinding)>) -> Option<Self> {
        (!bound.is_empty()).then(|| Self {
            vault,
            bound,
            sent: AtomicUsize::new(usize::MAX),
        })
    }

    /// The one rung that holds the voice, when only one does: the call is
    /// that rung's alone.
    pub(crate) fn only_rung(&self) -> Option<&ModelId> {
        match self.bound.as_slice() {
            [(rung, _)] => Some(rung),
            _ => None,
        }
    }

    /// The voice as the first rung that holds it renders it.
    pub(crate) fn first_voice(&self) -> Option<MediaVoice> {
        self.bound.first().map(|(_, binding)| binding.voice())
    }

    /// Whether `rung` held the voice when the call was admitted.
    pub(super) fn holds(&self, rung: &ModelId) -> bool {
        self.bound.iter().any(|(model, _)| model == rung)
    }

    /// The voice the call goes out in on `rung`: that rung's own binding,
    /// while it is still current. `None` when the rung holds none, or the
    /// voice was withdrawn or re-recorded since.
    pub(super) fn send_on(&self, rung: &ModelId) -> Option<MediaVoice> {
        let (at, (_, binding)) = self
            .bound
            .iter()
            .enumerate()
            .find(|(_, (model, _))| model == rung)?;
        if !binding.is_current(&self.vault) {
            return None;
        }
        self.sent.store(at, Ordering::Relaxed);
        Some(binding.voice())
    }

    /// Whether the binding the call last went out in is still current: an
    /// answer rendered in a voice withdrawn or re-recorded meanwhile is not
    /// handed back.
    pub(crate) fn answered_current(&self) -> bool {
        self.bound
            .get(self.sent.load(Ordering::Relaxed))
            .is_some_and(|(_, binding)| binding.is_current(&self.vault))
    }

    /// Whether no binding is current any more: the voice was withdrawn or
    /// re-recorded everywhere while the call waited.
    pub(crate) fn withdrawn(&self) -> bool {
        self.bound
            .iter()
            .all(|(_, binding)| !binding.is_current(&self.vault))
    }
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
}

/// A runtime that keeps its jobs hands each running job's permit off as it
/// stops, charging nothing: the job runs on at its provider, and the runtime
/// that takes it up from its kept row pays its end, once. A job in a poll
/// that holds it is left to its own permit.
impl Drop for MediaRuntime {
    fn drop(&mut self) {
        if self.store.is_none() {
            return;
        }
        for job in self.lock_jobs().values() {
            let Held::Running(job) = job else {
                continue;
            };
            let Ok(mut job) = job.try_lock() else {
                continue;
            };
            if let Some(permit) = job.permit.take()
                && let Err(denied) = permit.hand_off_media()
            {
                tracing::error!(%denied, "a kept media job's permit was not handed off");
            }
        }
    }
}

impl MediaRuntime {
    pub(super) fn empty() -> Self {
        Self {
            seats: BTreeMap::new(),
            meter: None,
            receipts: Arc::new(LoggedReceipts),
            host: None,
            jobs: Mutex::default(),
            store: None,
            job_rungs: BTreeMap::new(),
            rests: None,
            reference_targets: BTreeSet::new(),
            cloners: BTreeMap::new(),
            live_asr: BTreeMap::new(),
        }
    }

    /// The live socket rung `model` (a rung's engine id) opens, when it
    /// hears live.
    pub(super) fn live_rung(&self, model: &str) -> Option<Arc<SonioxRung>> {
        self.live_asr.get(model).cloned()
    }

    /// The clone wire of hosted render target `target`, when it is one.
    #[must_use]
    pub fn voice_cloner(&self, target: &str) -> Option<Arc<HostedCloner>> {
        self.cloners.get(target).cloned()
    }

    /// Whether `target` renders from a banked identity's reference clip on
    /// each call (a `voxcpm2` worker) rather than from a recorded clone.
    #[must_use]
    pub fn renders_from_refs(&self, target: &str) -> bool {
        self.reference_targets.contains(target)
    }

    /// Builds each `[models.media]` seat. A rung whose provider cannot
    /// start drops out of its ladder, and the reason shows in `status`. A
    /// `key_secret` provider's calls go through the credential broker at
    /// `site`, its key read at `keys`.
    pub(super) fn build(
        config: &ModelsConfig,
        rests: &Arc<OfferCooldowns>,
        status: &mut Vec<SeatStatus>,
        site: Option<&Result<BrokerSite, String>>,
        keys: Option<&Arc<dyn KeyDoor>>,
    ) -> Self {
        let mut runtime = Self::empty();
        if config.media.seats.is_empty() {
            return runtime;
        }
        runtime.meter = Some(BudgetGuard::new(
            MEDIA_RUN,
            config.media.budget_units,
            BudgetExhaustionPolicy::Suspend,
        ));
        runtime.rests = Some(Arc::clone(rests));
        runtime.reference_targets = config
            .providers
            .iter()
            .filter(|(_, provider)| provider.kind.renders_from_refs())
            .map(|(name, _)| name.clone())
            .collect();
        runtime.cloners = voice_cloners(config);
        runtime.live_asr = soniox::live_rungs(config);
        let backends = media_backends(config, site, keys);
        for (operation, seat) in &config.media.seats {
            let mut rungs = Vec::new();
            let mut rung_status = Vec::new();
            let mut rows = Vec::new();
            for (position, model) in seat.rungs.iter().enumerate() {
                let provider = &config.providers[&model.provider];
                let mut entry = RungStatus::new(model, provider);
                match backends.get(&model.provider).and_then(|backend| {
                    media_rung(provider, backend, model, position, *operation, &seat.caps)
                }) {
                    Some(rung) => {
                        rows.push((rung.model.clone(), model.clone(), provider.locality));
                        rungs.push(rung);
                    }
                    None => entry.available = false,
                }
                rung_status.push(entry);
            }
            if operation.is_job() {
                for rung in &rungs {
                    runtime.job_rungs.insert(rung.model.clone(), rung.clone());
                }
            }
            let state = if rungs.is_empty() {
                SeatState::Unavailable
            } else {
                SeatState::Ready
            };
            let seat_model = media_seat_model(*operation, &rungs);
            status.push(SeatStatus {
                role: format!("media.{}", operation.as_str()),
                seat_model: seat_model.as_ref().map(ToString::to_string),
                state,
                rungs: rung_status,
            });
            let Some(seat_model) = seat_model.filter(|_| !rungs.is_empty()) else {
                continue;
            };
            // A tier bound to a rung that did not start serves no voice.
            let tiers = seat
                .tiers
                .iter()
                .filter_map(|(tier, model)| {
                    let (id, _, _) = rows.iter().find(|(_, bound, _)| bound == model)?;
                    Some((tier.clone(), id.clone()))
                })
                .collect();
            let locality = ladder_locality(&rungs, config);
            let scope = SeatScope {
                wire: Wire::Media(*operation),
                stays_on_device: false,
                configured: seat.rungs.len(),
            };
            let alone = rungs
                .iter()
                .map(|rung| {
                    let ladder = OfferLadder::pinned(rung.clone(), Arc::clone(rests)).scoped(scope);
                    (rung.model.clone(), Arc::new(ladder))
                })
                .collect();
            let rows = rows
                .into_iter()
                .map(|(id, model, locality)| MediaRow {
                    operation: *operation,
                    model: id.to_string(),
                    seat_model: seat_model.to_string(),
                    provider: model.provider,
                    wire_model: model.model,
                    locality,
                    inputs: seat.caps.inputs.clone(),
                    outputs: seat.caps.outputs.clone(),
                    native_rates: seat.caps.native_rates.clone(),
                    max_references: seat.caps.max_references,
                })
                .collect();
            runtime.seats.insert(
                *operation,
                MediaSeat {
                    model: seat_model.clone(),
                    locality,
                    ladder: Arc::new(
                        OfferLadder::seat(seat_model, rungs, Arc::clone(rests)).scoped(scope),
                    ),
                    rungs: alone,
                    rows,
                    tiers,
                },
            );
        }
        runtime
    }

    pub(super) fn set_host_account(&mut self, host: Arc<HostAccount>) {
        self.host = Some(host);
    }

    pub(super) fn set_receipts(&mut self, receipts: Arc<dyn RunReceiptSink>) {
        self.receipts = receipts;
    }

    /// Every row that serves `operation` (every operation when `None`)
    /// over `inputs`.
    #[must_use]
    pub fn options(
        &self,
        operation: Option<AiOperation>,
        inputs: &BTreeSet<Modality>,
    ) -> Vec<MediaRow> {
        self.seats
            .iter()
            .filter(|(op, _)| operation.is_none_or(|wanted| wanted == **op))
            .flat_map(|(_, seat)| &seat.rows)
            .filter(|row| inputs.is_subset(&row.inputs))
            .cloned()
            .collect()
    }

    /// Whether the rung `model` of `operation`'s seat can take a call now
    /// (FIX 2942): it was built, and its offer is live ([`RungHealth::live_now`]).
    pub(super) fn rung_live(&self, operation: AiOperation, model: &str) -> bool {
        let Some(seat) = self.seats.get(&operation) else {
            return false;
        };
        ModelId::new(model.to_owned())
            .ok()
            .and_then(|id| seat.rungs.get(&id))
            .is_some_and(|alone| alone.health().iter().all(|(_, health)| health.live_now()))
    }

    /// What the media meter has left to spend, in token units.
    #[must_use]
    pub fn units_left(&self) -> Option<u64> {
        self.meter
            .as_ref()
            .map(|meter| meter.read().remaining_units)
    }

    /// The seat id and widest locality that serve `operation`.
    #[must_use]
    pub fn seat(&self, operation: AiOperation) -> Option<(ModelId, ModelLocality)> {
        self.seats
            .get(&operation)
            .map(|seat| (seat.model.clone(), seat.locality))
    }

    /// One rung alone of each media seat, as a model that a parked offer's
    /// media calls may fall back to once the owner names it (OF-305).
    pub(super) fn fallback_rungs(&self) -> Vec<FallbackRung> {
        self.seats
            .values()
            .flat_map(|seat| seat.rungs.values())
            .filter_map(OfferLadder::fallback_rung)
            .collect()
    }

    /// The ladder of the media seat that the status route lists as `role`
    /// (`media.<operation>`).
    pub(super) fn seat_ladder(&self, role: &str) -> Option<&Arc<OfferLadder>> {
        let operation = role.strip_prefix("media.")?;
        self.seats
            .iter()
            .find(|(seat, _)| seat.as_str() == operation)
            .map(|(_, seat)| &seat.ladder)
    }

    /// Where `model` runs, when a media seat or one of its rungs has that
    /// id: the host's attestation for the vault's inference check.
    #[must_use]
    pub fn locality(&self, operation: AiOperation, model: &ModelId) -> Option<ModelLocality> {
        let seat = self.seats.get(&operation)?;
        if &seat.model == model {
            return Some(seat.locality);
        }
        seat.rows
            .iter()
            .find(|row| row.model == model.as_str())
            .map(|row| row.locality)
    }

    /// Each voice tier a rung of `operation`'s seat is bound to, as the
    /// vault's voice routing reads it: the rung's own id, its tier and
    /// where it runs.
    #[must_use]
    pub fn voice_backends(&self, operation: AiOperation) -> Vec<VoiceBackendBinding> {
        let Some(seat) = self.seats.get(&operation) else {
            return Vec::new();
        };
        seat.tiers
            .iter()
            .filter_map(|(tier, model)| {
                let row = seat.rows.iter().find(|row| row.model == model.as_str())?;
                Some(VoiceBackendBinding {
                    model: model.clone(),
                    tier: tier.clone(),
                    locality: row.locality,
                })
            })
            .collect()
    }

    /// The rungs a call naming `model` may reach, in ladder order: every
    /// rung for the seat's id, the one rung for a rung's. Each comes with
    /// its provider, the render target the voice bank keys its clones by,
    /// and where it runs.
    #[must_use]
    pub fn rung_targets(
        &self,
        operation: AiOperation,
        model: &ModelId,
    ) -> Vec<(ModelId, String, ModelLocality)> {
        let Some(seat) = self.seats.get(&operation) else {
            return Vec::new();
        };
        seat.rows
            .iter()
            .filter(|row| seat.model == *model || row.model == model.as_str())
            .filter_map(|row| {
                let id = ModelId::new(row.model.clone()).ok()?;
                Some((id, row.provider.clone(), row.locality))
            })
            .collect()
    }

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

    fn walk<'a>(
        &'a self,
        request: MediaRequest,
        voices: Option<&'a RungVoices>,
    ) -> LlmResult<impl std::future::Future<Output = LlmResult<MediaAnswer>> + Send + 'a> {
        let ladder = self.ladder(&request)?;
        let meter = self.meter.clone().ok_or(FatalLlmError::InvalidRequest)?;
        let run = undeclared_run(
            MEDIA_RUN,
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
        );
        Ok(async move { ladder.media(&run, request, None, voices).await })
    }

    /// One call to its answer, on a run of its own on the media meter.
    pub async fn run(&self, request: MediaRequest) -> LlmResult<MediaResponse> {
        self.run_in(request, None).await
    }

    /// [`Self::run`] for a speech call in a banked voice (FIX 1746): it goes
    /// only to the rungs of its ladder that hold the voice, each in its own
    /// binding of it.
    pub(crate) async fn run_voiced(
        &self,
        request: MediaRequest,
        voices: &RungVoices,
    ) -> LlmResult<MediaResponse> {
        self.run_in(request, Some(voices)).await
    }

    async fn run_in(
        &self,
        request: MediaRequest,
        voices: Option<&RungVoices>,
    ) -> LlmResult<MediaResponse> {
        if request.operation.is_job() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        match self.walk(request, voices)?.await? {
            MediaAnswer::Done(response) => Ok(response),
            // Only a job operation is submitted.
            MediaAnswer::Job(mut job) => {
                job.settle_failed();
                Err(FatalLlmError::InvalidRequest.into())
            }
        }
    }

    /// Submits one job (`ai.video`); its caller polls the ticket. The job
    /// is kept in the vault, so a restart loses none.
    pub async fn submit(&self, request: MediaRequest) -> LlmResult<MediaTicket> {
        if !request.operation.is_job() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let operation = request.operation;
        let sent = self.store.as_ref().map(|_| request.clone());
        let MediaAnswer::Job(job) = self.walk(request, None)?.await? else {
            return Err(FatalLlmError::EmptyResponse.into());
        };
        let id = job_ticket(&job.provider_job);
        let ticket = MediaTicket {
            job: id.clone(),
            model: job.model.to_string(),
            operation,
        };
        if let (Some(store), Some(request)) = (&self.store, sent)
            && let Err(error) = store.put(
                &id,
                JobRow {
                    model: job.model.clone(),
                    operation,
                    provider_job: job.provider_job.clone(),
                    request,
                    ended: None,
                    receipt: job.receipt.clone(),
                },
            )
        {
            tracing::error!(%error, ticket = %id, "a media job was not kept: it runs held here");
        }
        self.lock_jobs()
            .insert(id, Held::Running(Arc::new(tokio::sync::Mutex::new(job))));
        Ok(ticket)
    }

    /// Where job `id` stands. A job that ended keeps its end, and every poll
    /// answers it until its caller deletes the job; without a vault it is
    /// answered once. An end the vault refuses is held here and answered
    /// from here, and each poll writes it again; the job is never polled or
    /// paid for again. A job a restart left running is taken up again on a
    /// fresh permit, and nothing is sent again.
    pub async fn poll(&self, id: &str) -> LlmResult<MediaJobState> {
        let job = match self.held(id)? {
            Held::Running(job) => job,
            Held::Unkept(state) => {
                self.keep_end(id, &state);
                return Ok(state);
            }
            Held::Ended(state) => return Ok(state),
        };
        let mut held = job.lock().await;
        if held.permit.is_none() {
            // The poll this one waited behind saw the end.
            drop(held);
            return self.ended(id);
        }
        let state = held.poll().await;
        if let Ok(state) = &state
            && state.ended()
        {
            self.keep_end(id, state);
        }
        state
    }

    /// Keeps job `id`'s end `state` in its row, the row and its clips in one
    /// write, and lets the job go from here. An end the vault refuses, or a
    /// job whose row was never kept, stays held here with its end, for the
    /// next poll to answer and write again. A job dropped meanwhile stays
    /// dropped.
    fn keep_end(&self, id: &str, state: &MediaJobState) {
        let kept = self
            .store
            .as_ref()
            .map_or(Ok(()), |store| -> Result<(), String> {
                let mut row = store
                    .get(id)
                    .ok_or_else(|| "its row is not kept".to_owned())?;
                row.ended = Some(state.clone());
                store.put(id, row)
            });
        let mut jobs = self.lock_jobs();
        match kept {
            Ok(()) => {
                jobs.remove(id);
            }
            Err(error) => {
                tracing::error!(%error, ticket = id, "a media job's end is held, not kept");
                if let Some(held) = jobs.get_mut(id)
                    && matches!(held, Held::Running(_))
                {
                    *held = Held::Unkept(state.clone());
                }
            }
        }
    }

    /// Stops job `id` at its provider and drops it, its kept row with it.
    /// A job that ended is only dropped.
    pub async fn cancel(&self, id: &str) -> LlmResult<()> {
        let held = self.held(id);
        self.lock_jobs().remove(id);
        if let Some(store) = &self.store {
            store.remove(id);
        }
        let job = match held? {
            Held::Running(job) => job,
            Held::Unkept(_) | Held::Ended(_) => return Ok(()),
        };
        let stopped = job.lock().await.cancel().await;
        stopped
    }

    /// Job `id`, held here or kept in the vault. A kept job that has not
    /// ended is taken up again here, once: a poll racing this one finds it
    /// held.
    fn held(&self, id: &str) -> LlmResult<Held> {
        if let Some(held) = self.lock_jobs().get(id) {
            return Ok(held.clone());
        }
        let row = self
            .store
            .as_ref()
            .and_then(|store| store.get(id))
            .ok_or(FatalLlmError::InvalidRequest)?;
        if let Some(state) = row.ended {
            return Ok(Held::Ended(state));
        }
        let mut jobs = self.lock_jobs();
        if let Some(held) = jobs.get(id) {
            return Ok(held.clone());
        }
        let job = Held::Running(Arc::new(tokio::sync::Mutex::new(self.take_up(&row)?)));
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
        for ticket in store.tickets() {
            if let Err(error) = self.held(&ticket) {
                tracing::warn!(%error, %ticket, "a kept media job was not taken up");
            }
        }
    }

    /// The end job `id` holds here, or its row keeps.
    fn ended(&self, id: &str) -> LlmResult<MediaJobState> {
        if let Some(Held::Unkept(state)) = self.lock_jobs().get(id) {
            return Ok(state.clone());
        }
        self.store
            .as_ref()
            .and_then(|store| store.get(id))
            .and_then(|row| row.ended)
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }

    /// A job a restart left running, taken up again on the rung that took
    /// it: a permit admitted afresh on this runtime's meter for the call
    /// its caller sent, and started for the job's polls without a new
    /// submit. It carries the served receipt it went out with, and its end
    /// counts toward its offer's health as a sent request's does: a
    /// recovering offer's one probation request when that slot is free. A
    /// job whose rung left the config cannot be taken up.
    fn take_up(&self, row: &JobRow) -> LlmResult<HeldJob> {
        let rung = self
            .job_rungs
            .get(&row.model)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let media = rung.media.as_ref().ok_or(FatalLlmError::InvalidRequest)?;
        let mut bound = row.request.clone();
        bound.model = rung.model.clone();
        bound.envelope.locality = rung.offer.binding.locality;
        let meter = self.meter.clone().ok_or(FatalLlmError::InvalidRequest)?;
        let run = undeclared_run(
            MEDIA_RUN,
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
        );
        let selector = Some(row.request.model.as_str());
        let permit = run.admit_media(selector, &bound, &rung.offer.binding)?;
        let gate = run.media_gate(Arc::clone(&media.backend), &rung.offer.binding);
        gate.resume(&bound, permit.lease())?;
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
            provider_job: row.provider_job.clone(),
            model: rung.model.clone(),
            operation: row.operation,
            caps: media.caps.clone(),
        })
    }

    fn lock_jobs(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Held>> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl super::ModelRuntime {
    /// Every row of the `ai.*` family that serves `operation` (every one
    /// when `None`) over `inputs`: each available rung of each text seat,
    /// then each media row. Only a rung that can take a call now is listed
    /// (FIX 2942): one whose provider is down, whose one probation request
    /// is out, or that a limit holds is left out until it is back.
    #[must_use]
    pub fn ai_options(
        &self,
        operation: Option<AiOperation>,
        inputs: &BTreeSet<Modality>,
    ) -> Vec<MediaRow> {
        let mut rows = Vec::new();
        if operation.is_none_or(|wanted| wanted == AiOperation::Text) {
            for (role, seat) in &self.seats {
                if *role == oneiron::llm::manifest::ModelRole::Reranker {
                    continue;
                }
                let mut caps = MediaCaps::for_operation(AiOperation::Text);
                if seat
                    .ladder
                    .supports(&seat.model, &oneiron::LlmCapability::ImageInput)
                {
                    caps.inputs.insert(Modality::Image);
                }
                if seat
                    .ladder
                    .supports(&seat.model, &oneiron::LlmCapability::AudioInput)
                {
                    caps.inputs.insert(Modality::Audio);
                }
                if !inputs.is_subset(&caps.inputs) {
                    continue;
                }
                let status = self
                    .status
                    .seats
                    .iter()
                    .find(|status| status.seat_model.as_deref() == Some(seat.model.as_str()));
                let health: BTreeMap<usize, RungHealth> =
                    seat.ladder.health().into_iter().collect();
                let rungs = status
                    .into_iter()
                    .flat_map(|status| status.rungs.iter().enumerate());
                for (position, rung) in rungs {
                    let live = health.get(&position).is_none_or(RungHealth::live_now);
                    let Some(model) = rung.engine_model.clone().filter(|_| rung.available && live)
                    else {
                        continue;
                    };
                    rows.push(MediaRow {
                        operation: AiOperation::Text,
                        model,
                        seat_model: seat.model.to_string(),
                        provider: rung.provider.clone(),
                        wire_model: rung.model.clone(),
                        locality: rung.locality,
                        inputs: caps.inputs.clone(),
                        outputs: caps.outputs.clone(),
                        native_rates: Vec::new(),
                        max_references: 0,
                    });
                }
            }
        }
        rows.extend(
            self.media
                .options(operation, inputs)
                .into_iter()
                .filter(|row| self.media.rung_live(row.operation, &row.model)),
        );
        rows
    }
}

/// One media client per provider some media seat names, each serving the
/// models those seats name on it. A `key_secret` provider's client sends
/// through the credential broker.
fn media_backends(
    config: &ModelsConfig,
    site: Option<&Result<BrokerSite, String>>,
    keys: Option<&Arc<dyn KeyDoor>>,
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
                        }) as Arc<dyn MediaBackend>
                    })
                }
            }
            ProviderKind::Gemini => gemini_backend(provider, wire_models),
            // It hears live only, through `open_voice_asr`; never the
            // OpenAI-compatible wire below.
            ProviderKind::Soniox => soniox::live_backend(provider),
            _ => ProviderHttp::new(provider, KeyStyle::Bearer).map(|http| {
                Arc::new(OpenAiMediaBackend::new(MediaHttp { http }, wire_models))
                    as Arc<dyn MediaBackend>
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

/// The clone wire of each configured hosted speech provider, by name.
fn voice_cloners(config: &ModelsConfig) -> BTreeMap<String, Arc<HostedCloner>> {
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
        match built {
            Ok((http, wire)) => {
                cloners.insert(
                    name.clone(),
                    Arc::new(HostedCloner {
                        http,
                        wire,
                        locality: provider.locality,
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

/// `model` on `provider` as a media rung at `position` for `operation`.
fn media_rung(
    provider: &ProviderConfig,
    backend: &Arc<dyn MediaBackend>,
    model: &ModelRef,
    position: usize,
    operation: AiOperation,
    caps: &MediaCaps,
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
            binding,
            backend: Arc::new(NoChat),
        },
        media: Some(MediaRung {
            backend: Arc::clone(backend),
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

/// A job's ticket: the server's own id for the provider's job, so a caller
/// never names a provider's id.
fn job_ticket(provider_job: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let mut digest = blake3::Hasher::new();
    digest.update(provider_job.as_bytes());
    digest.update(&nanos.to_le_bytes());
    format!("job_{}", &digest.finalize().to_hex()[..24])
}

impl MediaRuntime {
    /// Opens one bounded `ai.transcribe` stream (live partials) on a run of
    /// its own on the media meter: one permit for the whole stream,
    /// reserving `bound_ms` of audio, started at its rung's media gate
    /// before any audio leaves. As a [`HeldJob`] holds a job's permit to its
    /// end, the lease holds the stream's: it meters the audio its wire sends
    /// and settles when the stream ends or is cancelled.
    pub fn open_stream(
        &self,
        request: MediaRequest,
        bound_ms: u64,
    ) -> LlmResult<oneiron::llm::run_admission::MediaStreamLease> {
        if request.operation != AiOperation::Transcribe || bound_ms == 0 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let ladder = self.ladder(&request)?;
        let meter = self.meter.clone().ok_or(FatalLlmError::InvalidRequest)?;
        let run = undeclared_run(
            MEDIA_RUN,
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
        );
        ladder.open_media_stream(&run, request, bound_ms)
    }
}

impl super::ModelRuntime {
    /// This runtime with its `ai.video` jobs kept in `vault`, so a restart
    /// loses none and an ended job answers every poll (FIX-LIST 465).
    #[must_use]
    pub fn with_media_vault(mut self, vault: Arc<Vault>) -> Self {
        self.media.store = Some(JobStore::new(vault));
        self
    }

    /// Takes up, once the runtime is whole, every kept `ai.video` job a
    /// restart left running: its permit is admitted again on the media meter
    /// at start, not at its next poll, so new calls cannot spend what the
    /// job will owe.
    pub fn take_up_kept_media_jobs(&self) {
        self.media.take_up_kept();
    }
}
