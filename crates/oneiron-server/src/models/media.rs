//! The `ai.*` media seats (`[models.media]`): one ladder per operation, each
//! rung an OpenAI-compatible provider's media wire. A media call goes down
//! its seat's ladder on the same walk as a text call: each rung it reaches
//! is admitted on its own permit, sent through the run's media gate and
//! settled in token units on its own (ARCH-0053 `#run-admission`); an offer
//! refused for a limit rests and the call goes to the next. A video call is
//! a job: its permit is held while the provider renders and settled when
//! the job ends.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use oneiron::llm::media::{
    AiMediaDoor, AiOperation, MediaBackend, MediaCaps, MediaFuture, MediaJobState, MediaRequest,
    MediaResponse, Modality,
};
use oneiron::llm::run_admission::{HostAccount, MediaGate, RunPermit, RunReceiptSink};
use oneiron::llm::{SingleRouteBackend, SingleSend, VoiceBackendBinding};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, FatalLlmError, LlmBackend, LlmCatalogEntry,
    LlmError, LlmGenerateFuture, LlmRequest, LlmResult, LlmStreamResult, ModelId, ModelLocality,
    ModelTierRef,
};
use oneiron_llm_openai::{
    OpenAiMediaBackend, OpenAiMediaBody, OpenAiMediaHttpRequest, OpenAiMediaHttpResponse,
    OpenAiMediaMethod, OpenAiMediaTransport, OpenAiMediaTransportFuture,
};
use serde::Serialize;

use crate::config::models::{ModelRef, ModelsConfig, ProviderConfig, ProviderKind};

use super::catalog::{catalog_entry, engine_model_id};
use super::cooldown::{FallbackRung, OfferCooldowns, ProbePermit};
use super::gemini_media::gemini_backend;
use super::hosted_speech::{CARTESIA_VERSION, HostedCloner, HostedSpeech, HostedWire};
use super::http::{KeyStyle, MediaSend, ProviderHttp};
use super::ladder::{LadderRung, OfferLadder, PendingReceipt, SeatScope, Wire};
use super::offer::{ServedOffer, media_offer};
use super::rerank::transport;
use super::soniox::{self, SonioxRung};
use super::status::{RungStatus, SeatState, SeatStatus};
use super::voxcpm2_speech::VoxCpm2Speech;
use super::walk::provider_down;
use super::{LoggedReceipts, ladder_locality, undeclared_run};

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

/// Every media seat the config fills, their meter, and the jobs they run.
pub struct MediaRuntime {
    seats: BTreeMap<AiOperation, MediaSeat>,
    meter: Option<BudgetGuard>,
    receipts: Arc<dyn RunReceiptSink>,
    host: Option<Arc<HostAccount>>,
    jobs: Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<HeldJob>>>>,
    /// The render targets (provider names) that render from a banked
    /// identity's reference clip on each call and keep no clone.
    reference_targets: BTreeSet<String>,
    /// The hosted render targets (provider names) that clone a banked
    /// identity, by name.
    cloners: BTreeMap<String, Arc<HostedCloner>>,
    /// The transcribe rungs that hear live (soniox), by engine id.
    live_asr: BTreeMap<String, Arc<SonioxRung>>,
}

impl MediaRuntime {
    pub(super) fn empty() -> Self {
        Self {
            seats: BTreeMap::new(),
            meter: None,
            receipts: Arc::new(LoggedReceipts),
            host: None,
            jobs: Mutex::default(),
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
    /// start drops out of its ladder, and the reason shows in `status`.
    pub(super) fn build(
        config: &ModelsConfig,
        rests: &Arc<OfferCooldowns>,
        status: &mut Vec<SeatStatus>,
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
        runtime.reference_targets = config
            .providers
            .iter()
            .filter(|(_, provider)| provider.kind.renders_from_refs())
            .map(|(name, _)| name.clone())
            .collect();
        runtime.cloners = voice_cloners(config);
        runtime.live_asr = soniox::live_rungs(config);
        let backends = media_backends(config);
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

    fn walk(
        &self,
        request: MediaRequest,
    ) -> LlmResult<impl std::future::Future<Output = LlmResult<MediaAnswer>> + Send + '_> {
        let ladder = self.ladder(&request)?;
        let meter = self.meter.clone().ok_or(FatalLlmError::InvalidRequest)?;
        let run = undeclared_run(
            MEDIA_RUN,
            meter,
            self.host.clone(),
            Arc::clone(&self.receipts),
        );
        Ok(async move { ladder.media(&run, request, None).await })
    }

    /// One call to its answer, on a run of its own on the media meter.
    pub async fn run(&self, request: MediaRequest) -> LlmResult<MediaResponse> {
        if request.operation.is_job() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        match self.walk(request)?.await? {
            MediaAnswer::Done(response) => Ok(response),
            // Only a job operation is submitted.
            MediaAnswer::Job(mut job) => {
                job.settle_failed();
                Err(FatalLlmError::InvalidRequest.into())
            }
        }
    }

    /// Submits one job (`ai.video`); its caller polls the ticket.
    pub async fn submit(&self, request: MediaRequest) -> LlmResult<MediaTicket> {
        if !request.operation.is_job() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let operation = request.operation;
        let MediaAnswer::Job(job) = self.walk(request)?.await? else {
            return Err(FatalLlmError::EmptyResponse.into());
        };
        let id = job_ticket(&job.provider_job);
        let ticket = MediaTicket {
            job: id.clone(),
            model: job.model.to_string(),
            operation,
        };
        self.lock_jobs()
            .insert(id, Arc::new(tokio::sync::Mutex::new(job)));
        Ok(ticket)
    }

    /// Where job `id` stands. A job that ended is answered once, and leaves
    /// the table.
    pub async fn poll(&self, id: &str) -> LlmResult<MediaJobState> {
        let job = self
            .lock_jobs()
            .get(id)
            .cloned()
            .ok_or(FatalLlmError::InvalidRequest)?;
        let state = job.lock().await.poll().await;
        if state.as_ref().is_ok_and(MediaJobState::ended) {
            self.lock_jobs().remove(id);
        }
        state
    }

    /// Stops job `id` at its provider and drops it.
    pub async fn cancel(&self, id: &str) -> LlmResult<()> {
        let job = self
            .lock_jobs()
            .remove(id)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let stopped = job.lock().await.cancel().await;
        stopped
    }

    fn lock_jobs(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<String, Arc<tokio::sync::Mutex<HeldJob>>>> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl super::ModelRuntime {
    /// Every row of the `ai.*` family that serves `operation` (every one
    /// when `None`) over `inputs`: each available rung of each text seat,
    /// then each media row.
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
                for rung in status.into_iter().flat_map(|status| &status.rungs) {
                    let Some(model) = rung.engine_model.clone().filter(|_| rung.available) else {
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
        rows.extend(self.media.options(operation, inputs));
        rows
    }
}

/// Engine code's media door (an image asset's generation): each call is a
/// run of its own on the media meter, rung by rung through the media gate.
impl AiMediaDoor for MediaRuntime {
    fn call<'a>(&'a self, request: MediaRequest) -> MediaFuture<'a, MediaResponse> {
        Box::pin(self.run(request))
    }
}

/// One media client per provider some media seat names, each serving the
/// models those seats name on it.
fn media_backends(config: &ModelsConfig) -> BTreeMap<String, Arc<dyn MediaBackend>> {
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
