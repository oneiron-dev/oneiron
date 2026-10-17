//! The run's media backend: an `ai.*` media call (image, video, speech,
//! transcription, embedding) starts its permit here, before any byte
//! leaves, and leaves a dispatch receipt with its request digest, as a text
//! call does at the [`GatedBackend`](super::GatedBackend). Its permit is
//! admitted as the text call its admission request names
//! ([`RunAdmission::admit_media`](super::RunAdmission::admit_media)).
use std::sync::Arc;

use super::super::media::{
    AiOperation, MediaBackend, MediaCaps, MediaJobState, MediaRequest, MediaResponse, MediaUsage,
};
use super::super::{
    BudgetLease, BudgetSettlement, DispatchBinding, DispatchRefused, FatalLlmError, LlmResult,
    LlmUsage, ModelId,
};
use super::admission::{RunDenied, RunInner};
use super::gate::Dispatch;
use super::permit::RunPermit;
use super::settle::CallOutcome;

/// Keys a media adapter stamps into [`MediaUsage::raw_provider`](super::super::media::MediaUsage)
/// naming the model the provider said it served.
const SERVED_MODEL_KEYS: [&str; 2] = ["reported_model", "served_model"];

/// A media backend that serves one run through one offer. It refuses a call
/// whose lease this run did not issue, that is closed or already used, or
/// that names another model, route or offer than its permit, and a call
/// that picks its model or route through a param. One permit buys one
/// physical call; a job's polls and its cancel ride the permit its submit
/// started.
pub struct MediaGate {
    run: Arc<RunInner>,
    inner: Arc<dyn MediaBackend>,
    offer: DispatchBinding,
}

impl MediaGate {
    pub(super) fn new(
        run: Arc<RunInner>,
        inner: Arc<dyn MediaBackend>,
        offer: DispatchBinding,
    ) -> Self {
        Self { run, inner, offer }
    }

    /// Checks and starts the call's permit; the started call, for its
    /// dispatch receipt.
    fn open(&self, request: &MediaRequest, lease: &BudgetLease) -> LlmResult<Opened<'_>> {
        let model = request.model.as_str();
        if let Some(key) = request.admission_request().route_selector_override() {
            let reason = RunDenied::RouteOverride { key };
            self.run.refuse(Some(model), Some(lease), reason);
            return Err(FatalLlmError::InvalidRequest.into());
        }
        // A call the backend's own preflight refuses (a key its custody door
        // would refuse) is refused before its permit starts, so it costs
        // nothing and the permit stays usable. A media call may send several
        // requests (an embed's parts, a job's polls), so it binds no wire
        // digest: its route and offer bind it.
        if let Err(error) = self.inner.preflight(request) {
            self.run
                .refuse(Some(model), Some(lease), RunDenied::BackendRefused);
            return Err(error);
        }
        let digest = request
            .canonical_hash_hex()
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        let call = DispatchBinding {
            subject: model.to_owned(),
            request_digest: None,
            ..self.offer.clone()
        };
        self.run.begin_dispatch(lease, &call)?;
        Ok(Opened {
            gate: self,
            dispatch: Some(Dispatch {
                lease: lease.clone(),
                model: request.model.clone(),
                digest,
                broker_isolation: self.inner.broker_isolation(),
            }),
        })
    }

    /// Sends one call to its answer.
    pub async fn run(
        &self,
        request: MediaRequest,
        lease: &BudgetLease,
    ) -> LlmResult<MediaResponse> {
        let mut opened = self.open(&request, lease)?;
        let answer = self.inner.run(request, lease).await;
        let served = answer.as_ref().ok().and_then(served_model);
        opened.finish(served, answer.is_ok());
        answer
    }

    /// Starts one long call as a provider job; its permit stays open for
    /// the job's polls and is settled when the job ends.
    pub async fn submit(&self, request: MediaRequest, lease: &BudgetLease) -> LlmResult<String> {
        let mut opened = self.open(&request, lease)?;
        let job = self.inner.submit(request, lease).await;
        opened.finish(None, job.is_ok());
        job
    }

    /// Takes up a job that an earlier run's submit started, as a restart
    /// leaves one: starts this permit under the checks a submit takes, and
    /// sends nothing, so the job's polls and its cancel ride this permit.
    /// Its dispatch receipt stands for the job going on here.
    pub fn resume(&self, request: &MediaRequest, lease: &BudgetLease) -> LlmResult<()> {
        let mut opened = self.open(request, lease)?;
        opened.finish(None, true);
        Ok(())
    }

    /// Where the job a submit through this gate started stands.
    pub async fn poll(
        &self,
        model: &ModelId,
        job: &str,
        lease: &BudgetLease,
    ) -> LlmResult<MediaJobState> {
        self.started(lease)?;
        self.inner.poll(model, job, lease).await
    }

    /// Asks the provider to stop the job a submit through this gate started.
    pub async fn cancel(&self, model: &ModelId, job: &str, lease: &BudgetLease) -> LlmResult<()> {
        self.started(lease)?;
        self.inner.cancel(model, job, lease).await
    }

    /// A poll or a cancel continues a started call: its lease is this run's,
    /// open, and already sent once.
    fn started(&self, lease: &BudgetLease) -> LlmResult<()> {
        let ours = self.run.lock_calls().contains_key(lease.id());
        let started = ours
            && self.run.guard.lease_open(lease) == Some(true)
            && self.run.guard.dispatched(lease) == Some(true);
        if started {
            Ok(())
        } else {
            Err(FatalLlmError::InvalidRequest.into())
        }
    }
}

impl MediaGate {
    /// Opens one bounded media stream (live `ai.transcribe` partials) on
    /// `permit`, which this run admitted for it
    /// ([`RunAdmission::admit_media_stream`](super::RunAdmission::admit_media_stream)).
    /// The permit starts here, before any audio leaves, under the checks
    /// one call takes, and the stream holds it to its end. `bound_ms` is the
    /// most audio the stream carries; `caps` is its rung's row, whose rate
    /// the admitted audio settles at.
    pub fn open_stream(
        &self,
        request: &MediaRequest,
        permit: RunPermit,
        caps: MediaCaps,
        bound_ms: u64,
    ) -> LlmResult<MediaStreamLease> {
        let model = request.model.as_str();
        let lease = permit.lease().clone();
        if let Some(key) = request.admission_request().route_selector_override() {
            let reason = RunDenied::RouteOverride { key };
            self.run.refuse(Some(model), Some(&lease), reason);
            return Err(FatalLlmError::InvalidRequest.into());
        }
        // As a call's: the backend's preflight before the stream starts.
        if let Err(error) = self.inner.preflight(request) {
            self.run
                .refuse(Some(model), Some(&lease), RunDenied::BackendRefused);
            return Err(error);
        }
        let digest = request
            .canonical_hash_hex()
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        let call = DispatchBinding {
            subject: model.to_owned(),
            request_digest: None,
            ..self.offer.clone()
        };
        // A permit that does not start here is dropped unstarted, which
        // releases its reservation.
        self.run.begin_dispatch(&lease, &call)?;
        Ok(MediaStreamLease {
            run: Arc::clone(&self.run),
            route: self.offer.route.clone(),
            dispatch: Some(Dispatch {
                lease: lease.clone(),
                model: request.model.clone(),
                digest,
                broker_isolation: self.inner.broker_isolation(),
            }),
            lease,
            permit: Some(permit),
            operation: request.operation,
            caps,
            bound_ms,
            admitted_ms: 0,
        })
    }
}

/// One bounded media stream on one permit: live audio to a provider's
/// streaming wire, metered as it is admitted. Each chunk is admitted here
/// before it leaves, and none past the stream's bound, the audio its
/// permit reserved for; a longer stream ends this one and opens the next on
/// a fresh permit. It settles once, in its rung's native units (seconds
/// heard): on [`Self::end`], on [`Self::cancel`], or when dropped, which is
/// a cancel. Audio admitted before a cancel went out, so it is paid for; a
/// stream that admitted none pays nothing.
pub struct MediaStreamLease {
    run: Arc<RunInner>,
    route: String,
    dispatch: Option<Dispatch>,
    lease: BudgetLease,
    permit: Option<RunPermit>,
    operation: AiOperation,
    caps: MediaCaps,
    bound_ms: u64,
    admitted_ms: u64,
}

impl MediaStreamLease {
    /// What a stream of up to `bound_ms` of audio reserves, in token units
    /// at `caps`' rate for `operation`: its permit's reservation.
    #[must_use]
    pub fn reserve_units(operation: AiOperation, caps: &MediaCaps, bound_ms: u64) -> u64 {
        stream_units(operation, caps, bound_ms)
    }

    /// The lease the stream's wire carries.
    #[must_use]
    pub fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    /// The audio admitted so far, in milliseconds.
    #[must_use]
    pub fn admitted_ms(&self) -> u64 {
        self.admitted_ms
    }

    /// The audio the stream may still admit, in milliseconds.
    #[must_use]
    pub fn remaining_ms(&self) -> u64 {
        self.bound_ms.saturating_sub(self.admitted_ms)
    }

    /// Admits `ms` more audio before it leaves. Audio past the stream's
    /// bound, or on a lease no longer open, admits nothing.
    pub fn admit_audio(&mut self, ms: u64) -> LlmResult<()> {
        let admitted = self
            .admitted_ms
            .checked_add(ms)
            .filter(|admitted| *admitted <= self.bound_ms)
            .ok_or(FatalLlmError::InvalidRequest)?;
        if self.permit.is_none() || self.run.guard.lease_open(&self.lease) != Some(true) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.admitted_ms = admitted;
        Ok(())
    }

    /// Ends the stream answered: it pays for the audio it admitted.
    /// `served_model` is the model the provider said it served, for the
    /// dispatch receipt.
    pub fn end(mut self, served_model: Option<String>) -> Result<BudgetSettlement, RunDenied> {
        self.settle(served_model, true)
            .unwrap_or(Err(RunDenied::Dispatch {
                refused: DispatchRefused::Closed,
            }))
    }

    /// Cancels the stream: it pays for the audio it already sent.
    pub fn cancel(mut self) -> Result<BudgetSettlement, RunDenied> {
        self.settle(None, false).unwrap_or(Err(RunDenied::Dispatch {
            refused: DispatchRefused::Closed,
        }))
    }

    /// Writes the dispatch receipt and settles the permit, once; `None`
    /// once settled.
    fn settle(
        &mut self,
        served_model: Option<String>,
        answered: bool,
    ) -> Option<Result<BudgetSettlement, RunDenied>> {
        let permit = self.permit.take()?;
        if let Some(dispatch) = self.dispatch.take() {
            self.run
                .dispatched(dispatch, &self.route, served_model, answered);
        }
        let units = stream_units(self.operation, &self.caps, self.admitted_ms);
        Some(permit.settle(CallOutcome::Used(units)))
    }
}

impl Drop for MediaStreamLease {
    fn drop(&mut self) {
        // The refusal, if any, is on the Settled receipt.
        if let Some(settled) = self.settle(None, false) {
            settled.ok();
        }
    }
}

impl std::fmt::Debug for MediaStreamLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaStreamLease")
            .field("lease", &self.lease.id())
            .field("bound_ms", &self.bound_ms)
            .field("admitted_ms", &self.admitted_ms)
            .field("settled", &self.permit.is_none())
            .finish_non_exhaustive()
    }
}

/// `audio_ms` of audio in token units at `caps`' rate for `operation`.
fn stream_units(operation: AiOperation, caps: &MediaCaps, audio_ms: u64) -> u64 {
    MediaUsage {
        audio_ms,
        ..MediaUsage::default()
    }
    .token_units(operation, caps)
    .unwrap_or(0)
}

/// A started media call's dispatch receipt, written once: when the call
/// ends, or when it is dropped before it ends.
struct Opened<'a> {
    gate: &'a MediaGate,
    dispatch: Option<Dispatch>,
}

impl Opened<'_> {
    fn finish(&mut self, served_model: Option<String>, answered: bool) {
        if let Some(dispatch) = self.dispatch.take() {
            self.gate
                .run
                .dispatched(dispatch, &self.gate.offer.route, served_model, answered);
        }
    }
}

impl Drop for Opened<'_> {
    fn drop(&mut self) {
        self.finish(None, false);
    }
}

fn served_model(response: &MediaResponse) -> Option<String> {
    SERVED_MODEL_KEYS.iter().find_map(|key| {
        response
            .usage
            .raw_provider
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    })
}

impl RunPermit {
    /// Settles a media call that answered: the token units its usage
    /// counts ([`MediaUsage::token_units`](super::super::media::MediaUsage::token_units)),
    /// or its reservation when it counted none.
    pub fn settle_media(self, units: Option<u64>) -> Result<BudgetSettlement, RunDenied> {
        match units {
            Some(units) => self.settle(CallOutcome::Used(units)),
            None => self.settle(CallOutcome::Answered(&LlmUsage::zero())),
        }
    }
}
