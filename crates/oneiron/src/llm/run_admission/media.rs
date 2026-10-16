//! The run's media backend: an `ai.*` media call (image, video, speech,
//! transcription, embedding) starts its permit here, before any byte
//! leaves, and leaves a dispatch receipt with its request digest, as a text
//! call does at the [`GatedBackend`](super::GatedBackend). Its permit is
//! admitted as the text call its admission request names
//! ([`RunAdmission::admit_media`](super::RunAdmission::admit_media)).
use std::sync::Arc;

use super::super::media::{MediaBackend, MediaJobState, MediaRequest, MediaResponse};
use super::super::{
    BudgetLease, BudgetSettlement, DispatchBinding, FatalLlmError, LlmResult, LlmUsage, ModelId,
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
                broker_isolation: None,
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
