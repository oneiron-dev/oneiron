//! The run's model backend: every call starts its permit here, before any
//! byte leaves, and leaves a dispatch receipt with its request digest.
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_core::Stream;

use super::super::{
    BrokerIsolation, BudgetLease, DispatchBinding, FatalLlmError, LlmBackend, LlmCapability,
    LlmError, LlmGenerateFuture, LlmRequest, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult,
    LlmUsage, ModelId, SingleRouteBackend, WorkContext,
};
use super::admission::{RunDenied, RunInner};

/// Keys a provider adapter stamps into [`LlmUsage::raw_provider`] naming the
/// model the provider said it served, the ladder's first.
const SERVED_MODEL_KEYS: [&str; 2] = ["reported_model", "served_model"];

/// A model backend that serves one run through one offer. It refuses a call
/// whose lease this run did not issue, that is closed or already used, or that
/// names another model, route or offer than its permit, and a call that picks
/// its model or route through a param or provider option. Two offers at one
/// route, paid differently, are two gates.
///
/// It wraps only a [`SingleRouteBackend`]: a fallback ladder below a gate
/// would pick its model after the check. One permit buys one physical call,
/// so a retry, a schema correction or the next hop of a chain takes a fresh
/// admission. A call the backend's own preflight refuses is refused before
/// its permit starts, so it costs nothing and the permit stays usable. A lease from any other meter, the step
/// layer's included, is refused here.
pub struct GatedBackend {
    run: Arc<RunInner>,
    inner: Arc<dyn SingleRouteBackend>,
    /// The offer this gate sends for. A call's own model takes the subject.
    offer: DispatchBinding,
    /// One gate is one work tree; clones of this context share its cancel Arc.
    work_context: WorkContext,
}

impl GatedBackend {
    pub(super) fn new(
        run: Arc<RunInner>,
        inner: Arc<dyn SingleRouteBackend>,
        offer: DispatchBinding,
        work_context: WorkContext,
    ) -> Self {
        Self {
            run,
            inner,
            offer,
            work_context,
        }
    }

    /// The digest of the exact bytes the wrapped backend would send for
    /// `request`, when it builds them first; `None` when it does not, or
    /// cannot build them.
    pub(super) fn request_digest(&self, request: &LlmRequest) -> Option<String> {
        self.inner.request_digest(request, false).ok().flatten()
    }

    /// Checks and starts the call's permit; returns the digest of the request
    /// that is about to leave. A backend that builds its request bytes first
    /// names their digest, and the permit must have been admitted for exactly
    /// those bytes ([`RunAdmission::admit_request`](super::RunAdmission::admit_request)).
    fn open(&self, request: &LlmRequest, lease: &BudgetLease, stream: bool) -> LlmResult<String> {
        let model = request.model.as_str();
        if let Some(key) = request.route_selector_override() {
            let reason = RunDenied::RouteOverride { key };
            self.run.refuse(Some(model), Some(lease), reason);
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let bound = self
            .inner
            .preflight(request, stream)
            .and_then(|()| self.inner.request_digest(request, stream));
        let bound = match bound {
            Ok(bound) => bound,
            Err(error) => {
                self.run
                    .refuse(Some(model), Some(lease), RunDenied::BackendRefused);
                return Err(error);
            }
        };
        let digest = match &bound {
            Some(bound) => bound.clone(),
            None => request
                .canonical_hash_hex()
                .map_err(|_| LlmError::from(FatalLlmError::InvalidRequest))?,
        };
        let call = DispatchBinding {
            subject: model.to_owned(),
            request_digest: bound,
            ..self.offer.clone()
        };
        self.run.begin_dispatch(lease, &call)?;
        Ok(digest)
    }

    fn pending(&self, request: &LlmRequest, lease: &BudgetLease, digest: String) -> Pending<'_> {
        Pending {
            gate: self,
            dispatch: Some(Dispatch {
                lease: lease.clone(),
                model: request.model.clone(),
                digest,
                broker_isolation: self.inner.broker_isolation(),
            }),
        }
    }
}

/// A started call, as its dispatch receipt names it.
pub(super) struct Dispatch {
    pub(super) lease: BudgetLease,
    pub(super) model: ModelId,
    pub(super) digest: String,
    pub(super) broker_isolation: Option<BrokerIsolation>,
}

/// A started call's dispatch receipt, written once: when the call ends, or
/// when it is dropped before it ends.
struct Pending<'a> {
    gate: &'a GatedBackend,
    dispatch: Option<Dispatch>,
}

impl Pending<'_> {
    fn finish(&mut self, served_model: Option<String>, answered: bool) {
        if let Some(dispatch) = self.dispatch.take() {
            self.gate
                .run
                .dispatched(dispatch, &self.gate.offer.route, served_model, answered);
        }
    }
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.finish(None, false);
    }
}

fn served_model(usage: &LlmUsage) -> Option<String> {
    SERVED_MODEL_KEYS.iter().find_map(|key| {
        usage
            .raw_provider
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    })
}

impl LlmBackend for GatedBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.inner.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let digest = self.open(&request, lease, false)?;
            lease.attach_work_context(self.work_context.clone());
            let mut pending = self.pending(&request, lease, digest);
            let result = self.inner.generate(request, lease).await;
            match &result {
                Ok(response) => pending.finish(served_model(&response.usage), true),
                Err(_) => pending.finish(None, false),
            }
            result
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let digest = self.open(&request, lease, true)?;
        lease.attach_work_context(self.work_context.clone());
        let pending = self.pending(&request, lease, digest);
        let inner = self.inner.stream(request, lease)?;
        Ok(LlmStream::new(GatedStream { inner, pending }))
    }
}

/// The inner stream, receipted once: at its terminal, or when it is dropped
/// before one.
struct GatedStream<'a> {
    inner: LlmStream<'a>,
    pending: Pending<'a>,
}

impl Stream for GatedStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_next(cx);
        match &polled {
            Poll::Ready(Some(Ok(LlmStreamEvent::Done { usage, .. }))) => {
                this.pending.finish(served_model(usage), true);
            }
            Poll::Ready(Some(Err(_)) | None) => this.pending.finish(None, false),
            Poll::Ready(Some(Ok(_))) | Poll::Pending => {}
        }
        polled
    }
}
