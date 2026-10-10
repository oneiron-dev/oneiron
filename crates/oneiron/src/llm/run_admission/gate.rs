//! The run's model backend: every call starts its permit here, before any
//! byte leaves, and leaves a dispatch receipt with its request digest.
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_core::Stream;

use super::super::{
    BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmRequest,
    LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, LlmUsage, ModelId, SingleRouteBackend,
};
use super::admission::{RunDenied, RunInner};

/// Keys a provider adapter stamps into [`LlmUsage::raw_provider`] naming the
/// model the provider said it served, the ladder's first.
const SERVED_MODEL_KEYS: [&str; 2] = ["reported_model", "served_model"];

/// A model backend that serves one run on one route. It refuses a call whose
/// lease this run did not issue, that is closed or already used, or that names
/// another model or route than its permit, and a call that picks its model or
/// route through a param or provider option.
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
    route: String,
}

impl GatedBackend {
    pub(super) fn new(
        run: Arc<RunInner>,
        inner: Arc<dyn SingleRouteBackend>,
        route: String,
    ) -> Self {
        Self { run, inner, route }
    }

    /// Checks and starts the call's permit; returns the digest of the request
    /// that is about to leave.
    fn open(&self, request: &LlmRequest, lease: &BudgetLease, stream: bool) -> LlmResult<String> {
        let model = request.model.as_str();
        if let Some(key) = request.route_selector_override() {
            let reason = RunDenied::RouteOverride { key };
            self.run.refuse(Some(model), Some(lease), reason);
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if let Err(error) = self.inner.preflight(request, stream) {
            self.run
                .refuse(Some(model), Some(lease), RunDenied::BackendRefused);
            return Err(error);
        }
        let digest = request
            .canonical_hash_hex()
            .map_err(|_| LlmError::from(FatalLlmError::InvalidRequest))?;
        self.run.begin_dispatch(lease, model, &self.route)?;
        Ok(digest)
    }

    fn pending(&self, request: &LlmRequest, lease: &BudgetLease, digest: String) -> Pending<'_> {
        Pending {
            gate: self,
            dispatch: Some(Dispatch {
                lease: lease.clone(),
                model: request.model.clone(),
                digest,
            }),
        }
    }
}

struct Dispatch {
    lease: BudgetLease,
    model: ModelId,
    digest: String,
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
            self.gate.run.dispatched(
                &dispatch.lease,
                dispatch.model.as_str(),
                &self.gate.route,
                dispatch.digest,
                served_model,
                answered,
            );
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
