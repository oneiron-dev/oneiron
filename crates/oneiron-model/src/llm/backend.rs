//! Raw-call primitive: result aliases, the terminal-EOF stream wrapper, the host backend trait, and the budget admission token.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_core::Stream;
use oneiron_contracts::EntityId;

use super::inference_observation::InferenceObservations;
use super::{
    InferenceCallObservation, InferenceObservationId, LlmError, LlmRequest, LlmResponse,
    LlmStreamEvent, RetryableLlmError,
};

pub type LlmResult<T> = std::result::Result<T, LlmError>;

pub type LlmGenerateFuture<'a> = Pin<Box<dyn Future<Output = LlmResult<LlmResponse>> + Send + 'a>>;

pub type LlmStreamResult<'a> = LlmResult<LlmStream<'a>>;

/// Stream wrapper that makes [`LlmStreamEvent::Done`] the only successful EOF.
pub struct LlmStream<'a> {
    inner: Pin<Box<dyn Stream<Item = LlmResult<LlmStreamEvent>> + Send + 'a>>,
    terminal_seen: bool,
}

impl<'a> LlmStream<'a> {
    pub fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = LlmResult<LlmStreamEvent>> + Send + 'a,
    {
        Self {
            inner: Box::pin(stream),
            terminal_seen: false,
        }
    }
}

impl Stream for LlmStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminal_seen {
            return Poll::Ready(None);
        }

        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                if matches!(event, LlmStreamEvent::Done { .. }) {
                    this.terminal_seen = true;
                }
                Poll::Ready(Some(Ok(event)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.terminal_seen = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.terminal_seen = true;
                Poll::Ready(Some(Err(RetryableLlmError::StreamCut.into())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Raw-call primitive implemented by host-injected adapters.
///
/// The required [`BudgetLease`] argument makes budget admission visible in the
/// type signature. Budget policy, retry policy, durable memoization, and agent
/// loop behavior live above this trait.
pub trait LlmBackend: Send + Sync {
    /// Capability lookup for step policy; adapters resolve this from catalog data.
    fn supports(&self, _model: &super::ModelId, _capability: super::LlmCapability) -> bool {
        false
    }

    fn generate<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease)
    -> LlmGenerateFuture<'a>;

    /// Generates with the complete rows the request was read from, or `None`
    /// when any constituent is unknown. The default keeps an implementer's
    /// existing unsourced behavior; source-aware backends override it.
    fn generate_sourced<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
        _sources: Option<Vec<EntityId>>,
    ) -> LlmGenerateFuture<'a> {
        self.generate(request, lease)
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a>;
}

/// A backend whose one call is one request to one route: no retry, and no
/// fallback to another model or origin. A run admission's gate wraps only
/// these, so the permit it checks covers exactly the request that leaves. A
/// wire adapter is one only over a [`SingleSend`] transport.
pub trait SingleRouteBackend: LlmBackend {
    /// Every check this backend makes before it sends, with no I/O: the
    /// refusal its `generate` or `stream` would return for `request` before
    /// any byte leaves, or `Ok` when it would send.
    fn preflight(&self, request: &LlmRequest, stream: bool) -> LlmResult<()>;

    /// The digest of the exact request bytes `generate` or `stream` would send
    /// for `request`, for a backend that builds them before it sends (a
    /// credential broker's adapter, ARCH-0069 `#broker-digest`). A run's permit
    /// for the call binds it at admission and the gate checks it at dispatch,
    /// so the call sends only the bytes it was admitted for. `None`, the
    /// default, binds the call by its route and offer alone.
    fn request_digest(&self, request: &LlmRequest, stream: bool) -> LlmResult<Option<String>> {
        let _ = (request, stream);
        Ok(None)
    }

    /// How the credential broker that sends this backend's calls is kept
    /// apart from the daemon, for the dispatch receipt. `None`, the default,
    /// for a backend whose key, if any, no broker holds.
    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        None
    }
}

/// How a credential broker is kept apart from the daemon (ARCH-0069
/// `#broker-isolation`). A call's dispatch receipt names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerIsolation {
    /// The broker runs as its own OS user.
    SeparateUser,
    /// The broker shares the daemon's user: the run shows the unproven badge.
    SameUser,
}

/// A transport or runtime that makes one request per call: it never retries,
/// and never follows a redirect to another origin. Its author claims it; a
/// retrying transport stays below a ladder, never below a run's gate.
pub trait SingleSend {}

/// Opaque admission token issued by the budget guard.
#[derive(Clone)]
pub struct BudgetLease {
    pub(crate) id: String,
    // Allocation identity, not the caller's diagnostic ID, proves provenance.
    // Keeping it alive in leases prevents reuse after the issuing guard drops.
    pub(super) guard_identity: Arc<()>,
    /// What the call's physical requests measured (FIX 9065), shared by the
    /// lease's clones. Not part of its identity: equality and hash stay the
    /// id and the issuing guard.
    observations: Arc<InferenceObservations>,
}

impl fmt::Debug for BudgetLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BudgetLease").field("id", &self.id).finish()
    }
}

impl PartialEq for BudgetLease {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.guard_identity, &other.guard_identity)
    }
}

impl Eq for BudgetLease {}

impl std::hash::Hash for BudgetLease {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.id, state);
        std::hash::Hash::hash(&Arc::as_ptr(&self.guard_identity), state);
    }
}

impl BudgetLease {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn issued(id: impl Into<String>, guard_identity: Arc<()>) -> Self {
        Self {
            id: id.into(),
            guard_identity,
            observations: Arc::default(),
        }
    }

    /// Begins the observation of one physical request this lease's call sends
    /// (FIX 9065). An adapter begins one per request, before it leaves, and
    /// publishes what it measures through [`Self::observe_inference_call`]
    /// while the request runs, so a call cut before it returns still settles
    /// that evidence.
    #[must_use]
    pub fn begin_inference_observation(&self) -> InferenceObservationId {
        self.observations.begin()
    }

    /// Records what request `id` measured: its progress so far
    /// ([`InferenceCallObservation::Partial`]), or its final receipt
    /// ([`InferenceCallObservation::Final`]), in place of what it recorded
    /// before. A final receipt is never replaced by a partial one, and an id
    /// another lease began is ignored. A measurement no native source made is
    /// left absent, never zero.
    pub fn observe_inference_call(
        &self,
        id: InferenceObservationId,
        observation: InferenceCallObservation,
    ) {
        self.observations.observe(id, observation);
    }

    /// What this lease's requests measured, in the order they began; a request
    /// that recorded nothing is left out.
    #[must_use]
    pub fn inference_observations(&self) -> Vec<InferenceCallObservation> {
        self.observations.snapshot()
    }

    /// A lease no guard issued, for tests that need one without a budget. Compiled only
    /// under `cfg(test)` and the `test-hooks` / `test-support` features, which `oneiron`
    /// forwards from its own and enables only for tests.
    #[cfg(any(test, feature = "test-hooks", feature = "test-support"))]
    pub fn for_test(id: impl Into<String>) -> Self {
        Self::issued(id, Arc::new(()))
    }
}
