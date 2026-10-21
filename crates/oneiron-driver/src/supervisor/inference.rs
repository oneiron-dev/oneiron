//! The model-worker probe seam (FIX 8314, INFERENCE R1): what one worker is
//! declared to be, and the one call that says whether it serves that. The
//! values it reads and returns are the engine's
//! ([`oneiron::llm::WorkerReadiness`] and its kin); this module only names
//! the seam. Nothing here runs a probe: no loop, timer, retry or launch, and
//! the wake supervisor's loop, gate and restart backoff are not a worker
//! manager.
use std::future::Future;
use std::pin::Pin;

use oneiron::llm::{CacheIdentity, ModelId, WorkerKind, WorkerMode, WorkerReadiness};

/// One model worker as its declaration pins it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSpec {
    /// The worker's stable, validated config key; not an epoch.
    pub worker_id: String,
    /// The engine model the worker serves.
    pub model: ModelId,
    pub kind: WorkerKind,
    pub mode: WorkerMode,
    /// The pins an answer must match: an expected identity, never an
    /// observed one. Its model and runtime are readiness policy, and its
    /// template where the worker renders one (its tokenizer when given);
    /// its execution mode, cache mode and epoch are not.
    pub expected: CacheIdentity,
}

/// A probe's answer, in flight.
pub type WorkerProbeFuture<'a> = Pin<Box<dyn Future<Output = WorkerReadiness> + Send + 'a>>;

/// Whether one worker serves its named model and build: an actual answer
/// naming `expected`'s model on its route, with the pinned identity observed,
/// is `Ready`; missing evidence is `Unverified`; contradicting evidence is
/// `Failed`. An open port or a listing is never `Ready`.
pub trait WorkerProbe: Send + Sync {
    fn probe<'a>(&'a self, expected: &'a WorkerSpec) -> WorkerProbeFuture<'a>;
}
