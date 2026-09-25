//! Per-request stage-boundary budgets. No wall-clock promise about a running stage.
use crate::rerank::Reranker;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// An anytime budget shared by the stages of exactly one retrieval.
/// A stage already in progress completes; admission and final filters always run.
/// `was_cut_short` means requested work was actually skipped, not just that time passed.
pub struct RetrievalDeadline {
    at: Instant,
    cut_short: AtomicBool,
    cancelled: AtomicBool,
}
impl RetrievalDeadline {
    /// Raw monotonic deadline, including deadlines that already passed.
    pub fn at(at: Instant) -> Self {
        Self {
            at,
            cut_short: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }
    /// Convenience budget for anytime retrieval.
    pub fn after(duration: Duration) -> Self {
        Self::at(Instant::now() + duration)
    }
    /// Whether execution skipped a requested stage at a budget boundary.
    pub fn was_cut_short(&self) -> bool {
        self.cut_short.load(Ordering::Relaxed)
    }
    /// Requests the best admitted pack at the next stage boundary.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
    pub(crate) fn stop_before_stage(&self) -> bool {
        if self.cancelled.load(Ordering::Relaxed) || Instant::now() >= self.at {
            self.cut_short.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

/// Additional execution inputs for the regular memory recall pipeline.
/// No implicit embedding or model is invented when a host supplies neither.
#[derive(Default)]
pub struct RecallExecution<'a> {
    pub deadline: Option<&'a RetrievalDeadline>,
    pub reranker: Option<&'a dyn Reranker>,
    pub embedding: Option<&'a [f32]>,
    pub phonetic_codes: &'a [&'a str],
}
