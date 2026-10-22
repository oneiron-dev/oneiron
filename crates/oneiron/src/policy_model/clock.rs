//! One policy call's clock (FIX 10034; ARCH-0036:135, the owner's ruling of
//! 2026-10-16). It is made once at a logical entry and borrowed by every
//! attempt, read, safeguard read and notes leg under that entry. A
//! stale-policy retry derives its verdict again on the SAME clock: it never
//! restarts the configured ladder budget or the safeguard read's budget. The
//! budgets are the ones already configured; the clock adds no deadline of
//! its own, and separate decisions keep separate clocks.
use std::time::{Duration, Instant};

use crate::retrieval_depth::RetrievalDeadline;

/// When one policy call started.
#[derive(Debug, Clone, Copy)]
pub(super) struct PolicyCallClock {
    started: Instant,
}

impl PolicyCallClock {
    /// The clock of a call starting now.
    pub(super) fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    /// The hard deadline `budget` after the call's start, as the shared
    /// ladder reads one: a retry gets what is left, never a fresh budget.
    pub(super) fn deadline(&self, budget: Duration) -> RetrievalDeadline {
        RetrievalDeadline::hard(self.started, budget)
    }

    /// Whether one more read may still start inside `budget`, as the ladder
    /// decides it for a measurement.
    pub(super) fn may_start(&self, budget: Duration) -> bool {
        self.deadline(budget).decision_may_start()
    }
}
