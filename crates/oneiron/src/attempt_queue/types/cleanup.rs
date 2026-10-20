//! Lease-cleanup input and report types for the attempt queue, split from
//! [`super`] by move only.

use super::ATTEMPT_QUEUE_RETRY_REASON_COUNT;

/// Input for returning stale leased attempts to the ready index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupAttemptLeases {
    /// Current wall-clock seconds chosen by the caller.
    pub now: u64,
    /// A leased attempt expires when `now - updated_at >= lease_timeout_secs`.
    pub lease_timeout_secs: u64,
}

/// Privacy-stable retry reason classes reported by attempt-queue cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttemptQueueRetryReason {
    LeaseTimeout,
    RetryBackoff,
    /// A first try (no `retry_of`) scheduled for a later readiness instant:
    /// it waits on its own schedule, not on a retry's backoff (FIX 6106).
    DueLater,
}

impl AttemptQueueRetryReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseTimeout => "lease_timeout",
            Self::RetryBackoff => "retry_backoff",
            Self::DueLater => "due_later",
        }
    }

    pub(in crate::attempt_queue) const fn metric_index(self) -> usize {
        match self {
            Self::LeaseTimeout => 0,
            Self::RetryBackoff => 1,
            Self::DueLater => 2,
        }
    }

    pub(in crate::attempt_queue) const fn metric_values() -> [Self; ATTEMPT_QUEUE_RETRY_REASON_COUNT]
    {
        [Self::LeaseTimeout, Self::RetryBackoff, Self::DueLater]
    }
}

/// Count for one privacy-stable retry reason class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptQueueRetryReasonCount {
    pub reason: AttemptQueueRetryReason,
    pub count: u64,
}

impl AttemptQueueRetryReasonCount {
    const fn zero(reason: AttemptQueueRetryReason) -> Self {
        Self { reason, count: 0 }
    }
}

/// Queue cleanup report shaped for runner and run-tree surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptQueueCleanupReport {
    pub pending: u64,
    pub running: u64,
    pub failed: u64,
    pub done: u64,
    pub stale_requeued: u64,
    /// Landing rows whose lease expired mid-landing and were force-cancelled.
    /// A landing cannot be requeued as ordinary work, so it cannot be part of
    /// `stale_requeued`.
    pub landing_force_cancelled: u64,
    /// Rows that stopped without delivering and without being stopped.
    ///
    /// A sub-count of `done`, exactly like `landing_force_cancelled`: an
    /// abandoned row is settled terminal work, so folding it into `failed`
    /// would report a fault nobody observed, and leaving it only inside `done`
    /// would hide a stopped executor behind a success-shaped counter.
    pub abandoned: u64,
    pub retry_reasons: [AttemptQueueRetryReasonCount; ATTEMPT_QUEUE_RETRY_REASON_COUNT],
}

impl Default for AttemptQueueCleanupReport {
    fn default() -> Self {
        Self {
            pending: 0,
            running: 0,
            failed: 0,
            done: 0,
            stale_requeued: 0,
            landing_force_cancelled: 0,
            abandoned: 0,
            retry_reasons: AttemptQueueRetryReason::metric_values()
                .map(AttemptQueueRetryReasonCount::zero),
        }
    }
}

impl AttemptQueueCleanupReport {
    #[must_use]
    pub fn retry_reason_count(&self, reason: AttemptQueueRetryReason) -> u64 {
        self.retry_reasons[reason.metric_index()].count
    }

    pub(in crate::attempt_queue) fn increment_retry_reason(
        &mut self,
        reason: AttemptQueueRetryReason,
    ) {
        self.retry_reasons[reason.metric_index()].count += 1;
    }
}
