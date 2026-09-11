//! Per-vault cleanup counters, cleanup span emission, and the shared
//! invalid-transition error constructor.
//!
//! The counters carry stable, content-free labels only: a reason class never
//! names an attempt, an actor, or a payload.

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::error::Error;

use super::types::{
    ATTEMPT_QUEUE_RETRY_REASON_COUNT, AttemptQueueCleanupReport, AttemptQueueRetryReason,
    AttemptQueueRetryReasonCount, CleanupAttemptLeases,
};
use crate::error::ArtifactError;

/// One vault's attempt-queue cleanup counters.
///
/// Owned by that vault's store handle (`StoreCore::diagnostics`), so a cleanup
/// run on one vault never moves the number a reader of another vault sees.
pub(crate) struct AttemptQueueCleanupMetrics {
    runs: AtomicU64,
    stale_requeued: AtomicU64,
    retry_reasons: [AtomicU64; ATTEMPT_QUEUE_RETRY_REASON_COUNT],
}

impl Default for AttemptQueueCleanupMetrics {
    fn default() -> Self {
        Self {
            runs: AtomicU64::new(0),
            stale_requeued: AtomicU64::new(0),
            retry_reasons: [const { AtomicU64::new(0) }; ATTEMPT_QUEUE_RETRY_REASON_COUNT],
        }
    }
}

impl AttemptQueueCleanupMetrics {
    /// Returns this vault's attempt-queue cleanup counters.
    #[must_use]
    pub(crate) fn snapshot(&self) -> AttemptQueueCleanupMetricsSnapshot {
        AttemptQueueCleanupMetricsSnapshot {
            runs: self.runs.load(AtomicOrdering::Relaxed),
            stale_requeued: self.stale_requeued.load(AtomicOrdering::Relaxed),
            retry_reasons: AttemptQueueRetryReason::metric_values().map(|reason| {
                AttemptQueueRetryReasonCount {
                    reason,
                    count: self.retry_reasons[reason.metric_index()].load(AtomicOrdering::Relaxed),
                }
            }),
        }
    }

    pub(super) fn record(&self, report: &AttemptQueueCleanupReport) {
        self.runs.fetch_add(1, AtomicOrdering::Relaxed);
        self.stale_requeued
            .fetch_add(report.stale_requeued, AtomicOrdering::Relaxed);
        for counter in report.retry_reasons {
            self.retry_reasons[counter.reason.metric_index()]
                .fetch_add(counter.count, AtomicOrdering::Relaxed);
        }
    }
}

/// One vault's cleanup counters with stable, content-free labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptQueueCleanupMetricsSnapshot {
    pub runs: u64,
    pub stale_requeued: u64,
    pub retry_reasons: [AttemptQueueRetryReasonCount; ATTEMPT_QUEUE_RETRY_REASON_COUNT],
}

pub(super) fn invalid_transition(action: &'static str, state: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAttemptQueueTransition { action, state })
}

pub(super) fn emit_attempt_queue_cleanup_span(
    input: &CleanupAttemptLeases,
    report: &AttemptQueueCleanupReport,
) {
    let retry_lease_timeout = report.retry_reason_count(AttemptQueueRetryReason::LeaseTimeout);
    let retry_backoff = report.retry_reason_count(AttemptQueueRetryReason::RetryBackoff);
    let span = tracing::info_span!(
        target: "oneiron::attempt_queue",
        "attempt_queue_cleanup",
        lease_timeout_secs = input.lease_timeout_secs,
        pending = report.pending,
        running = report.running,
        failed = report.failed,
        done = report.done,
        stale_requeued = report.stale_requeued,
        landing_force_cancelled = report.landing_force_cancelled,
        abandoned = report.abandoned,
        retry_lease_timeout,
        retry_backoff,
    );
    let _entered = span.enter();
    tracing::info!(
        target: "oneiron::attempt_queue",
        pending = report.pending,
        running = report.running,
        failed = report.failed,
        done = report.done,
        stale_requeued = report.stale_requeued,
        landing_force_cancelled = report.landing_force_cancelled,
        abandoned = report.abandoned,
        retry_lease_timeout,
        retry_backoff,
        "attempt queue cleanup completed"
    );
}
