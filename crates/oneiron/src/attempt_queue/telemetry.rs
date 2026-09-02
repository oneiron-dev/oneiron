//! Process-local cleanup counters, cleanup span emission, and the shared
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

static ATTEMPT_QUEUE_CLEANUP_RUNS: AtomicU64 = AtomicU64::new(0);
static ATTEMPT_QUEUE_CLEANUP_STALE_REQUEUED: AtomicU64 = AtomicU64::new(0);
static ATTEMPT_QUEUE_CLEANUP_RETRY_REASON_COUNTERS: [AtomicU64; ATTEMPT_QUEUE_RETRY_REASON_COUNT] =
    [AtomicU64::new(0), AtomicU64::new(0)];

/// In-process cleanup counters with stable, content-free labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptQueueCleanupMetricsSnapshot {
    pub runs: u64,
    pub stale_requeued: u64,
    pub retry_reasons: [AttemptQueueRetryReasonCount; ATTEMPT_QUEUE_RETRY_REASON_COUNT],
}

/// Returns process-local attempt-queue cleanup counters.
#[must_use]
pub fn attempt_queue_cleanup_metrics_snapshot() -> AttemptQueueCleanupMetricsSnapshot {
    AttemptQueueCleanupMetricsSnapshot {
        runs: ATTEMPT_QUEUE_CLEANUP_RUNS.load(AtomicOrdering::Relaxed),
        stale_requeued: ATTEMPT_QUEUE_CLEANUP_STALE_REQUEUED.load(AtomicOrdering::Relaxed),
        retry_reasons: AttemptQueueRetryReason::metric_values().map(|reason| {
            AttemptQueueRetryReasonCount {
                reason,
                count: ATTEMPT_QUEUE_CLEANUP_RETRY_REASON_COUNTERS[reason.metric_index()]
                    .load(AtomicOrdering::Relaxed),
            }
        }),
    }
}

pub(super) fn invalid_transition(action: &'static str, state: &'static str) -> Error {
    Error::InvalidAttemptQueueTransition { action, state }
}

pub(super) fn record_attempt_queue_cleanup_metrics(report: &AttemptQueueCleanupReport) {
    ATTEMPT_QUEUE_CLEANUP_RUNS.fetch_add(1, AtomicOrdering::Relaxed);
    ATTEMPT_QUEUE_CLEANUP_STALE_REQUEUED.fetch_add(report.stale_requeued, AtomicOrdering::Relaxed);
    for counter in report.retry_reasons {
        ATTEMPT_QUEUE_CLEANUP_RETRY_REASON_COUNTERS[counter.reason.metric_index()]
            .fetch_add(counter.count, AtomicOrdering::Relaxed);
    }
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
        retry_lease_timeout,
        retry_backoff,
        "attempt queue cleanup completed"
    );
}
