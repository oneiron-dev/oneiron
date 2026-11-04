//! Per-vault cleanup counters, cleanup span emission, and the shared
//! invalid-transition error constructor.
//!
//! The counters carry stable, content-free labels only: a reason class never
//! names an attempt, an actor, or a payload.

use crate::error::Error;

use super::types::{AttemptQueueCleanupReport, AttemptQueueRetryReason, CleanupAttemptLeases};
use crate::error::ArtifactError;

pub(crate) use crate::store::attempt_cleanup::AttemptQueueCleanupMetrics;
pub use crate::store::attempt_cleanup::AttemptQueueCleanupMetricsSnapshot;

pub(super) fn invalid_transition(action: &'static str, state: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAttemptQueueTransition { action, state })
}

pub(super) fn emit_attempt_queue_cleanup_span(
    input: &CleanupAttemptLeases,
    report: &AttemptQueueCleanupReport,
) {
    let retry_lease_timeout = report.retry_reason_count(AttemptQueueRetryReason::LeaseTimeout);
    let retry_backoff = report.retry_reason_count(AttemptQueueRetryReason::RetryBackoff);
    let retry_due_later = report.retry_reason_count(AttemptQueueRetryReason::DueLater);
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
        retry_due_later,
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
        retry_due_later,
        "attempt queue cleanup completed"
    );
}
