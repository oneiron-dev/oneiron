//! Retry spacing for the host workers that retry every failed try of an
//! attempt through the native retry door, with no cutoff.
//!
//! A held try that never clears (a persona the route names but the host
//! does not configure, a model world that withholds the source) would
//! otherwise mint a failed row and a successor at one flat interval for as
//! long as the work stays open. The wait grows with the tries instead, as
//! the workflow step runner reads the same setting, so the ledger grows by
//! a bounded number of rows a day and the work still runs once the hold
//! clears.

use oneiron::Vault;
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord};

/// The longest wait between two tries of one attempt, unless the configured
/// wait is longer.
pub(super) const RETRY_BACKOFF_CAP_SECS: u64 = 3_600;

/// When the next try of `attempt` may run: `backoff_secs` times the tries so
/// far, at most [`RETRY_BACKOFF_CAP_SECS`] or `backoff_secs` itself when that
/// is longer.
///
/// A retry mints a fresh row whose lease counter restarts at zero, so the
/// tries so far are the row's retry lineage
/// ([`AttemptQueue::retry_chain_depth`]) plus this one. A lineage that does
/// not read waits the longest wait, never the first one.
pub(super) fn retry_backoff_until(
    vault: &Vault,
    attempt: &AttemptRecord,
    backoff_secs: u64,
    now: u64,
) -> u64 {
    let cap = RETRY_BACKOFF_CAP_SECS.max(backoff_secs);
    let wait = match AttemptQueue::new(vault).retry_chain_depth(attempt.id) {
        Ok(depth) => backoff_secs
            .saturating_mul(u64::from(depth.saturating_add(1)))
            .min(cap),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                attempt = ?attempt.id,
                "attempt retry lineage did not read"
            );
            cap
        }
    };
    now.saturating_add(wait)
}
