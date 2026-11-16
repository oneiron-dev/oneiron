//! Doors for `tests/settle_backoff_rules.rs` (UC-09 PR E): the delay before
//! a failed tagging marker's next retry, and the time a notice dispatcher
//! retries a send it keeps.

use crate::tagging::TaggingBackoff;

/// The delay, in store-clock seconds, before the retry that follows
/// `prior_retries` earlier retries under `backoff`.
#[must_use]
pub fn tagging_retry_delay_secs(backoff: TaggingBackoff, prior_retries: u32) -> u64 {
    backoff.delay_secs(prior_retries)
}

/// The `backoff_until` a notice dispatcher (trusted-contact notice, e-sign
/// notice) writes when it keeps a send for a later retry at `now`, its
/// receipt naming `edge` as its `retry_at` (FIX 11660). Both dispatchers
/// write this expression.
#[must_use]
pub fn kept_send_backoff_until(now: u64, edge: Option<u64>) -> u64 {
    now.saturating_add(60).max(edge.unwrap_or(0))
}
