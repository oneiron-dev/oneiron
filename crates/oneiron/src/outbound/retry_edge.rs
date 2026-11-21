//! The edge a dispatch's receipt holds a send to (FIX 11660): the `retry_at`
//! a delivery-window hold, a full count-bound budget window or a provider's
//! wait names, vault-clock seconds. A caller that keeps the send and tries
//! it again later waits for it; an immediate act answers it.

use super::OutboundDispatchResult;

/// The receipt field every hold edge is written under.
const RETRY_AT_FIELD: &str = "retry_at";

/// The least wait, in seconds, before a kept send is tried again.
const KEPT_SEND_RETRY_FLOOR_SECS: u64 = 60;

/// When a send a dispatcher keeps at `now` is tried again, vault-clock
/// seconds: a minute from `now`, and never before `edge`, the
/// [`OutboundDispatchResult::retry_at`] of the dispatch that kept it.
#[must_use]
pub(crate) fn kept_send_backoff_until(now: u64, edge: Option<u64>) -> u64 {
    now.saturating_add(KEPT_SEND_RETRY_FLOOR_SECS)
        .max(edge.unwrap_or(0))
}

impl OutboundDispatchResult {
    /// When this dispatch's receipt says the send may be tried again,
    /// vault-clock seconds: `None` when it names no edge.
    #[must_use]
    pub fn retry_at(&self) -> Option<u64> {
        self.receipt
            .fields
            .get(RETRY_AT_FIELD)
            .and_then(|edge| edge.parse().ok())
    }
}
