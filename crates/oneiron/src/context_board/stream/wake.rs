//! Wake envelopes and the host's drain.
//!
//! The engine publishes pending wakes and nothing more. Adapter install,
//! preference order and degrade are host-side, in the wake-adapters package
//! (ARCH-0067 §7, "Pinned 2026-08-05 — where the wake ladder lives").

use super::frames::StreamConnectionId;
use super::registry::BoardStreamRegistry;

/// One pending wake, minted from a committed TASK or from a pending
/// diary-read review (FIX 2879).
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct WakeEnvelope {
    /// The envelope id, `<task id>:<arrived|failed>:<revision>` (ARCH-0067
    /// `#wake-envelope-id`). The revision names the committed TASK state the
    /// event was minted from, so a task that fails, reopens and fails again
    /// queues two envelopes with two ids, and an acknowledgement names one
    /// occurrence. A review wake's id is its review's INBOX handle,
    /// `diary-read:<agent>:<request>`.
    pub event_ref: String,
    /// The TASK a TASK wake names; empty on a review wake, which names its
    /// review in `review_ref` instead.
    pub task_ref: String,
    pub actor_ref: String,
    pub line: String,
    /// The diary-read request a review wake names, waiting on `actor_ref`'s
    /// answer through `self.memory.diary.review`. Absent on every TASK wake.
    /// The wake carries no reader, reason or diary content and grants no read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_ref: Option<String>,
}

impl BoardStreamRegistry {
    /// Peeks the oldest queued wake without taking it. `None` for a missing
    /// or empty connection.
    #[must_use]
    pub fn next_wake(&self, c: &StreamConnectionId) -> Option<WakeEnvelope> {
        self.connections.get(c)?.wakes.front().cloned()
    }

    /// Hands the host every wake queued for one connection, oldest first, and
    /// keeps none: each envelope is handed over once. Empty for a missing or
    /// empty connection.
    ///
    /// An envelope is a notice, not a read grant. It was admitted under the
    /// connection's read of the TASK when it was published, and the TASK may
    /// since have been erased or hidden from that credential. The adapter that
    /// delivers it must read the TASK again at delivery, under the same
    /// predicate, and drop the envelope when the read says no, as the carrier
    /// drain does for each queued `tasks:` line. A review wake is read again
    /// as its reviewed agent's still pending request
    /// ([`super::PendingDiaryReview::is_pending`]) and dropped once answered.
    /// A failed delivery is the host's to retry or degrade; the TASK or the
    /// review row stays in the vault as the durable mailbox.
    pub fn drain_wakes(&mut self, c: &StreamConnectionId) -> Vec<WakeEnvelope> {
        self.connections
            .get_mut(c)
            .map(|st| st.wakes.drain(..).collect())
            .unwrap_or_default()
    }
}
