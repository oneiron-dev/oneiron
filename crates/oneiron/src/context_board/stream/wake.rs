//! Wake envelopes and the host's drain.
//!
//! The engine publishes pending wakes and nothing more. Adapter install,
//! preference order and degrade are host-side, in the wake-adapters package
//! (ARCH-0067 §7, "Pinned 2026-08-05 — where the wake ladder lives").

use super::frames::StreamConnectionId;
use super::registry::BoardStreamRegistry;

#[doc(hidden)]
pub use oneiron_verb_wire::context_board::stream::wake::WakeEnvelope;

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
