//! Wake envelopes and the host's drain.
//!
//! The engine publishes pending wakes and nothing more. Adapter install,
//! preference order and degrade are host-side, in the wake-adapters package
//! (ARCH-0067 §7, "Pinned 2026-08-05 — where the wake ladder lives").
//!
//! The host's acknowledgement of one envelope id (RC99) is recorded per
//! connection, in memory only: [`BoardStreamRegistry::acknowledge_wake`]
//! and [`BoardStreamRegistry::wake_delivery`].

use super::frames::StreamConnectionId;
use super::registry::BoardStreamRegistry;

/// Where one envelope a connection was handed stands (RC99, ARCH-0067
/// `#wake-envelope-id`). An acknowledgement says the wake arrived. It names
/// one occurrence, so a later failure of the same TASK, with its own
/// envelope id, reads `Handed` until it is acknowledged too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeDelivery {
    /// Drained to the host; no acknowledgement yet.
    Handed,
    /// The host acknowledged this occurrence.
    Acked,
}

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
    ///
    /// Each envelope handed over is recorded as [`WakeDelivery::Handed`]
    /// until the host acknowledges it ([`Self::acknowledge_wake`]).
    pub fn drain_wakes(&mut self, c: &StreamConnectionId) -> Vec<WakeEnvelope> {
        let Some(st) = self.connections.get_mut(c) else {
            return Vec::new();
        };
        let wakes: Vec<WakeEnvelope> = st.wakes.drain(..).collect();
        for wake in &wakes {
            st.record_handed(&wake.event_ref);
        }
        wakes
    }

    /// Records the host's acknowledgement of envelope id `event_ref` on
    /// connection `c`: that wake arrived (RC99). It names that one occurrence
    /// and never the TASK, so it acknowledges no other envelope. True when
    /// `c` was handed `event_ref`, now or already acknowledged. False, and
    /// nothing recorded, for an id `c` was never handed or no longer
    /// remembers. The record lives in memory only: a restart or a re-attach
    /// starts it empty (ARCH-0067 §7: no durable pending-wake store). Retry
    /// and degrade stay the host's.
    pub fn acknowledge_wake(&mut self, c: &StreamConnectionId, event_ref: &str) -> bool {
        let Some((_, delivery)) = self
            .connections
            .get_mut(c)
            .and_then(|st| st.handed.iter_mut().find(|(id, _)| id == event_ref))
        else {
            return false;
        };
        *delivery = WakeDelivery::Acked;
        true
    }

    /// Where envelope id `event_ref`, handed to connection `c`, stands.
    /// `None` for an id `c` was never handed or no longer remembers.
    #[must_use]
    pub fn wake_delivery(&self, c: &StreamConnectionId, event_ref: &str) -> Option<WakeDelivery> {
        self.connections
            .get(c)?
            .handed
            .iter()
            .find(|(id, _)| id == event_ref)
            .map(|(_, delivery)| *delivery)
    }
}

#[cfg(oneiron_test_support)]
impl BoardStreamRegistry {
    /// Routes TASK `task_ref`'s failure wake to owner `owner_ref`, as the
    /// own-task producer routes one, under envelope id `event_ref`, for
    /// `test_doors::wake_envelope_ack`. Never API.
    pub(crate) fn route_task_failure_for_test_door(
        &mut self,
        task_ref: &str,
        owner_ref: &str,
        event_ref: &str,
    ) -> super::events::RouteObservation {
        self.route_event(super::events::BoardEvent::OwnTaskFailed {
            event: super::provenance::VerifiedOwnTaskEvent {
                task_ref: task_ref.to_owned(),
                actor_ref: owner_ref.to_owned(),
                event_ref: event_ref.to_owned(),
            },
            line: format!("{task_ref} failed"),
        })
    }
}
