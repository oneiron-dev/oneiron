//! The presence hub's charge on the server's retained-memory line (rule 5,
//! census row 19). Every change to the hub, from a socket or from this
//! server's own message streams, is checked, charged and applied under one
//! guard, and expiry gives its bytes back. Presence larger than the whole
//! line runs alone; beside other retained state, a full line is the memory
//! floor, the one refusal.
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::sync::EphemeralStore;

use crate::byte_line::{ByteLine, HeldBytes};
use crate::wire_telemetry::LimitQuestions;

pub(crate) struct PresenceCharge {
    line: Arc<ByteLine>,
    questions: Arc<LimitQuestions>,
    held: Mutex<HeldBytes>,
}

/// The hub's charge, held for one change.
pub(crate) struct PresenceGuard<'a> {
    charge: &'a PresenceCharge,
    held: MutexGuard<'a, HeldBytes>,
}

impl PresenceCharge {
    pub(crate) fn new(line: Arc<ByteLine>, questions: Arc<LimitQuestions>) -> Self {
        let held = Mutex::new(line.empty());
        Self {
            line,
            questions,
            held,
        }
    }

    /// The guard one change to the hub holds from its first read of the hub
    /// to its apply.
    pub(crate) fn lock(&self) -> PresenceGuard<'_> {
        PresenceGuard {
            charge: self,
            held: self.held.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }
}

impl PresenceGuard<'_> {
    /// Charges the hub at `bytes`. `false` is the memory floor: the hub keeps
    /// its charge and the change must not be applied.
    pub(crate) fn fit(&mut self, bytes: usize) -> bool {
        self.charge
            .line
            .try_resize(&mut self.held, bytes, &self.charge.questions)
    }

    /// Drops expired presence from `hub` and gives its bytes back.
    pub(crate) fn expire(&mut self, hub: &EphemeralStore) {
        hub.remove_outdated();
        // Shrinking always fits.
        let _ = self.fit(hub.encode_all().len());
    }
}
