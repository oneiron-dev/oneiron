//! One chat compaction flight per conversation at a time (FIX 5030).
//!
//! Each answer past its threshold builds its own driver, so no driver sees
//! another answer's flight. The vault-bound writer factory holds the set of
//! conversations whose flight is held now. An answer claims its
//! conversation before it captures its call or queues its flight, and the
//! claim rides the queued pass through sealing, its hook retry, its paid
//! tries and its landing. A second answer in the same conversation while
//! the claim is held does not fly: its log stays raw, and the next turn
//! past the threshold tries again. Dropping the claim releases it on every
//! exit, a refusal, a pass that never ran and an unwind included. The set is
//! held in memory only, so a process that ends leaves no conversation
//! claimed. The durable epoch boundary, checked at sealing and again in the
//! mint, stays the authority on what lands.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::EntityId;

/// The conversations of one vault whose chat compaction flight is held now.
#[derive(Default)]
pub(super) struct ChatFlightClaims {
    held: Arc<Mutex<BTreeSet<EntityId>>>,
}

impl ChatFlightClaims {
    /// Claims `conversation`'s one flight; `None` while another flight of
    /// that conversation holds it. Never waits.
    pub(super) fn claim(&self, conversation: EntityId) -> Option<ChatFlightClaim> {
        let inserted = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(conversation);
        inserted.then(|| ChatFlightClaim {
            held: Arc::clone(&self.held),
            conversation,
        })
    }
}

/// A held flight claim; dropping it releases its conversation.
pub(super) struct ChatFlightClaim {
    held: Arc<Mutex<BTreeSet<EntityId>>>,
    conversation: EntityId,
}

impl Drop for ChatFlightClaim {
    fn drop(&mut self) {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.conversation);
    }
}
