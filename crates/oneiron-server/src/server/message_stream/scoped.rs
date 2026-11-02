//! The trusted scope of each message partial in the presence hub (FIX 9537),
//! kept apart from what clients write there. Only the host's stream relay
//! records one, from the scope its vault published with the frame; presence
//! a client writes, under any key, never adds, moves or drops one. A scope
//! lives while the hub holds its key, the tombstone its stream's clear left
//! included, and goes once the hub lets the key expire.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use oneiron::EntityId;
use oneiron::sync::{EphemeralStore, MessagePresenceScope, decode_ephemeral_states};

/// The hub's message partials, by presence key, with their scope.
#[derive(Default)]
pub(crate) struct MessageScopes(Mutex<HashMap<String, MessagePresenceScope>>);

impl MessageScopes {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, MessagePresenceScope>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `scope` for the hub's presence key `key`, before its frame is
    /// applied, so no reader finds the partial in the hub unscoped. A clear
    /// of an older generation leaves a newer generation's scope as it is.
    pub(super) fn record(&self, key: &str, scope: MessagePresenceScope) {
        let mut scopes = self.lock();
        if scope.cleared
            && scopes
                .get(key)
                .is_some_and(|held| held.generation != scope.generation)
        {
            return;
        }
        scopes.insert(key.to_owned(), scope);
    }

    /// The conversation whose message stream wrote `key`, if one did.
    pub(crate) fn conversation(&self, key: &str) -> Option<EntityId> {
        self.lock().get(key).map(|scope| scope.conversation)
    }

    /// Whether the hub holds no message partial: all its presence goes as
    /// it always went.
    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Drops each scope whose key `hub` no longer holds.
    pub(super) fn expire(&self, hub: &EphemeralStore) {
        self.lock().retain(|key, _| {
            decode_ephemeral_states(&hub.encode(key)).is_ok_and(|states| !states.is_empty())
        });
    }
}
