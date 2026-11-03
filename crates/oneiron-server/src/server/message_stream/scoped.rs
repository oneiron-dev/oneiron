//! The trusted scope of each message partial in the presence hub (FIX 9537),
//! kept apart from what clients write there. Only the host's stream relay
//! records one, from the scope its vault published with the frame; presence
//! a client writes, under any key, never adds, moves or drops one. A scope
//! lives while the hub holds its key, the tombstone its stream's clear left
//! included, and goes once the hub lets the key expire.
//!
//! It also keeps the release verdict of each scoped conversation for the
//! machines a destination names, at the vault write generation it was
//! judged at (FIX 11166): a partial fanning out to every socket is judged
//! once per generation, and any write — a world setting, a machine's
//! removal, a conversation moving worlds — moves the generation and every
//! verdict with it. Nothing here judges; the vault's hold does, per ask
//! the cache cannot answer.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use oneiron::EntityId;
use oneiron::authority::PeerMachine;
use oneiron::sync::{EphemeralStore, MessagePresenceScope, decode_ephemeral_states};

/// Verdicts kept at one write generation; past it, they are judged again.
const MAX_VERDICTS: usize = 4096;

/// One destination machine as a verdict is keyed by: the machine its proof
/// stands on and the key it proved, or none for one nobody proved.
type PeerKey = Option<(EntityId, [u8; 32])>;

fn peer_keys(peers: &[PeerMachine]) -> Vec<PeerKey> {
    peers
        .iter()
        .map(|peer| match peer {
            PeerMachine::Proven { machine, key } => Some((*machine, *key)),
            PeerMachine::Unknown => None,
        })
        .collect()
}

/// The release verdicts of one vault write generation.
#[derive(Default)]
struct ReleaseVerdicts {
    generation: usize,
    may: HashMap<(EntityId, Vec<PeerKey>), bool>,
}

/// The hub's message partials, by presence key, with their scope.
#[derive(Default)]
pub(crate) struct MessageScopes {
    scopes: Mutex<HashMap<String, MessagePresenceScope>>,
    verdicts: Mutex<ReleaseVerdicts>,
}

impl MessageScopes {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, MessagePresenceScope>> {
        self.scopes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn verdicts(&self) -> MutexGuard<'_, ReleaseVerdicts> {
        self.verdicts.lock().unwrap_or_else(PoisonError::into_inner)
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

    /// Whether `conversation`'s partials may go to `peers`, as judged at
    /// vault write `generation`; `None` when this generation has no
    /// verdict for it yet.
    pub(crate) fn verdict(
        &self,
        generation: usize,
        conversation: EntityId,
        peers: &[PeerMachine],
    ) -> Option<bool> {
        let verdicts = self.verdicts();
        if verdicts.generation != generation {
            return None;
        }
        verdicts.may.get(&(conversation, peer_keys(peers))).copied()
    }

    /// Keeps the verdict `may` for `conversation` to `peers`, judged at
    /// vault write `generation`. A verdict from an older generation than
    /// the held one is already stale and kept nowhere.
    pub(crate) fn record_verdict(
        &self,
        generation: usize,
        conversation: EntityId,
        peers: &[PeerMachine],
        may: bool,
    ) {
        let mut verdicts = self.verdicts();
        if generation < verdicts.generation {
            return;
        }
        if verdicts.generation != generation || verdicts.may.len() >= MAX_VERDICTS {
            verdicts.generation = generation;
            verdicts.may.clear();
        }
        verdicts.may.insert((conversation, peer_keys(peers)), may);
    }
}
