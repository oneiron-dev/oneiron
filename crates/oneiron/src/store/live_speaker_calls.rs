//! Per-room live voice-call registration index.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::entity_id::EntityId;

/// The vault's live room-bound voice calls, by room.
#[derive(Debug, Default)]
pub(crate) struct LiveSpeakers {
    rooms: Mutex<BTreeMap<EntityId, LiveRoom>>,
}

#[derive(Debug, Default)]
struct LiveRoom {
    /// Moves on each register and end. A room keeps it after its last call
    /// ends, so a later call never reads as an earlier one did.
    revision: u64,
    /// Each live call's token and the roster ref its host heard it under.
    calls: BTreeMap<EntityId, Option<String>>,
}

impl LiveSpeakers {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<EntityId, LiveRoom>> {
        self.rooms.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn register(&self, room: EntityId, call: EntityId, roster_ref: Option<String>) {
        let mut rooms = self.lock();
        let live = rooms.entry(room).or_default();
        live.revision = live.revision.saturating_add(1);
        live.calls.insert(call, roster_ref);
    }

    /// Token-exact and idempotent: an ended call never removes another.
    pub(crate) fn remove(&self, room: EntityId, call: EntityId) {
        let mut rooms = self.lock();
        if let Some(live) = rooms.get_mut(&room)
            && live.calls.remove(&call).is_some()
        {
            live.revision = live.revision.saturating_add(1);
        }
    }

    pub(crate) fn snapshot(&self, room: EntityId) -> (u64, Vec<(EntityId, Option<String>)>) {
        self.lock().get(&room).map_or((0, Vec::new()), |live| {
            (
                live.revision,
                live.calls
                    .iter()
                    .map(|(call, roster)| (*call, roster.clone()))
                    .collect(),
            )
        })
    }
}
