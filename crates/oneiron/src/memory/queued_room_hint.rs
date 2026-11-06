//! Original room-turn positions for optional queued hints in this vault open.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryResult};
use crate::claim::{RoomTurnCeiling, TurnTerms, WeakTurnTerms};
use crate::{EntityId, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct LiveTurn {
    open: [u8; 16],
    serial: u64,
}

#[derive(Default)]
pub(crate) struct QueuedRoomHintRuntime(Mutex<LiveTurns>);

#[derive(Default)]
struct LiveTurns {
    next: u64,
    turns: BTreeMap<u64, WeakTurnTerms>,
}

impl QueuedRoomHintRuntime {
    fn capture(&self, open: [u8; 16], terms: &TurnTerms) -> Option<LiveTurn> {
        let mut live = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live.turns.retain(|_, terms| terms.upgrade().is_some());
        if let Some((&serial, _)) = live
            .turns
            .iter()
            .find(|(_, held)| held.upgrade().is_some_and(|held| held == *terms))
        {
            return Some(LiveTurn { open, serial });
        }
        let serial = live.next;
        live.next = serial.checked_add(1)?;
        live.turns.insert(serial, terms.downgrade());
        Some(LiveTurn { open, serial })
    }

    fn resolve(&self, open: [u8; 16], turn: LiveTurn) -> Option<TurnTerms> {
        let mut live = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live.turns.retain(|_, terms| terms.upgrade().is_some());
        if turn.open != open {
            return None;
        }
        live.turns.get(&turn.serial)?.upgrade()
    }
}

/// Semantic inputs of the original native room position, never its grants
/// or its roster. The live reference cannot be recovered from a room id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QueuedRoomHintReader {
    room: EntityId,
    caller: EntityId,
    branch: Option<EntityId>,
    personal: bool,
    turn: LiveTurn,
}

impl QueuedRoomHintReader {
    pub(super) fn capture(vault: &Vault, original: &RoomTurnCeiling) -> Option<Self> {
        Some(Self {
            room: original.room,
            caller: original.caller,
            branch: original.branch,
            personal: original.personal,
            turn: vault
                .queued_room_hints
                .capture(vault.store.open_nonce, &original.terms)?,
        })
    }

    pub(super) fn belongs_to(&self, actor: EntityId) -> bool {
        self.caller == actor
    }

    pub(super) fn bind<'v>(&self, memory: Memory<'v>) -> MemoryResult<Option<Memory<'v>>> {
        let Some(terms) = memory
            .vault
            .queued_room_hints
            .resolve(memory.vault.store.open_nonce, self.turn)
        else {
            return Ok(None);
        };
        let mut current = match self.branch {
            Some(thread) => memory.for_thread_projection(self.room, thread)?,
            None => memory.for_room_turn(self.room)?,
        };
        let ceiling = current
            .memory
            .room_turn
            .as_mut()
            .expect("a room projection is bound to its native ceiling");
        terms.meet(&ceiling.terms.get());
        ceiling.terms = terms;
        ceiling.personal = self.personal;
        Ok(Some(current.memory))
    }
}
