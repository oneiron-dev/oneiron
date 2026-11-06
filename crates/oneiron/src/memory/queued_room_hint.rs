//! Original room-turn positions for optional queued hints in this vault open.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryResult};
use crate::attempt_queue::AttemptId;
use crate::claim::{RoomTurnCeiling, TurnTerms, WeakTurnTerms};
use crate::store::Store;
use crate::{EntityId, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct LiveTurn {
    open: [u8; 16],
    serial: u64,
}

#[derive(Clone, Default)]
pub(crate) struct QueuedRoomHintRuntime(Arc<Mutex<LiveTurns>>);

#[derive(Default)]
struct LiveTurns {
    next: u64,
    turns: BTreeMap<u64, WeakTurnTerms>,
    attempts: BTreeMap<AttemptId, AttemptTurns>,
}

#[derive(Default)]
struct AttemptTurns {
    committed: Option<Arc<StagedTurns>>,
    staged: Vec<Weak<StagedTurns>>,
}

struct StagedTurns {
    _terms: Vec<TurnTerms>,
    retired: AtomicBool,
}

/// Only the real transaction owns an uncommitted node. The runtime has a
/// weak reference so a later commit can retire that exact node, even before
/// this transaction's successful-commit callback runs.
struct TurnPublication {
    runtime: QueuedRoomHintRuntime,
    next: Option<Arc<StagedTurns>>,
    prior: Vec<Arc<StagedTurns>>,
    id: AttemptId,
}

impl TurnPublication {
    fn publish(self) {
        let mut live = self
            .runtime
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(attempt) = live.attempts.get_mut(&self.id) else {
            return;
        };
        for node in &self.prior {
            node.retired.store(true, Ordering::Relaxed);
            if attempt
                .committed
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, node))
            {
                attempt.committed = None;
            }
        }
        if let Some(node) = &self.next {
            if !node.retired.load(Ordering::Relaxed) {
                attempt.committed = Some(Arc::clone(node));
            }
        }
    }
}

impl Drop for TurnPublication {
    fn drop(&mut self) {
        self.next = None;
        self.prior.clear();
        let mut live = self
            .runtime
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live.attempts.retain(|_, attempt| {
            attempt.staged.retain(|node| node.strong_count() != 0);
            attempt.committed.is_some() || !attempt.staged.is_empty()
        });
    }
}

impl QueuedRoomHintRuntime {
    pub(crate) fn stage(&self, txn: &mut heed::RwTxn<'_>, id: AttemptId, terms: Vec<TurnTerms>) {
        let mut live = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = (!terms.is_empty()).then(|| {
            Arc::new(StagedTurns {
                _terms: terms,
                retired: AtomicBool::new(false),
            })
        });
        if next.is_none() && !live.attempts.contains_key(&id) {
            return;
        }
        let attempt = live.attempts.entry(id).or_default();
        attempt.staged.retain(|node| node.strong_count() != 0);
        let prior = attempt.staged.iter().filter_map(Weak::upgrade).collect();
        if let Some(node) = &next {
            attempt.staged.push(Arc::downgrade(node));
        }
        drop(live);
        let publication = TurnPublication {
            runtime: self.clone(),
            next,
            prior,
            id,
        };
        txn.on_commit(move || publication.publish());
    }

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
                .store
                .queued_room_hints
                .capture(vault.store.open_nonce, &original.terms)?,
        })
    }

    pub(super) fn belongs_to(&self, actor: EntityId) -> bool {
        self.caller == actor
    }

    pub(super) fn hold_turn(&self, store: &Store) -> Option<TurnTerms> {
        store.queued_room_hints.resolve(store.open_nonce, self.turn)
    }

    pub(super) fn bind<'v>(&self, memory: Memory<'v>) -> MemoryResult<Option<Memory<'v>>> {
        let Some(terms) = memory
            .vault
            .store
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
