//! A room's threads as one reader reaches them (FIX 5545, Engine ruling
//! 2026-10-19). A member added "from now on" reads no turn of a private
//! thread from before its add, the opener included, yet the thread is still
//! theirs: it lists, opens and folds for them. So a read keeps two things
//! apart: the turns it reads, each on its own gate, and the place of each
//! turn held back from it, which carries no word of that turn.
//!
//! A held-back turn is a bare copy of its room row: its id, its room, the
//! turn it answers and its trunk anchor. It names no actor, addressed agent,
//! message, task, quote or project, and its time is 0, so a fold reads no
//! activity from it and no count holds it. Only the thread fold and the
//! root map walk it; nothing serves it.

use super::audience::{private_members_readable_in, resolved_root_in, root_audience_in};
use super::audience_events::fold_audience_in;
use super::*;
use crate::claim::ScopedRead;
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use std::collections::{BTreeMap, BTreeSet};

/// The turns of a room one reader reaches, in the order read: the ones it
/// reads, and a bare place for each one held back from it.
#[derive(Debug, Default)]
pub(super) struct RoomReach {
    placed: Vec<RoomTurn>,
    held: BTreeSet<String>,
}

impl RoomReach {
    /// A turn this reader reads, with what of it the read admits.
    pub(super) fn push_read(&mut self, turn: RoomTurn) {
        self.placed.push(turn);
    }

    /// A turn held back from this reader, as its bare place.
    pub(super) fn push_held(&mut self, turn: &RoomTurn) {
        self.held.insert(turn.turn_id.clone());
        self.placed.push(bare(turn));
    }

    pub(super) fn extend(&mut self, other: Self) {
        self.placed.extend(other.placed);
        self.held.extend(other.held);
    }

    pub(super) fn sort_by_key<K: Ord>(&mut self, key: impl FnMut(&RoomTurn) -> K) {
        self.placed.sort_by_key(key);
    }

    /// Every turn this reader reaches, the held-back ones bare: the topology
    /// the thread fold and the root map walk, never served.
    pub(super) fn placed(&self) -> &[RoomTurn] {
        &self.placed
    }

    /// The turns this reader reads, in order: all a read may serve.
    pub(super) fn read(&self) -> impl Iterator<Item = &RoomTurn> {
        self.placed
            .iter()
            .filter(|turn| !self.held.contains(&turn.turn_id))
    }

    /// [`Self::read`], owned.
    pub(super) fn into_read(self) -> Vec<RoomTurn> {
        let held = self.held;
        self.placed
            .into_iter()
            .filter(|turn| !held.contains(&turn.turn_id))
            .collect()
    }

    /// [`history::answer_closed`] over the places: a turn under a held-back
    /// one stays, and one under a turn this reader does not reach goes, with
    /// every turn under it.
    pub(super) fn answer_closed(self) -> Self {
        let placed = history::answer_closed(self.placed);
        let held = {
            let kept: BTreeSet<&str> = placed.iter().map(|turn| turn.turn_id.as_str()).collect();
            self.held
                .into_iter()
                .filter(|id| kept.contains(id.as_str()))
                .collect()
        };
        Self { placed, held }
    }
}

/// `turn` as a place alone; see the module docs.
fn bare(turn: &RoomTurn) -> RoomTurn {
    RoomTurn {
        turn_id: turn.turn_id.clone(),
        room_id: turn.room_id.clone(),
        actor: String::new(),
        addressed_agents: BTreeSet::new(),
        message_ids: Vec::new(),
        reply_to: turn.reply_to.clone(),
        thread_of: turn.thread_of.clone(),
        at: 0,
        task_ids: Vec::new(),
        converted_project: None,
        quotes: BTreeMap::new(),
    }
}

/// The ids among `turns` that may be places: each turn, and each turn one
/// answers or hangs under, that `content` does not read.
pub(super) fn unread_places(
    turns: &[RoomTurn],
    content: impl Fn(&String) -> bool,
) -> BTreeSet<String> {
    turns
        .iter()
        .flat_map(|turn| {
            [&turn.turn_id]
                .into_iter()
                .chain(&turn.reply_to)
                .chain(&turn.thread_of)
        })
        .filter(|id| !content(*id))
        .cloned()
        .collect()
}

impl Memory<'_> {
    /// The turns among `turns`, read under the private thread `thread`, that
    /// this reader does not read under the CONTENT rule
    /// ([`Self::thread_place_in`]), whatever the thread's lane admits. None
    /// under the room's lane, whose turns sit in no private thread.
    pub(super) fn unread_turns_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        thread: Option<EntityId>,
        turns: &[RoomTurn],
    ) -> Result<BTreeSet<String>> {
        let mut unread = BTreeSet::new();
        if thread.is_none() {
            return Ok(unread);
        }
        for turn in turns {
            let id = EntityId::from_hex(&turn.turn_id)?;
            if self.thread_place_in(txn, room, id)? == ThreadPlace::Withheld {
                unread.insert(turn.turn_id.clone());
            }
        }
        Ok(unread)
    }

    /// Whether this reader reaches `turn`, a turn of a private thread of
    /// `room`, as a place alone: the thread places it for this reader
    /// ([`Self::thread_reach_in`], CURRENT) and it sits before some member's
    /// add. Its words stay the CONTENT rule's; a turn one member of a
    /// ceiling's roster does not read reads for none of them, so such a turn
    /// is held back from each.
    pub(crate) fn thread_turn_held_back_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        turn: EntityId,
    ) -> Result<bool> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(&self.vault().store, txn, &turn)?
        else {
            return Ok(false);
        };
        let Some(binding) = thread_binding(&body)? else {
            return Ok(false);
        };
        let cut = match root_audience_in(self.vault(), txn, room, binding.root) {
            Ok(Some(folded)) => folded.cuts(turn),
            Ok(None) | Err(Error::EntityNotFound) => false,
            Err(error) => return Err(error),
        };
        Ok(cut && self.thread_reach_in(txn, room, turn)? == ThreadPlace::Private(binding.root))
    }

    /// The ids among `ids`, turns of `room`, held back from this reader
    /// ([`Self::thread_turn_held_back_in`]), read in one snapshot.
    pub(super) fn held_back_among(
        &self,
        room: EntityId,
        ids: &BTreeSet<String>,
    ) -> MemoryResult<BTreeSet<String>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let mut held = BTreeSet::new();
        for id in ids {
            if self.thread_turn_held_back_in(&txn, room, EntityId::from_hex(id)?)? {
                held.insert(id.clone());
            }
        }
        Ok(held)
    }
}

/// Whether the caller `read` authenticates reaches the TURN `turn` it reads
/// in `txn` as a place alone: it stands in the turn's private thread now
/// (CURRENT), and `turn` sits before some member's add. Read on the view
/// `read` reads, the audience on base. False for a turn off any private
/// thread, one whose root does not resolve, and a read that authenticates
/// no one.
pub(crate) fn turn_held_back_for_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
) -> Result<bool> {
    let vault = read.vault();
    let dbs = read.store_read();
    let viewers: Vec<_> = read
        .actor_key()
        .authenticated_person()
        .into_iter()
        .collect();
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&dbs, txn, &turn)?
    else {
        return Ok(false);
    };
    let Some(root) = thread_binding(&body)?.map(|binding| binding.root) else {
        return Ok(false);
    };
    let Some(ThreadBinding {
        room,
        audience: Some(seed),
        ..
    }) = resolved_root_in(&dbs, txn, root)?
    else {
        return Ok(false);
    };
    let folded = fold_audience_in(vault, txn, root, &seed)?;
    if !folded.cuts(turn) {
        return Ok(false);
    }
    match private_members_readable_in(vault, txn, room, Some(&folded.current()), &viewers) {
        Err(Error::EntityNotFound) => Ok(false),
        result => result,
    }
}
