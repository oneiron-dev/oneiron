//! When an open offer card's thread has ended (OF-530, ARCH-0006a:233): a
//! thread is live while it has an open task, an open wait or fresh messages,
//! and a card ages out with it. One fold over the room's turn rows decides
//! it for every room (THREAD-TASK-EVERY-ROOM P2: every TURN keeps its row),
//! over only what the caller reads; nothing is stored. A card for the room
//! itself is not decided here.

use std::collections::{BTreeMap, BTreeSet};

use super::{RoomTurn, agent_off_room_in_txn, liveness, require_reader};
use crate::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult};

impl Memory<'_> {
    /// The threads among `threads` of `room` that have ended, so their open
    /// cards age out: the room's thread fold, as the caller reads it, lists
    /// them quiet, with no open task, open wait or fresh message. A branch
    /// the fold does not hold, or whose root or trunk anchor the caller
    /// cannot read, ends nothing. A home room's roster is its project's
    /// seats; any other room's is its own, and a thread there that the
    /// caller does not read is left out before the fold.
    pub(super) fn ended_offer_threads(
        &self,
        room: EntityId,
        threads: &BTreeSet<EntityId>,
    ) -> MemoryResult<BTreeSet<EntityId>> {
        if threads.is_empty() {
            return Ok(BTreeSet::new());
        }
        let vault = self.vault();
        if let Some(project_room) = vault.project_room(room)? {
            let members = project_room.member_ids.into_iter().collect();
            return self.ended_room_threads(room, threads, &members);
        }
        let (readable, members) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let Some(roster) = crate::context_board::room_roster_in(vault, &txn, room)? else {
                return Ok(BTreeSet::new());
            };
            let mut readable = BTreeSet::new();
            for thread in threads {
                if crate::context_board::thread_reader_in(
                    vault,
                    &txn,
                    room,
                    *thread,
                    &roster,
                    self.actor(),
                )? {
                    readable.insert(*thread);
                }
            }
            let members: BTreeSet<String> = roster.iter().map(EntityId::to_hex).collect();
            (readable, members)
        };
        if readable.is_empty() {
            return Ok(BTreeSet::new());
        }
        self.ended_room_threads(room, &readable, &members)
    }

    /// [`Self::ended_offer_threads`] over the room's history, for the room's
    /// `members`. An agent with no standing in the room itself, and a person
    /// the room does not read (a vault Owner or Admin reading a private
    /// thread, FIX 5638), reads each thread on that thread's own receipt,
    /// through a snapshot and a lane bound to it alone.
    fn ended_room_threads(
        &self,
        room: EntityId,
        threads: &BTreeSet<EntityId>,
        members: &BTreeSet<String>,
    ) -> MemoryResult<BTreeSet<EntityId>> {
        let now = crate::unix_seconds_now();
        // The caller's own thread settings, resolved before any reader is
        // rebound to the room or a thread.
        let (off_room, fold) = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            (
                agent_off_room_in_txn(self.vault(), &txn, room, self.actor())?
                    || require_reader(self.vault(), &txn, room, self.actor()).is_err(),
                liveness::direct_thread_fold_in(self.vault(), &txn, self.actor(), now)?,
            )
        };
        if !off_room {
            // Task and wait reads run inside the room, as the room's own fold
            // reads them.
            let turns = self.room_turn_snapshot(room)?;
            let projection = self.for_room_projection(room)?;
            return ended_in(
                projection.memory(),
                turns.placed(),
                turns.held(),
                room,
                threads,
                members,
                fold,
            );
        }
        let mut ended = BTreeSet::new();
        for thread in threads {
            let turns = self.thread_turn_snapshot(room, *thread)?;
            let projection = self.for_thread_projection(room, *thread)?;
            let memory = projection.memory();
            let one = BTreeSet::from([*thread]);
            ended.extend(ended_in(
                memory,
                turns.placed(),
                turns.held(),
                room,
                &one,
                members,
                fold,
            )?);
        }
        Ok(ended)
    }
}

/// The fold itself: of `threads`, those `turns` hold whose direct-by-handle
/// projection under the caller's `fold` lists them quiet, with the tasks
/// bound to them read through `memory` for the room's `members` at its time.
/// `held` are the ids among `turns` held back from the reader (FIX 5658).
fn ended_in(
    memory: &Memory<'_>,
    turns: &[RoomTurn],
    held: &BTreeSet<String>,
    room: EntityId,
    threads: &BTreeSet<EntityId>,
    members: &BTreeSet<String>,
    fold: liveness::ThreadFold,
) -> MemoryResult<BTreeSet<EntityId>> {
    let selected: BTreeMap<EntityId, EntityId> = liveness::thread_root_map(turns)?
        .into_iter()
        .filter(|(_, root)| threads.contains(root))
        .collect();
    if selected.is_empty() {
        return Ok(BTreeSet::new());
    }
    let bindings = liveness::thread_task_bindings(turns, &selected)?;
    let tasks =
        crate::task_verb::room_thread_tasks(memory, &selected, &bindings, members, fold.now)?;
    let edits = {
        let txn = memory.vault().store.env.read_txn().map_err(Error::from)?;
        super::audience_events::audience_edit_turns_in(memory.vault(), &txn, turns)?
    };
    let mut ended = BTreeSet::new();
    for thread in threads {
        // FIX 5658: `thread_tasks` are this thread's TASK facts, not the held
        // set `held` (bare places); the fold takes both explicitly.
        let thread_tasks: Vec<_> = tasks
            .iter()
            .filter(|task| task.thread == *thread)
            .cloned()
            .collect();
        if liveness::thread_is_live(turns, held, &edits, &thread_tasks, room, *thread, fold)?
            == Some(false)
        {
            ended.insert(*thread);
        }
    }
    Ok(ended)
}
