//! When an open offer card's thread has ended (OF-530, ARCH-0006a:233): a
//! thread is live while it has an open task, an open wait or fresh messages,
//! and a card ages out with it. One fold decides it for a project room's
//! turns and for an ordinary Conversation's DAG threads, over only what the
//! caller reads; nothing is stored. A card for the room itself is not decided
//! here.

use std::collections::{BTreeMap, BTreeSet};

use super::{RoomTurn, agent_off_room_in_txn, history, liveness};
use crate::EntityId;
use crate::claim::{ClaimReadStatus, PointRead};
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};

impl Memory<'_> {
    /// The threads among `threads` of `room` that have ended, so their open
    /// cards age out: the room's thread fold, as the caller reads it, lists
    /// them quiet, with no open task, open wait or fresh message. A branch
    /// the fold does not hold, or whose root or trunk anchor the caller
    /// cannot read, ends nothing.
    pub(super) fn ended_offer_threads(
        &self,
        room: EntityId,
        threads: &BTreeSet<EntityId>,
    ) -> MemoryResult<BTreeSet<EntityId>> {
        if threads.is_empty() {
            return Ok(BTreeSet::new());
        }
        match self.vault().project_room(room)? {
            Some(project_room) => {
                let members = project_room.member_ids.into_iter().collect();
                self.ended_project_threads(room, threads, &members)
            }
            None => self.ended_dag_threads(room, threads),
        }
    }

    /// [`Self::ended_offer_threads`] for a project room: its own fold over
    /// the room's history. An agent with no standing in the room itself reads
    /// each thread on that thread's own receipt, through a snapshot and a lane
    /// bound to it alone.
    fn ended_project_threads(
        &self,
        room: EntityId,
        threads: &BTreeSet<EntityId>,
        members: &BTreeSet<String>,
    ) -> MemoryResult<BTreeSet<EntityId>> {
        let off_room = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            agent_off_room_in_txn(self.vault(), &txn, room, self.actor())?
        };
        let now = crate::unix_seconds_now();
        if !off_room {
            // Task and wait reads run inside the room, as the room's own fold
            // reads them.
            let turns = self.room_turn_snapshot(room)?;
            let projection = self.for_room_projection(room)?;
            return ended_in(projection.memory(), &turns, room, threads, members, now);
        }
        let mut ended = BTreeSet::new();
        for thread in threads {
            let turns = self.thread_turn_snapshot(room, *thread)?;
            let projection = self.for_thread_projection(room, *thread)?;
            let memory = projection.memory();
            let one = BTreeSet::from([*thread]);
            ended.extend(ended_in(memory, &turns, room, &one, members, now)?);
        }
        Ok(ended)
    }

    /// [`Self::ended_offer_threads`] for an ordinary Conversation: its DAG
    /// threads folded the same way. The room's records are found by their
    /// structure alone ([`crate::conversation_dag::offer_turns_in_txn`]); each
    /// thread the caller reads is then admitted through a lane bound to that
    /// thread, its root's whole branch and the trunk record it hangs off, and
    /// its tasks are read on the same lane.
    fn ended_dag_threads(
        &self,
        room: EntityId,
        threads: &BTreeSet<EntityId>,
    ) -> MemoryResult<BTreeSet<EntityId>> {
        let vault = self.vault();
        let (members, readable, turns) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let Some(members) = crate::context_board::room_roster_in(vault, &txn, room)? else {
                return Ok(BTreeSet::new());
            };
            let mut readable = Vec::new();
            for thread in threads {
                if crate::context_board::thread_reader_in(
                    vault,
                    &txn,
                    room,
                    *thread,
                    &members,
                    self.actor(),
                )? {
                    readable.push(*thread);
                }
            }
            if readable.is_empty() {
                return Ok(BTreeSet::new());
            }
            // Every record is read, however many (rule 5); past the
            // threshold row the owner's check is raised for the room.
            let mut count = crate::scan_check::ScanCount::start(
                &vault.store,
                &txn,
                crate::scan_check::EngineScan::RoomHistoryRows,
                room.as_bytes(),
            )?;
            let turns = crate::conversation_dag::offer_turns_in_txn(vault, &txn, room, &mut count)?;
            drop(txn);
            count.finish(vault);
            (members, readable, turns)
        };
        let members: BTreeSet<String> = members.iter().map(EntityId::to_hex).collect();
        let turns = history::answer_closed(turns);
        let roots = liveness::thread_root_map(&turns)?;
        let now = crate::unix_seconds_now();
        let mut ended = BTreeSet::new();
        for thread in readable {
            if roots.get(&thread) != Some(&thread) {
                continue;
            }
            let root = thread.to_hex();
            let anchor = turns
                .iter()
                .find(|turn| turn.turn_id == root)
                .and_then(|turn| turn.thread_of.clone());
            let selected: Vec<RoomTurn> = turns
                .iter()
                .filter(|turn| {
                    anchor.as_ref() == Some(&turn.turn_id)
                        || EntityId::from_hex(&turn.turn_id)
                            .is_ok_and(|id| roots.get(&id) == Some(&thread))
                })
                .cloned()
                .collect();
            let projection = self.for_thread_projection(room, thread)?;
            let memory = projection.memory();
            let admitted = history::answer_closed(admitted_records(memory, selected)?);
            let one = BTreeSet::from([thread]);
            ended.extend(ended_in(memory, &admitted, room, &one, &members, now)?);
        }
        Ok(ended)
    }
}

/// The turns among `turns` whose own records `memory`'s lane admits.
fn admitted_records(memory: &Memory<'_>, turns: Vec<RoomTurn>) -> MemoryResult<Vec<RoomTurn>> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let ids = turns
        .iter()
        .map(|turn| EntityId::from_hex(&turn.turn_id))
        .collect::<Result<Vec<_>>>()?;
    let mut admitted = BTreeSet::new();
    for chunk in ids.chunks(128) {
        let reads: Vec<_> = chunk.iter().copied().map(PointRead::id).collect();
        let rows = lane.read(&reads, None)?.value;
        admitted.extend(
            chunk
                .iter()
                .zip(rows)
                .filter_map(|(id, row)| row.map(|_| *id)),
        );
    }
    Ok(turns
        .into_iter()
        .filter(|turn| EntityId::from_hex(&turn.turn_id).is_ok_and(|id| admitted.contains(&id)))
        .collect())
}

/// The fold itself: of `threads`, those `turns` hold whose direct-by-handle
/// projection lists them quiet, with the tasks bound to them read through
/// `memory` for the room's `members` at `now`.
fn ended_in(
    memory: &Memory<'_>,
    turns: &[RoomTurn],
    room: EntityId,
    threads: &BTreeSet<EntityId>,
    members: &BTreeSet<String>,
    now: u64,
) -> MemoryResult<BTreeSet<EntityId>> {
    let selected: BTreeMap<EntityId, EntityId> = liveness::thread_root_map(turns)?
        .into_iter()
        .filter(|(_, root)| threads.contains(root))
        .collect();
    if selected.is_empty() {
        return Ok(BTreeSet::new());
    }
    let bindings = liveness::thread_task_bindings(turns, &selected)?;
    let tasks = crate::task_verb::room_thread_tasks(memory, &selected, &bindings, members, now)?;
    let mut ended = BTreeSet::new();
    for thread in threads {
        let held: Vec<_> = tasks
            .iter()
            .filter(|task| task.thread == *thread)
            .cloned()
            .collect();
        if liveness::thread_is_live(turns, &held, room, *thread, now)? == Some(false) {
            ended.insert(*thread);
        }
    }
    Ok(ended)
}
