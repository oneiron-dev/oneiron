//! The `schedule.tick` source (ARCH-0080 §4 Watchers; FIX 4749). A TASK
//! created with a due time is a watcher: it ticks once, after that time
//! passes. The due index holds each TASK not yet ticked, ordered by its due
//! time. A runner pass releases the due rows into the tick feed in one write:
//! a row leaves the index and gains its feed sequence together, so each tick
//! is released once, and feed order is commit order. Hooks read the feed
//! through their own cursors, as they read the settlement feed, so a restart
//! neither skips nor repeats a tick.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

use super::{FactEntry, FactKind, FactOp, FactPosition, SchedulePosition, SourceBatch};

/// Each TASK waiting for its tick, by due time (Unix seconds) and id.
const TASK_DUE: SideTable<(u64, EntityId), (), Named> = SideTable::new(&side_table::HOOKS_TASK_DUE);
/// The tick feed: one row per released tick, keyed by its sequence.
const TICKS: SideTable<u64, TickRow, Named> = SideTable::new(&side_table::HOOKS_TICK);
/// The last tick sequence handed out.
const TICKS_NEXT: SideTable<(), u64, Named> = SideTable::new(&side_table::HOOKS_TICK_NEXT);

/// Due rows one release moves into the tick feed (CALLS, FIX 4749): an
/// engine call that bounds one write. A longer backlog moves on the next
/// passes, which the runner starts at once.
const HOOK_TICK_RELEASE_ROWS: usize = 256;

/// One released tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TickRow {
    #[serde(with = "crate::serialize::entity_ref")]
    task: EntityId,
    /// The TASK's due time, Unix seconds.
    due_at: u64,
    /// When the release committed, Unix seconds.
    recorded_at: u64,
}

impl TickRow {
    fn input_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-tick.v1");
        hasher.update(self.task.as_bytes());
        hasher.update(&self.due_at.to_be_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// What a tick adds to its hook's input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime_hooks) struct TickDetails {
    /// The TASK's due time, Unix seconds.
    pub(in crate::runtime_hooks) due_at: u64,
}

/// Holds `task` for its tick at `due_at` (Unix seconds), in the TASK mint's
/// own write, so a due TASK never commits without its row.
pub(crate) fn index_task_due_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    due_at: u64,
) -> Result<()> {
    TASK_DUE.put(&vault.store, txn, &(due_at, task), &())
}

/// Moves the due rows at or before `now` (Unix seconds) into the tick feed,
/// in due order, at most [`HOOK_TICK_RELEASE_ROWS`]. A row whose TASK is
/// gone, has settled, or is no longer due at that time leaves the index with
/// no tick. Returns whether due rows remain past the bound.
pub(in crate::runtime_hooks) fn release_due_ticks(vault: &Vault, now: u64) -> Result<bool> {
    let (due, more) = {
        let rtxn = vault.store.env.read_txn()?;
        let mut due = Vec::new();
        let mut more = false;
        for row in TASK_DUE.iter_from(&vault.store, &rtxn, &[])? {
            let ((due_at, task), ()) = row?;
            if due_at > now {
                break;
            }
            if due.len() == HOOK_TICK_RELEASE_ROWS {
                more = true;
                break;
            }
            due.push((due_at, task));
        }
        (due, more)
    };
    if due.is_empty() {
        return Ok(false);
    }
    let recorded_at = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        let mut sequence = TICKS_NEXT.get(&vault.store, txn, &())?.unwrap_or(0);
        for (due_at, task) in &due {
            // A row another release already moved is ticked already.
            if !TASK_DUE.delete(&vault.store, txn, &(*due_at, *task))? {
                continue;
            }
            if crate::task_verb::open_task_due_at_in_txn(vault, txn, *task)? != Some(*due_at) {
                continue;
            }
            sequence = sequence
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("hook tick sequence"))?;
            let row = TickRow {
                task: *task,
                due_at: *due_at,
                recorded_at,
            };
            TICKS.put(&vault.store, txn, &sequence, &row)?;
        }
        TICKS_NEXT.put(&vault.store, txn, &(), &sequence)
    })?;
    Ok(more)
}

/// Ticks after `after`. A tick's actor is the engine's own principal: the
/// clock made it, not a writer.
pub(super) fn ticks_after(
    vault: &Vault,
    after: Option<SchedulePosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    let rtxn = vault.store.env.read_txn()?;
    let start = after
        .as_ref()
        .map_or(Bound::Unbounded, |position| Bound::Excluded(&position.0));
    let actor = crate::ports::storage_service_principal()?;
    let mut batch = SourceBatch::default();
    for row in TICKS.iter_range(&vault.store, &rtxn, start, Bound::Unbounded)? {
        if batch.entries.len() >= max_entries {
            batch.more = true;
            break;
        }
        let (sequence, tick) = row?;
        let position = FactPosition::Schedule(SchedulePosition(sequence));
        batch.through = Some(position);
        batch.entries.push(FactEntry {
            position,
            kind: FactKind::ScheduleTick,
            entity: tick.task,
            op: FactOp::Tick,
            actor,
            recorded_at: tick.recorded_at,
            input_hash: tick.input_hash(),
            body_hash: None,
            revision: None,
            settlement: None,
            predicate: None,
            tick: Some(TickDetails {
                due_at: tick.due_at,
            }),
            surface: None,
        });
    }
    Ok(batch)
}

/// The newest tick position, or `None` while the feed is empty.
pub(super) fn head_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<FactPosition>> {
    Ok(TICKS
        .iter_rev_from(&vault.store, txn, &[])?
        .next()
        .transpose()?
        .map(|(sequence, _)| FactPosition::Schedule(SchedulePosition(sequence))))
}
