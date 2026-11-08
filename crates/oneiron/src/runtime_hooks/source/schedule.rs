//! The `schedule.tick` source (ARCH-0080 §4 Watchers; FIX 4749). A TASK
//! created with a due time is a watcher: it ticks once per due time, after
//! that time passes. The due index holds each TASK not yet ticked, ordered by
//! its due time. The storage door keeps it beside every TASK body that lands,
//! a peer's synced copy too, so the index follows the TASK to each device.
//! The vault's elected home releases the due rows into the tick feed in one
//! write: a row leaves the index and gains its feed sequence together, so
//! each tick is released once per vault, and feed order is commit order.
//! Hooks read the feed through their own cursors, as they read the
//! settlement feed, so a restart neither skips nor repeats a tick.
//! The runner prunes the rows every hook binding has passed, but an open
//! TASK's own tick, and an erase leaves an erased TASK's rows at their
//! sequences with no TASK in them.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

use super::{FactEntry, FactKind, FactOp, FactPosition, SchedulePosition, SourceBatch};

/// Each TASK waiting for its tick, by due time (Unix seconds) and id.
const TASK_DUE: SideTable<(u64, EntityId), (), Named> = SideTable::new(&side_table::HOOKS_TASK_DUE);
/// Each indexed TASK's due time and the tick its release committed: a body
/// written again at the same due time adds no second tick, and a new
/// binding starts at the earliest tick of a TASK still open.
const TASK_DUE_REVERSE: SideTable<EntityId, DueEntry, Named> =
    SideTable::new(&side_table::HOOKS_TASK_DUE_REVERSE);
/// The tick feed: one row per released tick, keyed by its sequence.
const TICKS: SideTable<u64, TickRow, Named> = SideTable::new(&side_table::HOOKS_TICK);
/// The last tick sequence handed out.
const TICKS_NEXT: SideTable<(), u64, Named> = SideTable::new(&side_table::HOOKS_TICK_NEXT);

/// Due rows one release moves into the tick feed (CALLS, FIX 4749): an
/// engine call that bounds one write. A longer backlog moves on the next
/// passes, which the runner starts at once.
const HOOK_TICK_RELEASE_ROWS: usize = 256;

/// One TASK's place in the due index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct DueEntry {
    /// The due time the index holds, Unix seconds.
    due_at: u64,
    /// The tick feed sequence its release committed; `None` while it waits.
    tick: Option<u64>,
}

/// One tick feed row, at the sequence its release committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TickRow {
    /// A released tick.
    Released(ReleasedTick),
    /// A tick whose TASK was erased: it keeps its position, so a cursor past
    /// it neither breaks nor reads it again, and names no TASK or due time.
    /// No reader takes it.
    Erased,
}

/// One released tick's TASK and due time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReleasedTick {
    #[serde(with = "crate::serialize::entity_ref")]
    task: EntityId,
    /// The TASK's due time, Unix seconds.
    due_at: u64,
    /// When the release committed, Unix seconds.
    recorded_at: u64,
}

impl ReleasedTick {
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

/// Keeps `task`'s due index row in step with its body's due time, in the
/// write that stores the body: `due_at` is the time the body ticks at, or
/// `None` for a body that ticks at no time. A due time the index already
/// holds, waiting or ticked, changes nothing, so a body written again never
/// ticks twice; a new due time replaces the old row and ticks again.
pub(crate) fn index_task_due_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    due_at: Option<u64>,
) -> Result<()> {
    let held = TASK_DUE_REVERSE.get(store, txn, &task)?;
    if held.map(|entry| entry.due_at) == due_at {
        return Ok(());
    }
    if let Some(entry) = held {
        TASK_DUE.delete(store, txn, &(entry.due_at, task))?;
    }
    let Some(due_at) = due_at else {
        TASK_DUE_REVERSE.delete(store, txn, &task)?;
        return Ok(());
    };
    TASK_DUE.put(store, txn, &(due_at, task), &())?;
    TASK_DUE_REVERSE.put(store, txn, &task, &DueEntry { due_at, tick: None })
}

/// Whether this node releases the vault's ticks. The vault's elected MACRO
/// home does (ARCH-0026), the one node its due digests and bookings run on,
/// so a tick fires once per vault however many devices hold its TASK. A
/// vault with no elected home releases where its rows are.
fn releases_here(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let home =
        crate::dreamer_runner::DreamerRunnerStore::new(vault).home_node_designation_in_txn(txn)?;
    match home {
        None => Ok(true),
        Some(home) => Ok(crate::identity::read_client_id_in_txn(vault, txn)? == Some(home.node_id)),
    }
}

/// Moves the due rows at or before `now` (Unix seconds) into the tick feed,
/// in due order, at most [`HOOK_TICK_RELEASE_ROWS`], on the vault's home
/// alone. A row whose TASK is gone, has settled, or is no longer due at that
/// time leaves the index with no tick. Returns whether due rows remain past
/// the bound.
pub(in crate::runtime_hooks) fn release_due_ticks(vault: &Vault, now: u64) -> Result<bool> {
    let (due, more) = {
        let rtxn = vault.store.env.read_txn()?;
        if !releases_here(vault, &rtxn)? {
            return Ok(false);
        }
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
            let row = TickRow::Released(ReleasedTick {
                task: *task,
                due_at: *due_at,
                recorded_at,
            });
            TICKS.put(&vault.store, txn, &sequence, &row)?;
            let entry = DueEntry {
                due_at: *due_at,
                tick: Some(sequence),
            };
            TASK_DUE_REVERSE.put(&vault.store, txn, task, &entry)?;
        }
        TICKS_NEXT.put(&vault.store, txn, &(), &sequence)
    })?;
    Ok(more)
}

/// Where a binding new to the tick feed starts: just before the earliest
/// tick of a TASK still open at that due time, so a watcher bound after its
/// TASK ticked still sees that tick; at the feed head when no open TASK has
/// ticked here.
pub(super) fn open_tick_start_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<FactPosition>> {
    let mut earliest: Option<u64> = None;
    for row in TASK_DUE_REVERSE.iter_from(&vault.store, txn, &[])? {
        let (_, entry) = row?;
        earliest = match (earliest, entry.tick) {
            (Some(held), Some(tick)) => Some(held.min(tick)),
            (held, tick) => held.or(tick),
        };
    }
    match earliest {
        Some(tick) => Ok(Some(FactPosition::Schedule(SchedulePosition(
            tick.saturating_sub(1),
        )))),
        None => head_in_txn(vault, txn),
    }
}

/// Ticks after `after`, at most `max_entries` rows scanned. A tick's actor
/// is the engine's own principal: the clock made it, not a writer. An erased
/// row is scanned past, so the cursor moves over it as over a skipped fact.
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
    for (scanned, row) in TICKS
        .iter_range(&vault.store, &rtxn, start, Bound::Unbounded)?
        .enumerate()
    {
        if scanned >= max_entries {
            batch.more = true;
            break;
        }
        let (sequence, row) = row?;
        let position = FactPosition::Schedule(SchedulePosition(sequence));
        batch.through = Some(position);
        let TickRow::Released(tick) = row else {
            continue;
        };
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

/// Deletes the tick rows at or before `floor`, the lowest cursor of every
/// enabled fact binding, at most `max_rows`, in the caller's write. The
/// tick an open TASK's due index entry holds stays: a binding new to the
/// feed starts before it ([`open_tick_start_in_txn`]). Every other passed
/// row is one no binding takes again, as the runner delivers a tick only
/// while its TASK is open at that due time. The scan passes over the kept
/// ticks, at most one per open TASK.
pub(super) fn prune_passed_ticks_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    floor: SchedulePosition,
    max_rows: usize,
) -> Result<()> {
    let read: &heed::RoTxn<'_> = txn;
    let mut passed = Vec::new();
    for row in TICKS.iter_range(
        &vault.store,
        read,
        Bound::Unbounded,
        Bound::Included(&floor.0),
    )? {
        if passed.len() >= max_rows {
            break;
        }
        let (sequence, row) = row?;
        if let TickRow::Released(tick) = &row
            && TASK_DUE_REVERSE
                .get(&vault.store, read, &tick.task)?
                .is_some_and(|entry| entry.tick == Some(sequence))
        {
            continue;
        }
        passed.push(sequence);
    }
    for sequence in &passed {
        TICKS.delete(&vault.store, txn, sequence)?;
    }
    Ok(())
}

/// Erases `task` from the tick source in the caller's erase write: its due
/// index rows go, and each tick feed row that names it becomes
/// [`TickRow::Erased`] at its own sequence. A complete scan, as the other
/// hook carriers' scrub; a row erased already stays as it is.
pub(super) fn scrub_task_ticks_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: &EntityId,
) -> Result<()> {
    index_task_due_in_txn(&vault.store, txn, *task, None)?;
    let mut named = Vec::new();
    for row in TICKS.iter_from(&vault.store, txn, &[])? {
        let (sequence, row) = row?;
        if matches!(&row, TickRow::Released(tick) if tick.task == *task) {
            named.push(sequence);
        }
    }
    for sequence in &named {
        TICKS.put(&vault.store, txn, sequence, &TickRow::Erased)?;
    }
    Ok(())
}
