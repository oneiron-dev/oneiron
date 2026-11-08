//! The `schedule.tick` source (ARCH-0080 §4 Watchers; FIX 4749). A TASK
//! created with a due time is a watcher: it ticks once per due time, after
//! that time passes. The due index holds each TASK not yet ticked, ordered by
//! its due time. The storage door keeps it beside every TASK body that lands,
//! a peer's synced copy too, so the index follows the TASK to each device.
//! The vault's elected home releases the due rows into the tick feed in one
//! write: a row leaves the index and gains its feed sequence together, so
//! each tick is released once per vault, and feed order is commit order.
//! Before an election names a home, a device releases only while its synced
//! machine roster names no other machine; with another there, none releases
//! until a home is elected, as no MACRO round, digest or booking runs on an
//! unelected vault, and each due row waits, then ticks once, late. The
//! releasing node releases at each fact-hook runner pass and each
//! housekeeping pass, the owner's run now and `oneiron maintain` included,
//! hooks on or off, with a binding to take a tick or none, so a watch TASK
//! settles at its due time on that node, served or stopped: a stopped vault
//! wakes for its earliest due row, and `oneiron maintain` settles its due
//! watch TASKs (FIX 22180). Hooks read the feed through their own cursors,
//! as they read the settlement feed, so a restart neither skips nor repeats
//! a tick. A watch TASK's tick settles it Done in the write that releases it
//! (FIX 22121); the hooks bound at that release are still offered the
//! tick, as it was open at its due time, and a hook bound after it is not
//! (review #6784). A binding a peer enabled is bound here when this node
//! first places its cursor.
//! The runner and each housekeeping pass prune the rows every hook binding
//! has passed, but an open TASK's own tick, so a host that runs no runner
//! keeps the feed bounded too, and an erase leaves an erased TASK's rows at
//! their sequences with no TASK in them.

use std::collections::BTreeSet;
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
/// releases: the runner starts its next pass at once, and a housekeeping
/// pass releases again until its budget passes.
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
/// so a tick fires once per vault however many devices hold its TASK.
///
/// Before any election names a home, a device releases only while it is
/// the vault's one machine: the synced authority roster profiles no machine
/// but this install's own that was not removed
/// (`AuthorityFold::profiles_other_machine`), so a vault no serve has
/// claimed still ticks, `oneiron maintain` included. With another machine
/// there, none releases, as no MACRO round, digest or booking runs on a
/// vault with no elected home; the due rows wait, and the home's first pass
/// once one is elected (its serve claims it, a device elects the home it
/// dials, or the owner picks one) releases each, late, once. A roster this
/// snapshot cannot read (history the vault lacks, conflicting vault roots)
/// releases nothing, as it elects nothing.
fn releases_here(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let home =
        crate::dreamer_runner::DreamerRunnerStore::new(vault).home_node_designation_in_txn(txn)?;
    if let Some(home) = home {
        return Ok(crate::identity::read_client_id_in_txn(vault, txn)? == Some(home.node_id));
    }
    let fold = match vault.authority_view_readonly_in_txn(txn) {
        Ok(fold) if !fold.vault_root_is_conflicted() => fold,
        Ok(_) => return Ok(false),
        Err(error) if crate::authority::is_history_incomplete(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    let own = crate::identity::read_machine_id_in_txn(vault, txn)?;
    Ok(!fold.profiles_other_machine(own))
}

/// Moves the due rows at or before `now` (Unix seconds) into the tick feed,
/// in due order, at most [`HOOK_TICK_RELEASE_ROWS`], on the one node that
/// releases the vault's ticks ([`releases_here`]). A row whose TASK is
/// gone, has settled, or is no longer due at that time leaves the index with
/// no tick. A watch TASK settles Done with its tick, whether or not a hook
/// takes it (FIX 22121). Returns whether due rows remain past the bound. The
/// fact-hook runner calls it at the start of each pass and each housekeeping
/// pass before its sweeps, the host tick's, the owner's run now and
/// `oneiron maintain`, whatever the bindings and the hooks switch (FIX
/// 22180). A row two releases both plan moves once: the writes commit one
/// after the other, the later one finds the row gone from the due index and
/// skips it, and each draws its sequences in its own write.
pub(crate) fn release_due_ticks(vault: &Vault, now: u64) -> Result<bool> {
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
            // Its tick is a watch TASK's whole work (FIX 22121): it settles
            // here, after the row above, which its settled body then drops.
            crate::task_verb::settle_watch_task_in_txn(vault, txn, *task, recorded_at)?;
        }
        TICKS_NEXT.put(&vault.store, txn, &(), &sequence)
    })?;
    Ok(more)
}

/// When this node next releases a tick: the due time of the earliest row in
/// the due index, Unix seconds, on the node that releases ([`releases_here`]),
/// the elected home or, before an election, the vault's one machine; `None`
/// on any other, a device of a vault with no elected home included, and
/// while no TASK waits. A stopped vault wakes then
/// (`Vault::housekeeping_wake_at`, FIX 22180). A cancelled TASK's row wakes
/// it once: that release drops the row with no tick.
pub(crate) fn next_tick_release_at(vault: &Vault) -> Result<Option<u64>> {
    let rtxn = vault.store.env.read_txn()?;
    if !releases_here(vault, &rtxn)? {
        return Ok(None);
    }
    let earliest = TASK_DUE
        .iter_from(&vault.store, &rtxn, &[])?
        .next()
        .transpose()?;
    Ok(earliest.map(|((due_at, _), ())| due_at))
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

/// The tick rows at or before `floor`, the lowest cursor of every enabled
/// fact binding, that no binding reads again, at most `max_rows`, read in
/// `txn` for a later write to delete ([`delete_ticks_in_txn`]). The
/// tick an open TASK's due index entry holds stays: a binding new to the
/// feed starts before it ([`open_tick_start_in_txn`]). Every other passed
/// row is one no binding takes again, as the runner delivers a tick only
/// while its TASK is open at that due time. The scan passes over the kept
/// ticks, at most one per open TASK.
pub(super) fn passed_ticks_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    floor: SchedulePosition,
    max_rows: usize,
) -> Result<Vec<u64>> {
    let mut passed = Vec::new();
    for row in TICKS.iter_range(
        &vault.store,
        txn,
        Bound::Unbounded,
        Bound::Included(&floor.0),
    )? {
        if passed.len() >= max_rows {
            break;
        }
        let (sequence, row) = row?;
        if let TickRow::Released(tick) = &row
            && TASK_DUE_REVERSE
                .get(&vault.store, txn, &tick.task)?
                .is_some_and(|entry| entry.tick == Some(sequence))
        {
            continue;
        }
        passed.push(sequence);
    }
    Ok(passed)
}

/// Deletes the tick feed rows `sequences` names, in the caller's write.
pub(super) fn delete_ticks_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sequences: &[u64],
) -> Result<()> {
    for sequence in sequences {
        TICKS.delete(&vault.store, txn, sequence)?;
    }
    Ok(())
}

/// Erases `tasks` from the tick source in the caller's erase write: their
/// due index rows go, and each tick feed row that names one becomes
/// [`TickRow::Erased`] at its own sequence. One complete scan for all of
/// them, as the other hook carriers' scrub; a row erased already stays as
/// it is. A tick written later names none: a release ticks only a TASK
/// still open in its own write.
pub(super) fn scrub_task_ticks_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    tasks: &BTreeSet<EntityId>,
) -> Result<()> {
    for task in tasks {
        index_task_due_in_txn(&vault.store, txn, *task, None)?;
    }
    let mut named = Vec::new();
    for row in TICKS.iter_from(&vault.store, txn, &[])? {
        let (sequence, row) = row?;
        if matches!(&row, TickRow::Released(tick) if tasks.contains(&tick.task)) {
            named.push(sequence);
        }
    }
    for sequence in &named {
        TICKS.put(&vault.store, txn, sequence, &TickRow::Erased)?;
    }
    Ok(())
}
