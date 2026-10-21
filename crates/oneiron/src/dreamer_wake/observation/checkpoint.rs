//! The wake observation's Checkpoint half: the cut a park's own write
//! records, the check the deadline lane arms on, and the later pass's
//! checked resume of a park an ended pass cut. A pass whose process died, or
//! whose root dropped, before it recorded its end has ended all the same
//! (FIX 5172): its parks resume at the next pass, not only at a boot.

use super::{
    ATTEMPTS, CALLS, CHECKPOINTS, LATEST, WAKES, WakeCallState, WakeObservedAttempt,
    WakeObservedCheckpoint, WakeObservedHeader, WakeObservedResume, WakeRef, attempt_key,
    checkpoint_key, holds_lease, in_savepoint, latest_key, row_key, skipped, wake_key,
};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::{
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DreamerParkedAttemptRecord, DreamerRunnerStore,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// A Checkpoint cut planned in the park's write, before its savepoint.
struct PlannedCut {
    generation: Vec<u8>,
    admitted: WakeObservedAttempt,
    park: EntityId,
    row: WakeObservedCheckpoint,
}

/// Records the pass a Checkpoint park cut, in a savepoint of the park's own
/// write: the park lands exactly as it would unobserved. Only a park of the
/// generation its pass observed, still under that pass's lease, records one.
pub(crate) fn record_checkpoint_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    park: &DreamerParkedAttemptRecord,
) {
    if park.cause.later_pass_resume_delay().is_none() {
        return;
    }
    let planned = match plan_checkpoint_in_txn(vault, wtxn, park) {
        Ok(Some(planned)) => planned,
        Ok(None) => return,
        Err(error) => {
            skipped(&error, "checkpoint park");
            return;
        }
    };
    in_savepoint(vault, wtxn, "checkpoint park", |txn| {
        CHECKPOINTS.put(vault, txn, &checkpoint_key(planned.park), &planned.row)?;
        ATTEMPTS.put(vault, txn, &planned.generation, &planned.admitted)
    });
}

fn plan_checkpoint_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    park: &DreamerParkedAttemptRecord,
) -> Result<Option<PlannedCut>> {
    let attempt = park.attempt_id;
    let Some(latest) = LATEST.get(&vault.store, txn, &latest_key(attempt))? else {
        return Ok(None);
    };
    let generation = attempt_key(attempt, latest.attempt_count);
    let Some(mut admitted) = ATTEMPTS.get(&vault.store, txn, &generation)? else {
        return Ok(None);
    };
    let Some(current) = AttemptQueue::new(vault).get_in_txn(txn, attempt)? else {
        return Ok(None);
    };
    if !holds_lease(&current, &admitted.worker, admitted.attempt_count) {
        return Ok(None);
    }
    // A re-park of the same generation refreshes its one cut.
    let park_ref = match admitted.park {
        Some(existing) => existing,
        None => vault.store.clock.entity_id()?,
    };
    let mut saved_steps = Vec::new();
    let calls = row_key(
        b'c',
        &[
            admitted.wake.0.as_bytes().as_slice(),
            attempt.as_bytes().as_slice(),
        ],
    );
    for row in CALLS.iter_from(&vault.store, txn, &calls)? {
        let (_, call) = row?;
        let claimed = call
            .end
            .as_ref()
            .is_some_and(|end| end.state == WakeCallState::Claimed);
        if claimed
            && call.attempt_count == admitted.attempt_count
            && !saved_steps.contains(&call.step_hash)
        {
            saved_steps.push(call.step_hash);
        }
    }
    admitted.park = Some(park_ref);
    let row = WakeObservedCheckpoint {
        attempt,
        attempt_count: admitted.attempt_count,
        wake: admitted.wake,
        parked_at: park.parked_at,
        saved_steps,
        resumed: None,
    };
    Ok(Some(PlannedCut {
        generation,
        admitted,
        park: park_ref,
        row,
    }))
}

/// A Checkpoint park's recorded cut, as one snapshot reads it.
pub(crate) struct CheckpointCut {
    park: EntityId,
    row: WakeObservedCheckpoint,
}

/// The cut a Checkpoint park records, when the pass that cut it has ended
/// (`pass_over`) and `record` (its queue row) still holds that pass's
/// lease at the generation it observed: what the deadline lane arms on and
/// the resume rechecks. `None` for any other park, and for one no pass
/// observed.
pub(crate) fn checkpoint_resumable_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    park: &DreamerParkedAttemptRecord,
    record: &AttemptRecord,
) -> Result<Option<CheckpointCut>> {
    if park.cause.later_pass_resume_delay().is_none() || record.id != park.attempt_id {
        return Ok(None);
    }
    let Some(latest) = LATEST.get(&vault.store, txn, &latest_key(park.attempt_id))? else {
        return Ok(None);
    };
    let generation = attempt_key(park.attempt_id, latest.attempt_count);
    let Some(admitted) = ATTEMPTS.get(&vault.store, txn, &generation)? else {
        return Ok(None);
    };
    let Some(park_ref) = admitted.park else {
        return Ok(None);
    };
    if !holds_lease(record, &admitted.worker, admitted.attempt_count) {
        return Ok(None);
    }
    let Some(row) = CHECKPOINTS.get(&vault.store, txn, &checkpoint_key(park_ref))? else {
        return Ok(None);
    };
    if row.resumed.is_some() || row.wake != admitted.wake {
        return Ok(None);
    }
    let ended = WAKES
        .get(&vault.store, txn, &wake_key(row.wake))?
        .is_some_and(|header| pass_over(vault, row.wake, &header));
    Ok(ended.then_some(CheckpointCut {
        park: park_ref,
        row,
    }))
}

/// Whether the pass `wake` names runs no more (FIX 5172): it recorded its
/// end, or it never will. A pass whose process died first, or whose root
/// dropped without its end, leaves its header open for good. Such a pass is
/// over when this process holds the vault's writer lease, so no other
/// process runs a pass on it, and no root on this vault runs `wake`. The
/// live registry holds a pass from before its header is visible until its
/// last deadline clone is gone, and every call of the pass runs under one,
/// so a pass with a call still running is never over here. Nothing is timed
/// and no clock is read.
fn pass_over(vault: &Vault, wake: WakeRef, header: &WakeObservedHeader) -> bool {
    header.ended.is_some()
        || (vault
            .writer_lease()
            .is_some_and(crate::store::VaultWriterLease::held_by_current_process)
            && vault.active_wakes.get(wake).is_none())
}

/// The later pass resuming ended Checkpoint parks: its wake, its node and
/// the worker label it leases under.
pub(crate) struct LaterWake<'a> {
    pub(crate) wake: WakeRef,
    pub(crate) local_node_id: u64,
    pub(crate) worker: &'a str,
    pub(crate) now: u64,
}

/// Resumes, from a later pass's root before it prepares, each Checkpoint
/// park an ended pass cut that this pass may take, one write per park: the
/// rechecks, the unpark, its released lease and the resume edge commit
/// together or not at all. Best-effort: a miss or an error leaves the park
/// exactly as it was.
pub(crate) fn resume_checkpoints_for_wake(vault: &Vault, later: &LaterWake<'_>) {
    let store = DreamerRunnerStore::new(vault);
    // Read-only first, so a park this pass may not take opens no write.
    let due = match store.checkpoint_resumes_due() {
        Ok(due) => due,
        Err(error) => {
            skipped(&error, "checkpoint resume");
            return;
        }
    };
    let mut changed = false;
    // A Retry park waits out its delay at this site too (Engine 10-21).
    for park in due
        .iter()
        .filter(|park| park.due_at <= later.now && park.attempt.accepts_worker(later.worker))
    {
        let resumed = vault.with_write_txn_grouped(|wtxn| {
            resume_checkpoint_in_txn(vault, wtxn, &store, park.attempt.id, later)
        });
        match resumed {
            Ok(moved) => changed |= moved,
            Err(error) => skipped(&error, "checkpoint resume"),
        }
    }
    // The deadline lane arms the queued tries, and a moved home, at once.
    if changed {
        vault.store.notify_proactivity_changes();
    }
}

/// One checked Checkpoint resume; `true` when it resumed the park or the
/// MACRO home election it ran moved the home.
fn resume_checkpoint_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    store: &DreamerRunnerStore<'_>,
    attempt: AttemptId,
    later: &LaterWake<'_>,
) -> Result<bool> {
    let Some((status, Some(park))) = store.status_with_park_in_txn(wtxn, attempt)? else {
        return Ok(false);
    };
    // A Retry park resumes only once its delay passed, on the clock it
    // parked by.
    if park.later_pass_due_at().is_none_or(|due| due > later.now) {
        return Ok(false);
    }
    let record = &status.attempt;
    let Some(cut) = checkpoint_resumable_in_txn(vault, wtxn, &park, record)? else {
        return Ok(false);
    };
    if cut.row.wake == later.wake || !record.accepts_worker(later.worker) {
        return Ok(false);
    }
    if record.kind == DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND {
        // MACRO admission's own rules, in its own order: the vault identity
        // is this pass's node, and after the election admission runs first,
        // that node is the elected home.
        if crate::identity::load_or_mint_client_id_in_txn(vault, wtxn)? != later.local_node_id {
            return Ok(false);
        }
        let moved =
            crate::dreamer_runner::reelect_home_in_txn(&vault.store, wtxn, vault.privacy_posture());
        let home = store
            .home_node_designation_in_txn(wtxn)?
            .is_some_and(|home| home.node_id == later.local_node_id);
        if !home {
            return Ok(moved);
        }
    }
    if store
        .resume_parked_in_txn(wtxn, attempt, &park.park_owner, later.now)?
        .is_none()
    {
        return Err(Error::InvariantViolation(
            "a checked checkpoint resume found no park",
        ));
    }
    // The release must have queued the row again as the same try.
    match store.status_with_park_in_txn(wtxn, attempt)? {
        Some((after, None)) if after.attempt.state == AttemptState::Queued => {}
        _ => {
            return Err(Error::InvariantViolation(
                "a checked checkpoint resume did not release its lease",
            ));
        }
    }
    let mut row = cut.row;
    row.resumed = Some(WakeObservedResume {
        wake: later.wake,
        at: later.now,
        worker: later.worker.to_owned(),
    });
    CHECKPOINTS.put(vault, wtxn, &checkpoint_key(cut.park), &row)?;
    Ok(true)
}
