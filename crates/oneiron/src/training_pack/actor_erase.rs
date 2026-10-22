//! An erased owner out of the training rows that name it (FIX 3520): the
//! runs, and the role-swap receipts in both tables that keep them; and any
//! erased row out of the runs' source rows (FIX 6933).

use super::{ROLES, RUNS, SWAPS, TrainingState};
use crate::Vault;
use crate::deletion::names_no_actor;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Erasing `actor` from the training runs (FIX 3520). A run it prepared that
/// has not gone to the host yet (prepared, or authorized and not
/// dispatched) is an act still to run, so it goes; a run it authorized for
/// someone else's prepared spec goes back to prepared, its authorization
/// gone. A dispatched, failed, returned, scored or bound run keeps its
/// evidence and names no one. One-way, in the erase's own transaction. An
/// id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a run row that cannot be read.
pub(crate) fn erase_run_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut runs = Vec::new();
    for (key, mut run) in RUNS.scan(&vault.store, wtxn)? {
        let owned = run.owner.forget(*actor);
        let authorized = run
            .authorization
            .as_mut()
            .is_some_and(|authorization| authorization.owner.forget(*actor));
        if owned || authorized {
            runs.push((key, run, owned, authorized));
        }
    }
    for (key, mut run, owned, authorized) in runs {
        let pending = matches!(
            run.state,
            TrainingState::Prepared | TrainingState::Authorized
        );
        if pending && owned {
            RUNS.delete(&vault.store, wtxn, &key)?;
            continue;
        }
        if pending && authorized {
            run.state = TrainingState::Prepared;
            run.authorization = None;
            run.hold = None;
        }
        RUNS.put(&vault.store, wtxn, &key, &run)?;
    }
    Ok(())
}

/// Drops an erased row `id` from every training run's source rows (FIX
/// 6933), whatever `id` names: each run keeps its plan, spec, corpus,
/// consent, compute, state, evidence and owner, and an unknown set stays
/// unknown. A source alone never cancels a run or touches its
/// authorization.
///
/// # Errors
///
/// Storage errors, or a run row that cannot be read.
pub(crate) fn erase_run_source_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut runs = Vec::new();
    for (key, mut run) in RUNS.scan(&vault.store, wtxn)? {
        if crate::skill_optimize::forget_source_row(&mut run.source_rows, id) {
            runs.push((key, run));
        }
    }
    for (key, run) in runs {
        RUNS.put(&vault.store, wtxn, &key, &run)?;
    }
    Ok(())
}

/// The run table's declared scrub: [`erase_run_actor_in_txn`] once, for an
/// erased actor, then [`erase_run_source_in_txn`] for any erased row.
///
/// # Errors
///
/// As either.
pub(crate) fn erase_run_id_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    erase_run_actor_in_txn(vault, wtxn, id)?;
    erase_run_source_in_txn(vault, wtxn, id)
}

/// Erasing `actor` from the role-swap receipts (FIX 3520): each swap it
/// approved keeps its binding, checks, choice and time and names no one.
/// One-way, in the erase's own transaction. An id whose entity is no actor
/// scans nothing.
///
/// # Errors
///
/// Storage errors, or a receipt row that cannot be read.
pub(crate) fn erase_swap_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut receipts = Vec::new();
    for (key, mut receipt) in SWAPS.scan(&vault.store, wtxn)? {
        if receipt.owner.forget(*actor) {
            receipts.push((key, receipt));
        }
    }
    for (key, receipt) in receipts {
        SWAPS.put(&vault.store, wtxn, &key, &receipt)?;
    }
    Ok(())
}

/// Erasing `actor` from each role's current swap receipt (FIX 3520), the
/// copy [`erase_swap_actor_in_txn`] scrubs in the swap log: the role keeps
/// its checkpoint and binding, and the receipt names no one. One-way, in the
/// erase's own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a receipt row that cannot be read.
pub(crate) fn erase_role_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut receipts = Vec::new();
    for (key, mut receipt) in ROLES.scan(&vault.store, wtxn)? {
        if receipt.owner.forget(*actor) {
            receipts.push((key, receipt));
        }
    }
    for (key, receipt) in receipts {
        ROLES.put(&vault.store, wtxn, &key, &receipt)?;
    }
    Ok(())
}
