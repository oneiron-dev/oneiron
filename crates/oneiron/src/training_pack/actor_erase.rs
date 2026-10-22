//! An erased owner out of the training rows that name it (FIX 3520): the
//! runs, and the role-swap receipts in both tables that keep them.

use super::{ROLES, RUNS, SWAPS, TrainingState};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the training rows.
use crate::deletion::names_no_actor;

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
