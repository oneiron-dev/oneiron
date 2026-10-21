//! The run fence on a symbol declaration (FIX 6867, G1 PR2b): a leased run's
//! declaration names the try, lease and repo ref it was made under, and the
//! run names it back by its declaration id alone. Every new declaration and
//! every reacquisition mints a fresh id, the same holder's included, and a
//! renewal keeps it, so a released, replaced or expired declaration never
//! answers to an old handle. These run-only helpers judge in the caller's
//! transaction, against the same table, TTL and overlap rule as the
//! scheduler; the owner's declare, renew, release and expiry are unchanged.
//! Symbols order work; they veto none: an overlap leaves a declaration
//! waiting, never refused.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{LEASES, SymbolLease, blockers, load, save, validate_declaration};
use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// The leased run a declaration was made under: its try, that try's lease
/// owner and generation, and the repo and full ref its work is on. The
/// holder is the declaration's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolLeaseRun {
    pub attempt: AttemptId,
    pub lease_owner: String,
    pub generation: u32,
    /// The CODE anchor the run's work is on.
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
}

/// What a run's declaration answers to: its id, the TASK it is held under,
/// its holder and the run that made it. The run names only the id; the rest
/// is the host binding's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolLeaseFence {
    pub declaration_id: EntityId,
    pub task: EntityId,
    pub holder: EntityId,
    pub run: SymbolLeaseRun,
}

impl SymbolLeaseFence {
    /// Whether `lease` is this fence's declaration: the same id, TASK,
    /// holder and run.
    fn names(&self, lease: &SymbolLease) -> bool {
        lease.declaration_id == self.declaration_id
            && lease.task_ref == self.task.to_hex()
            && lease.holder_ref == self.holder.to_hex()
            && lease.run.as_ref() == Some(&self.run)
    }
}

/// A run's fresh declaration of `symbols` on `task`, as `holder`, in `txn`,
/// under a fresh id: the declaration and the TASKs whose live overlapping
/// declarations it waits behind (empty when held). It replaces the same
/// holder's earlier declaration of `task`, held or not, so that one's id no
/// longer answers. `None` when another holder's unexpired declaration holds
/// `task`: a run never takes it over.
///
/// # Errors
/// An invalid symbol set or lifetime, a TASK or holder that is not there,
/// or a store failure.
#[expect(
    clippy::too_many_arguments,
    reason = "one declaration's TASK, holder, run, symbols, lifetime and clock"
)]
pub(crate) fn declare_symbols_for_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    holder: EntityId,
    run: SymbolLeaseRun,
    symbols: BTreeSet<String>,
    ttl_seconds: u64,
    now: u64,
) -> Result<Option<(SymbolLease, Vec<EntityId>)>> {
    validate_declaration(&symbols, ttl_seconds)?;
    if vault.get_entity_type_in_txn(txn, &task)? != Some(crate::registry::ENTITY_TYPE_TASK)
        || vault.get_entity_type_in_txn(txn, &holder)?.is_none()
    {
        return Err(Error::EntityNotFound);
    }
    if let Some(prior) = load(&vault.store, txn, task)?
        && prior.expires_at > now
        && prior.holder_ref != holder.to_hex()
    {
        return Ok(None);
    }
    let blocked = blockers(&vault.store, txn, task, &symbols, now)?;
    let lease = SymbolLease {
        task_ref: task.to_hex(),
        holder_ref: holder.to_hex(),
        symbols,
        expires_at: now
            .checked_add(ttl_seconds)
            .ok_or(Error::ArithmeticOverflow("symbol lease expiry"))?,
        held: blocked.is_empty(),
        ttl_seconds,
        declaration_id: EntityId::now(),
        run: Some(run),
    };
    save(&vault.store, txn, task, &lease)?;
    Ok(Some((lease, blocked)))
}

/// The CALL "FIX 6867 run-only waiting renewal": extends the declaration
/// `fence` names by its declared lifetime, in `txn`, keeping its id and its
/// held state; a waiting one stays waiting and steals nothing. `None` when
/// the declaration is missing, released, replaced or expired: only a fresh
/// declaration reacquires.
///
/// # Errors
/// Expiry overflow or a store failure.
pub(crate) fn renew_symbols_for_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fence: &SymbolLeaseFence,
    now: u64,
) -> Result<Option<SymbolLease>> {
    let Some(mut lease) = admit_symbol_fence_in_txn(vault, txn, fence, now)? else {
        return Ok(None);
    };
    lease.expires_at = now
        .checked_add(lease.ttl_seconds)
        .ok_or(Error::ArithmeticOverflow("symbol lease expiry"))?;
    save(&vault.store, txn, fence.task, &lease)?;
    Ok(Some(lease))
}

/// Removes the declaration `fence` names, in `txn`. False, and nothing
/// removed, when it is missing, released, replaced or expired.
///
/// # Errors
/// A store failure.
pub(crate) fn release_symbols_for_run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fence: &SymbolLeaseFence,
    now: u64,
) -> Result<bool> {
    if admit_symbol_fence_in_txn(vault, txn, fence, now)?.is_none() {
        return Ok(false);
    }
    LEASES.delete(&vault.store, txn, &fence.task)
}

/// The declaration `fence` names, read in `txn`, while it is its TASK's
/// current declaration and unexpired: held, or waiting behind an overlap,
/// which is no staleness. `None` when it is missing, released, replaced or
/// expired.
///
/// # Errors
/// A store failure.
pub(crate) fn admit_symbol_fence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fence: &SymbolLeaseFence,
    now: u64,
) -> Result<Option<SymbolLease>> {
    Ok(load(&vault.store, txn, fence.task)?
        .filter(|lease| fence.names(lease) && lease.expires_at > now))
}

/// The current declaration of `task`, read in `txn`, when `holder` made it
/// under `run` and it is unexpired: the run's own declaration, whichever id
/// it holds now. `None` when the TASK has none of this run's.
///
/// # Errors
/// A store failure.
pub(crate) fn run_declaration_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    holder: EntityId,
    run: &SymbolLeaseRun,
    now: u64,
) -> Result<Option<SymbolLease>> {
    Ok(load(&vault.store, txn, task)?.filter(|lease| {
        lease.holder_ref == holder.to_hex()
            && lease.run.as_ref() == Some(run)
            && lease.expires_at > now
    }))
}

/// The live declarations of other TASKs that overlap `symbols` (CALL "FIX
/// 6867 run-only overlap granularity"), read in `txn`: each such TASK with
/// the id of the declaration that holds it now, in table order.
///
/// # Errors
/// A store failure or a stored TASK ref that does not parse.
pub(crate) fn symbol_blockers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    symbols: &BTreeSet<String>,
    now: u64,
) -> Result<Vec<(EntityId, EntityId)>> {
    let mut blocked = Vec::new();
    for (_, lease) in LEASES.scan(&vault.store, txn)? {
        let other = EntityId::from_hex(&lease.task_ref)?;
        if other != task
            && lease.held
            && lease.expires_at > now
            && !lease.symbols.is_disjoint(symbols)
        {
            blocked.push((other, lease.declaration_id));
        }
    }
    Ok(blocked)
}

/// Whether the declaration `declaration` still holds `task`, read in `txn`:
/// it is that TASK's current declaration, held and unexpired. A release,
/// an expiry or a replacement ends it.
///
/// # Errors
/// A store failure.
pub(crate) fn declaration_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    declaration: EntityId,
    now: u64,
) -> Result<bool> {
    Ok(load(&vault.store, txn, task)?.is_some_and(|lease| {
        lease.declaration_id == declaration && lease.held && lease.expires_at > now
    }))
}
