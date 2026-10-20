//! Who held each code-run wait's reply (FIX 5718, KEY STORE = A; Engine
//! ruling 2): one durable row per run a wait's reply was delivered to, at the
//! generation it parked, naming the actor whose run it is. A wait's settled
//! reply is shared: every run parked on the wait, before or after it settled,
//! is delivered the same reply, and the settled row stays for the parks still
//! to come. A run's waiter and delivery rows go once it resumed, so they are
//! no membership; these rows are, and they outlive them.
//!
//! An erase of an actor ([`erase_actor_wait_holds_in_txn`], from the same
//! actor scrub as its runs' replay replies, so a soft delete runs it too and
//! it only releases) marks its runs' memberships erased and leaves each
//! delivery its runs were given its erased form; a code consent wait bound to
//! one of its runs, which that run alone holds, keeps its settled row in its
//! erased form too. Every other holder's membership and delivery, a shared
//! settled reply, and a consent wait's digests and receipts stay. Nothing is
//! deleted for want of a waiter.
//!
//! The erase fences every later delivery and read of the actor's runs
//! ([`holder_erased_in_txn`]): a run whose membership is erased, whose
//! replies are erased or whose actor is gone is delivered the reply's erased
//! form, parks on nothing and reads a typed unavailable, so no membership
//! written after the erase brings the reply back.
//!
//! A connector call's caller holds its own call's settled reply too (part 3,
//! Engine 10-20 19:5x): `connector.call_status` reads it by the call's ref
//! for that caller and the owner, and no run need hold that copy. Its
//! membership ([`hold_settled_for_caller_in_txn`], written with the settle)
//! names the caller, under [`CALLER_GENERATION`]; the caller's erase marks
//! it Erased, and once no membership of the wait keeps the reply, its
//! settled row takes its erased form. A settle after that erase lands
//! erased.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::super::consent_wait::code_consent_waits_bound_to_in_txn;
use super::records::REPLAY_RECORDS;
use super::replay_capsule::actor_gone_in_txn;
use super::response_owners::response_owner_in_txn;
use super::wait_delivery::{DELIVERIES, SETTLED, SETTLED_TAG, WaitDelivery, WaitKey};
use crate::side_table::{self, Erased, Named, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// The rows. Key: id16(wait) + id16(run) + be64(generation).
const HOLDERS: SideTable<(EntityId, EntityId, u64), WaitHolder, Named> =
    SideTable::new(&side_table::CODE_RUN_WAIT_HOLDER);

/// The generation a connector call's caller holds its call's settled reply
/// under (FIX 5718 part 3; CALLS C5718-23): the key names the wait, the
/// caller's actor where a run's id goes, and this generation, which no
/// run's park reaches. Such a row names no run.
const CALLER_GENERATION: u64 = u64::MAX;

/// What one run holds of a wait's reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum WaitHolder {
    /// The reply, for `actor`'s run, when its run's stamps name one.
    Kept { actor: Option<EntityId> },
    /// Its run's actor was erased: the reply reads as erased for it, for
    /// good.
    Erased,
}

impl WaitHolder {
    const fn actor(self) -> Option<EntityId> {
        match self {
            Self::Kept { actor } => actor,
            Self::Erased => None,
        }
    }

    pub(super) const fn erased(self) -> bool {
        matches!(self, Self::Erased)
    }
}

/// Where a run's wait stands for it (FIX 5718).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitReply {
    /// No reply yet.
    Pending,
    /// A reply the run reads.
    Delivered,
    /// A reply that came, which an erase of the run's actor took: the wait
    /// is settled, and the run never reads it.
    Erased,
}

const fn holder_key(key: &WaitKey) -> (EntityId, EntityId, u64) {
    (key.wait_id, key.run, key.generation)
}

/// What run `run` holds as its writes stamped it: Erased once an erase took
/// its replies (its owner row says so, or the actor it names is gone), else
/// the actor its owner row names, or, for a run with none, the actor its
/// turn program runs as or its live run binding names.
fn run_holder_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, run: EntityId) -> Result<WaitHolder> {
    let store = &vault.store;
    let actor = match response_owner_in_txn(store, txn, &run)? {
        Some(owner) if owner.erased() => return Ok(WaitHolder::Erased),
        Some(owner) => owner.actor(),
        None => match crate::dreamer_runner::program_run_actor_in_txn(store, txn, &run)? {
            Some(actor) => Some(actor),
            None => REPLAY_RECORDS
                .get_lenient(store, txn, &run)?
                .and_then(|record| record.live_run.as_ref().map(|live| live.actor)),
        },
    };
    if actor.is_some_and(|actor| actor_gone_in_txn(vault, txn, &actor)) {
        return Ok(WaitHolder::Erased);
    }
    Ok(WaitHolder::Kept { actor })
}

/// What `key`'s run holds of its wait's reply at `txn`: Erased once its
/// membership says so, the actor that membership names is gone, or its run
/// reads as erased; else its run's stamps.
fn holder_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, key: &WaitKey) -> Result<WaitHolder> {
    let run = run_holder_in_txn(vault, txn, key.run)?;
    let stamped = HOLDERS.get_lenient(&vault.store, txn, &holder_key(key))?;
    let gone = |actor: &EntityId| actor_gone_in_txn(vault, txn, actor);
    Ok(match stamped {
        Some(WaitHolder::Erased) => WaitHolder::Erased,
        Some(WaitHolder::Kept { actor: Some(actor) }) if gone(&actor) => WaitHolder::Erased,
        _ => run,
    })
}

/// Whether `key`'s run reads its wait's reply as erased (FIX 5718): an erase
/// of its actor took its replies, before or after the reply came.
///
/// # Errors
///
/// Storage errors.
pub(super) fn holder_erased_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &WaitKey,
) -> Result<bool> {
    Ok(holder_in_txn(vault, txn, key)?.erased())
}

/// Joins `key`'s run to its wait's holders in `wtxn`, as a delivery of the
/// wait's reply to it does: its row names its run's actor, or says Erased
/// once the run reads as erased, and an erased row stays erased. Returns
/// the row as it stands.
///
/// # Errors
///
/// Storage errors.
pub(super) fn join_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
) -> Result<WaitHolder> {
    let held = holder_in_txn(vault, wtxn, key)?;
    HOLDERS.put(&vault.store, wtxn, &holder_key(key), &held)?;
    Ok(held)
}

/// Where `key`'s wait stands for its run at `txn`'s revision (FIX 5718): a
/// wait settled for every waiter or delivered to this one is never pending,
/// and it reads as erased once an erase of the run's actor took its replies
/// or its delivered copy holds the erased form.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn wait_reply_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &WaitKey,
) -> Result<WaitReply> {
    let store = &vault.store;
    let row = (key.run, key.wait_id, key.generation);
    let copy = match DELIVERIES.get_bytes(store, txn, &row)? {
        Some(bytes) => Some(DELIVERIES.decode_value(&bytes).ok()),
        None => SETTLED
            .get_bytes(store, txn, &(SETTLED_TAG, key.wait_id))?
            .map(|bytes| SETTLED.decode_value(&bytes).ok()),
    };
    let Some(copy) = copy else {
        return Ok(WaitReply::Pending);
    };
    let erased_copy = copy.is_some_and(|copy| copy.erased);
    if erased_copy || holder_erased_in_txn(vault, txn, key)? {
        return Ok(WaitReply::Erased);
    }
    Ok(WaitReply::Delivered)
}

/// Every run whose membership names `actor`: the runs a wait's reply was
/// delivered to as `actor`'s. A row that does not decode names no actor.
///
/// # Errors
///
/// Storage errors.
pub(super) fn wait_holder_runs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut runs = Vec::new();
    for row in HOLDERS.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Some((_, run, generation)) = <(EntityId, EntityId, u64) as SideKey>::decode_key(&key)
        else {
            continue;
        };
        if generation == CALLER_GENERATION {
            continue;
        }
        if HOLDERS
            .decode_value(&bytes)
            .is_ok_and(|held| held.actor() == Some(*actor))
        {
            runs.push(run);
        }
    }
    Ok(runs)
}

/// The actor scrub of `actor` over its runs' wait replies (FIX 5718), in the
/// erase's own writer, release only: each membership that names `actor` or
/// whose run is one of `runs` (its runs, as their replay rows name them) says
/// Erased; each delivery those runs were given takes its erased form (when
/// it came and the rows its reply was derived from stay, its reply goes);
/// and so does the settled row of each code consent wait bound to one of
/// them, which that run alone holds. Another run's membership and delivery,
/// a shared settled reply, and a consent wait's settlement and consumption
/// digests and receipts stay. A row that does not decode takes the bare
/// erased form, so it never fails the erase.
///
/// # Errors
///
/// Storage errors.
pub(super) fn erase_actor_wait_holds_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
    runs: &BTreeSet<EntityId>,
) -> Result<()> {
    let store = &vault.store;
    let mut held = Vec::new();
    for row in HOLDERS.iter_raw_from(store, wtxn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <(EntityId, EntityId, u64) as SideKey>::decode_key(&key) else {
            continue;
        };
        let names = HOLDERS
            .decode_value(&bytes)
            .is_ok_and(|holder| holder.actor() == Some(*actor));
        if names || runs.contains(&key.1) {
            held.push(key);
        }
    }
    let mut scope = runs.clone();
    let mut called = BTreeSet::new();
    for &(wait, run, generation) in &held {
        if generation == CALLER_GENERATION {
            called.insert(wait);
        } else {
            scope.insert(run);
        }
    }
    for key in held {
        HOLDERS.put(store, wtxn, &key, &WaitHolder::Erased)?;
    }
    for run in &scope {
        let mut delivered = Vec::new();
        for row in DELIVERIES.iter_raw_from(store, wtxn, run.as_bytes())? {
            let (key, bytes) = row?;
            if let Some(key) = <(EntityId, EntityId, u64) as SideKey>::decode_key(&key) {
                delivered.push((key, DELIVERIES.decode_value(&bytes).ok()));
            }
        }
        for ((_, wait, generation), delivery) in delivered {
            HOLDERS.put(store, wtxn, &(wait, *run, generation), &WaitHolder::Erased)?;
            if delivery.as_ref().is_some_and(|delivery| delivery.erased) {
                continue;
            }
            let erased = Erased::of(delivery.unwrap_or_else(unreadable_delivery))?;
            DELIVERIES.put_erased(store, wtxn, &(*run, wait, generation), erased)?;
        }
    }
    for wait in code_consent_waits_bound_to_in_txn(vault, wtxn, &scope)? {
        erase_settled_in_txn(store, wtxn, wait)?;
    }
    // A connector call's settled copy its caller held goes once no other
    // membership of the wait keeps it.
    for wait in called {
        erase_settled_unheld_in_txn(store, wtxn, wait)?;
    }
    Ok(())
}

/// Joins `caller`, the actor whose connector call settles wait `wait_id`,
/// to the wait's holders in `wtxn`, as the reader of its settled reply by
/// `connector.call_status` (FIX 5718 part 3): its row names the caller, or
/// says Erased once the caller is gone, and an erased row stays erased.
/// An erased one leaves the settled row its erased form when no other
/// membership of the wait keeps the reply, so a settle that lands after the
/// caller's erase keeps no copy of it.
///
/// # Errors
///
/// Storage errors.
pub(super) fn hold_settled_for_caller_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    caller: EntityId,
) -> Result<()> {
    let store = &vault.store;
    let key = (wait_id, caller, CALLER_GENERATION);
    let held = match HOLDERS.get_lenient(store, wtxn, &key)? {
        Some(WaitHolder::Erased) => WaitHolder::Erased,
        _ if actor_gone_in_txn(vault, wtxn, &caller) => WaitHolder::Erased,
        _ => WaitHolder::Kept {
            actor: Some(caller),
        },
    };
    HOLDERS.put(store, wtxn, &key, &held)?;
    if held.erased() {
        erase_settled_unheld_in_txn(store, wtxn, wait_id)?;
    }
    Ok(())
}

/// Leaves `wait_id`'s settled row its erased form when every membership of
/// the wait says Erased: no holder keeps its reply. A membership that does
/// not decode keeps it, so no shared reply goes on a row that cannot be
/// read.
fn erase_settled_unheld_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
) -> Result<()> {
    for row in HOLDERS.iter_raw_from(store, wtxn, wait_id.as_bytes())? {
        let (_, bytes) = row?;
        if !HOLDERS.decode_value(&bytes).is_ok_and(WaitHolder::erased) {
            return Ok(());
        }
    }
    erase_settled_in_txn(store, wtxn, wait_id)
}

/// Leaves code consent wait `wait_id`'s settled row its erased form in
/// `wtxn` when `run`, the one run bound to it, reads as erased (FIX 5718): a
/// settle that lands after that run's actor was erased keeps its outcome,
/// its receipt and the digest of the reply it delivered, and no copy of the
/// reply.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_settled_reply_of_erased_run_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    run: EntityId,
) -> Result<()> {
    if run_holder_in_txn(vault, wtxn, run)?.erased() {
        erase_settled_in_txn(&vault.store, wtxn, wait_id)?;
    }
    Ok(())
}

/// Leaves `wait_id`'s settled row its erased form in `wtxn`, when it has
/// one: when it settled and the rows its reply was derived from stay, its
/// reply goes. One that does not decode takes the bare erased form.
fn erase_settled_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
) -> Result<()> {
    let key = (SETTLED_TAG, wait_id);
    let Some(bytes) = SETTLED.get_bytes(store, wtxn, &key)? else {
        return Ok(());
    };
    let settled = SETTLED.decode_value(&bytes).ok();
    if settled.as_ref().is_some_and(|settled| settled.erased) {
        return Ok(());
    }
    let erased = Erased::of(settled.unwrap_or_else(unreadable_delivery))?;
    SETTLED.put_erased(store, wtxn, &key, erased)
}

/// What an erase leaves of a delivery row that does not decode: a delivery
/// with no reply, time or rows.
fn unreadable_delivery() -> WaitDelivery {
    WaitDelivery {
        reply: String::new(),
        delivered_at_ms: 0,
        source_rows: None,
        erased: true,
    }
}
