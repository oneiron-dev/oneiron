//! Who held each code-run wait's reply (FIX 5718, KEY STORE = A; Engine
//! ruling 2): one durable row per run a wait's reply was delivered to, at the
//! generation it parked, naming the actor whose run it is. A wait's settled
//! reply is shared: every run parked on the wait, before or after it settled,
//! is delivered the same reply, and the settled row stays for the parks still
//! to come. A run's waiter and delivery rows go once it resumed, so they are
//! no membership; these rows are, and they outlive them.
//!
//! The actor scrub of an actor's runs' replay replies reaches their waits
//! too ([`erase_actor_wait_holds_in_txn`]), release only. A soft delete's
//! scrub (FIX 15532) marks its runs' memberships Deleted, keeping the actor
//! only so its later erase still selects them (FIX 6591); an erase's marks
//! them Erased. Either leaves each delivery its runs were given its erased
//! form; a code consent wait bound to one of its runs, which that run alone
//! holds, keeps its settled row in its erased form too. Every other holder's
//! membership and delivery, a shared settled reply, and a consent wait's
//! digests and receipts stay. Nothing is deleted for want of a waiter.
//!
//! The erase fences every later delivery and read of the actor's runs
//! ([`holder_erased_in_txn`]): a run whose membership is erased, whose
//! replies are erased or whose actor is gone is delivered the reply's erased
//! form, parks on nothing and reads a typed unavailable, so no membership
//! written after the erase brings the reply back. Such a late membership
//! says Erased once the actor's hard erasure is complete (its hard-delete
//! marker), since no later erase reaches it, and Deleted for any other gone
//! actor, a soft-deleted one or one a pending delete removed (FIX 6591).
//!
//! A connector call's caller holds its own call's settled reply too (part 3,
//! Engine 10-20 19:5x): `connector.call_status` reads it by the call's ref
//! for that caller and the owner, and no run need hold that copy. Its
//! membership ([`hold_settled_for_caller_in_txn`], written with the settle)
//! names the caller, under [`CALLER_GENERATION`]; the caller's erase marks
//! it Erased, and once no membership of the wait keeps the reply, its
//! settled row takes its erased form. A settle after that erase lands
//! erased. The call's erase records that release before it drops the call
//! row ([`release_settled_for_caller_in_txn`], FIX 19257). A settle that
//! finds no call row then applies the recorded release.
//!
//! Each delivery and settled reply is a row-held response in checkpoint
//! images (`response`, FIX 6588): a settled row's erased form is its final
//! holder's release, which stages the retirement an earlier holder's erase
//! owes the copies older images carry.

mod response;

use std::collections::BTreeSet;

use super::super::consent_wait::code_consent_waits_bound_to_in_txn;
use super::records::REPLAY_RECORDS;
use super::replay_capsule::{actor_gone_in_store, actor_gone_in_txn, actor_hard_erased_in_store};
use super::response_erase::ResponseScrub;
use super::response_owners::response_owner_in_txn;
use super::wait_delivery::{DELIVERIES, SETTLED, SETTLED_TAG, WaitDelivery, WaitKey};
use crate::side_table::{Erased, SideKey, SideTableDbs};
use crate::store::{ResponseDb, Store, response_carrier, settle_shared_response_in_txn};
use crate::{EntityId, Result, Vault};

pub(crate) use self::response::wait_delivery_owners;
use crate::store::executor_wait_delivery::{HOLDERS, WaitHolder, wait_reply_erased};

/// The generation a connector call's caller holds its call's settled reply
/// under (FIX 5718 part 3; CALLS C5718-23): the key names the wait, the
/// caller's actor where a run's id goes, and this generation, which no
/// run's park reaches. Such a row names no run.
const CALLER_GENERATION: u64 = u64::MAX;

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
/// its replies, Deleted for the actor once a soft delete took them (its
/// owner row says so, or the actor its stamps name is gone: FIX 6591) and
/// Erased once that actor's hard erasure is complete
/// ([`drop_hard_erased_actor`]), else the actor its owner row names, or,
/// for a run with none, the actor its turn program runs as or its live run
/// binding names.
fn run_holder_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, run: EntityId) -> Result<WaitHolder> {
    run_holder_in(&vault.store, &vault.store, txn, run)
}

/// [`run_holder_in_txn`], its stamps read through `dbs`: the vault's own
/// tables, or a room session's view composed over them (FIX 6586). Whether
/// the actor is gone is always the answer of the vault's canonical store
/// `base`.
fn run_holder_in(
    base: &Store,
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
) -> Result<WaitHolder> {
    let actor = match response_owner_in_txn(dbs, txn, &run)? {
        Some(owner) if owner.erased() => {
            let held = owner
                .retirement_actor()
                .map_or(WaitHolder::Erased, |actor| WaitHolder::Deleted { actor });
            return drop_hard_erased_actor(base, txn, held);
        }
        Some(owner) => owner.actor(),
        None => match crate::dreamer_runner::program_run_actor_in_txn(dbs, txn, &run)? {
            Some(actor) => Some(actor),
            None => REPLAY_RECORDS
                .get_lenient(dbs, txn, &run)?
                .and_then(|record| record.live_run.as_ref().map(|live| live.actor)),
        },
    };
    match actor {
        Some(actor) if actor_gone_in_store(base, txn, &actor) => {
            drop_hard_erased_actor(base, txn, WaitHolder::Deleted { actor })
        }
        actor => Ok(WaitHolder::Kept { actor }),
    }
}

/// `held` as a late write leaves it (FIX 6591): a Deleted membership whose
/// actor's hard erasure is complete (its hard-delete marker) says Erased,
/// since no later erase of that actor runs to take its id. A soft-deleted
/// actor's, or one a pending delete removed, stays Deleted for the
/// retirement still to come. Any other stays as it is. A marker read error
/// is returned.
fn drop_hard_erased_actor(
    base: &Store,
    txn: &heed::RoTxn<'_>,
    held: WaitHolder,
) -> Result<WaitHolder> {
    Ok(match held {
        WaitHolder::Deleted { actor } if actor_hard_erased_in_store(base, txn, &actor)? => {
            WaitHolder::Erased
        }
        held => held,
    })
}

/// What `key`'s run holds of its wait's reply at `txn`: Erased once its
/// membership or its run says so; Deleted once its membership says so or
/// the actor that membership names is gone (FIX 6591), so a retry never
/// keeps the reply again, and Erased once that actor's hard erasure is
/// complete; else its run's stamps.
fn holder_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, key: &WaitKey) -> Result<WaitHolder> {
    holder_in(&vault.store, &vault.store, txn, key)
}

/// [`holder_in_txn`], its membership and run stamps read through `dbs`, the
/// actor's state from the canonical store `base`.
fn holder_in(
    base: &Store,
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &WaitKey,
) -> Result<WaitHolder> {
    let run = run_holder_in(base, dbs, txn, key.run)?;
    let stamped = HOLDERS.get_lenient(dbs, txn, &holder_key(key))?;
    let gone = |actor: &EntityId| actor_gone_in_store(base, txn, actor);
    match stamped {
        Some(WaitHolder::Erased) => Ok(WaitHolder::Erased),
        _ if matches!(run, WaitHolder::Erased) => Ok(WaitHolder::Erased),
        Some(held @ WaitHolder::Deleted { .. }) => drop_hard_erased_actor(base, txn, held),
        Some(WaitHolder::Kept { actor: Some(actor) }) if gone(&actor) => {
            drop_hard_erased_actor(base, txn, WaitHolder::Deleted { actor })
        }
        _ => Ok(run),
    }
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
/// wait's reply to it does: its row names its run's actor, or says Deleted
/// or Erased once the run reads as erased, and a deleted or erased row
/// stays so. Returns the row as it stands.
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

/// Whether `key`'s run reads its wait's reply as erased, for a room
/// session's run (FIX 6586): its membership and stamps read through the
/// session's composed view `read`, the actor's state from the vault's
/// canonical store `base`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn holder_erased_routed(
    base: &Store,
    read: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    key: &WaitKey,
) -> Result<bool> {
    Ok(holder_in(base, read, txn, key)?.erased())
}

/// [`join_wait_in_txn`] for a room session's run (FIX 6586): the holder is
/// read through the composed view `read` and its row written along the
/// run's route `write`, in the routed writer `wtxn`, so the membership
/// rides with the delivery it joins.
///
/// # Errors
///
/// Storage errors.
pub(super) fn join_wait_routed(
    base: &Store,
    read: &impl SideTableDbs,
    write: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &WaitKey,
) -> Result<WaitHolder> {
    let held = holder_in(base, read, wtxn, key)?;
    HOLDERS.put(write, wtxn, &holder_key(key), &held)?;
    Ok(held)
}

/// Where `key`'s wait stands for its run at `txn`'s revision (FIX 5718): a
/// wait settled for every waiter or delivered to this one is never pending,
/// and it reads as erased once an erase of the run's actor took its replies
/// or its delivered copy holds the erased form, or the erased marker of a
/// retired reply that never decoded (FIX 9390).
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
        Some(bytes) => Some(bytes),
        None => SETTLED.get_bytes(store, txn, &(SETTLED_TAG, key.wait_id))?,
    };
    let Some(copy) = copy else {
        return Ok(WaitReply::Pending);
    };
    if wait_reply_erased(&copy) || holder_erased_in_txn(vault, txn, key)? {
        return Ok(WaitReply::Erased);
    }
    Ok(WaitReply::Delivered)
}

/// Every run whose membership names `actor`: the runs a wait's reply was
/// delivered to as `actor`'s, a soft delete's Deleted membership among them
/// (FIX 6591). A row that does not decode names no actor.
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
            .is_ok_and(|held| held.retirement_actor() == Some(*actor))
        {
            runs.push(run);
        }
    }
    Ok(runs)
}

/// The actor scrub `scrub` of `actor` over its runs' wait replies (FIX
/// 5718), in the delete's or the erase's own writer, release only: each
/// membership that names `actor`, a soft delete's Deleted one included (FIX
/// 6591), or whose run is one of `runs` (its runs, as their replay rows name
/// them) says Deleted for a soft delete, keeping the actor it names, or
/// Erased for an erase; each delivery those runs were given takes its erased
/// form (when
/// it came and the rows its reply was derived from stay, its reply goes);
/// and so does the settled row of each code consent wait bound to one of
/// them, which that run alone holds. Another run's membership and delivery,
/// a shared settled reply, and a consent wait's settlement and consumption
/// digests and receipts stay; a connector call's settled reply whose caller
/// was already released goes once no run keeps it (FIX 19257). A row that does not decode takes the bare
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
    scrub: ResponseScrub,
) -> Result<()> {
    let store = &vault.store;
    let mut held = Vec::new();
    for row in HOLDERS.iter_raw_from(store, wtxn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <(EntityId, EntityId, u64) as SideKey>::decode_key(&key) else {
            continue;
        };
        let holder = HOLDERS.decode_value(&bytes).ok();
        let names = holder.is_some_and(|holder| holder.retirement_actor() == Some(*actor));
        if names || runs.contains(&key.1) {
            held.push((key, holder));
        }
    }
    let mut scope = runs.clone();
    let mut called = BTreeSet::new();
    let mut joined = BTreeSet::new();
    for &((wait, run, generation), _) in &held {
        if generation == CALLER_GENERATION {
            called.insert(wait);
        } else {
            scope.insert(run);
            joined.insert(wait);
        }
    }
    for (key, holder) in held {
        HOLDERS.put(store, wtxn, &key, &scrubbed_holder(scrub, holder, *actor))?;
    }
    for run in &scope {
        let mut delivered = Vec::new();
        for row in DELIVERIES.iter_raw_from(store, wtxn, run.as_bytes())? {
            let (key, bytes) = row?;
            if let Some(key) = <(EntityId, EntityId, u64) as SideKey>::decode_key(&key) {
                let erased = wait_reply_erased(&bytes);
                delivered.push((key, erased, DELIVERIES.decode_value(&bytes).ok()));
            }
        }
        for ((_, wait, generation), erased, delivery) in delivered {
            joined.insert(wait);
            let key = (wait, *run, generation);
            let holder = HOLDERS.get_lenient(store, wtxn, &key)?;
            HOLDERS.put(store, wtxn, &key, &scrubbed_holder(scrub, holder, *actor))?;
            // An erased reply, the marker of an opaque one among them,
            // stays erased as it is (FIX 9390).
            if erased {
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
    for &wait in &called {
        erase_settled_unheld_in_txn(store, wtxn, wait)?;
    }
    // A wait whose caller's erase already released its hold keeps its
    // settled copy only while a run's membership keeps it, so the erase of
    // a run's membership checks that copy again (FIX 19257).
    for &wait in joined.difference(&called) {
        if caller_released_in_txn(store, wtxn, wait)? {
            erase_settled_unheld_in_txn(store, wtxn, wait)?;
        }
    }
    Ok(())
}

/// The membership `prior` once the actor scrub `scrub` of `actor` takes
/// it: Deleted, keeping the actor it names, for a soft delete (FIX 6591),
/// and Erased for an erase.
const fn scrubbed_holder(
    scrub: ResponseScrub,
    prior: Option<WaitHolder>,
    actor: EntityId,
) -> WaitHolder {
    match scrub {
        ResponseScrub::Delete => WaitHolder::deleted(prior, actor),
        ResponseScrub::Erase => WaitHolder::Erased,
    }
}

/// Joins `caller`, the actor whose connector call settles wait `wait_id`,
/// to the wait's holders in `wtxn`, as the reader of its settled reply by
/// `connector.call_status` (FIX 5718 part 3): its row names the caller, or
/// says Deleted for the caller once the caller is gone (FIX 6591), and a
/// deleted or erased row stays so; Erased once the caller's hard erasure is
/// complete (its hard-delete marker). An erased one leaves the settled row
/// its erased form when no other membership of the wait keeps the reply, so
/// a settle that lands after the caller's erase keeps no copy of it.
///
/// # Errors
///
/// Storage errors, and a hard-delete marker read error.
pub(super) fn hold_settled_for_caller_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    caller: EntityId,
) -> Result<()> {
    let store = &vault.store;
    let key = (wait_id, caller, CALLER_GENERATION);
    let prior = HOLDERS.get_lenient(store, wtxn, &key)?;
    let held = if prior.is_some_and(WaitHolder::erased) || actor_gone_in_txn(vault, wtxn, &caller) {
        drop_hard_erased_actor(store, wtxn, WaitHolder::deleted(prior, caller))?
    } else {
        WaitHolder::Kept {
            actor: Some(caller),
        }
    };
    HOLDERS.put(store, wtxn, &key, &held)?;
    if held.erased() {
        erase_settled_unheld_in_txn(store, wtxn, wait_id)?;
    }
    Ok(())
}

/// Releases `caller`'s hold on the settled reply of its connector call's
/// wait `wait_id`, in the erase's writer `wtxn` (FIX 19257). The call's
/// erase runs this before it drops the call row, because only that row
/// names the caller. The caller's membership says Erased even when the
/// wait has not settled yet, so a later settle finds the release with no
/// call row left. It does not wait for the caller's hard-delete marker. A
/// settled reply takes its erased form once no other membership of the
/// wait keeps it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn release_settled_for_caller_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    caller: EntityId,
) -> Result<()> {
    let key = (wait_id, caller, CALLER_GENERATION);
    HOLDERS.put(store, wtxn, &key, &WaitHolder::Erased)?;
    erase_settled_unheld_in_txn(store, wtxn, wait_id)
}

/// Applies a connector caller's recorded release to wait `wait_id`'s
/// settled row, in the settling writer `wtxn`, after every parked run
/// joined (FIX 19257). The settle runs this when it finds no call row. A
/// caller membership of the wait that says Deleted or Erased is the release
/// the call's erase recorded: the settled row takes its erased form once no
/// other membership keeps it. A wait with no such membership stays as it
/// is, so a call row missing for another reason releases nothing.
///
/// # Errors
///
/// Storage errors.
pub(super) fn apply_caller_release_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
) -> Result<()> {
    if caller_released_in_txn(store, wtxn, wait_id)? {
        erase_settled_unheld_in_txn(store, wtxn, wait_id)?;
    }
    Ok(())
}

/// Whether a caller membership of `wait_id`, under [`CALLER_GENERATION`],
/// says Deleted or Erased (FIX 19257). A row that does not decode is no
/// release.
fn caller_released_in_txn(store: &Store, txn: &heed::RoTxn<'_>, wait_id: EntityId) -> Result<bool> {
    for row in HOLDERS.iter_raw_from(store, txn, wait_id.as_bytes())? {
        let (key, bytes) = row?;
        let caller = matches!(
            <(EntityId, EntityId, u64) as SideKey>::decode_key(&key),
            Some((_, _, CALLER_GENERATION))
        );
        if caller && HOLDERS.decode_value(&bytes).is_ok_and(WaitHolder::erased) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Leaves `wait_id`'s settled row its erased form when every membership of
/// the wait says Deleted or Erased: no holder keeps its reply. A membership
/// that does not decode keeps it, so no shared reply goes on a row that
/// cannot be read.
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
/// reply goes. One that does not decode takes the bare erased form; the
/// erased marker of an opaque one is erased already, and stays (FIX 9390).
fn erase_settled_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
) -> Result<()> {
    let key = (SETTLED_TAG, wait_id);
    let Some(bytes) = SETTLED.get_bytes(store, wtxn, &key)? else {
        return Ok(());
    };
    if wait_reply_erased(&bytes) {
        return Ok(());
    }
    let settled = SETTLED.decode_value(&bytes).ok();
    let erased = Erased::of(settled.unwrap_or_else(unreadable_delivery))?;
    SETTLED.put_erased(store, wtxn, &key, erased)?;
    // Its reply's final holder released it: a retirement an earlier
    // holder's erase owes the copies older images carry is staged now (FIX
    // 6588).
    let carrier = response_carrier(ResponseDb::VaultMeta, &SETTLED.key_bytes(&key));
    settle_shared_response_in_txn(store, wtxn, &carrier)
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
