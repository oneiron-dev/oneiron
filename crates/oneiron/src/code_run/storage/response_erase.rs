//! An erase of a code run's actor, over the reply content its runs kept
//! (FIX 5718, KEY STORE = A): the replay rows (a run's own and its write
//! receipts', bridge outcomes and output previews) and the bodies of the
//! outputs that hold reply content.
//!
//! The actor scrub ([`erase_actor_responses_in_txn`], from the capsule
//! table's one callback) runs on a soft delete too, so it only releases: each
//! record keeps what its run did and loses what it was answered
//! ([`super::replay_bodies::erase_replies`]), each reply body's occurrence
//! is released with its own taint and secret marks, and the record's owner
//! row says Erased. Another holder of the same bytes keeps them. The hard
//! erase cause comes from the provenance door alone
//! ([`retire_actor_responses_in_txn`], called with the erase's own cause):
//! it retires the body instances of the same occurrences, and of the
//! actor's capsules' request, start and fork answers (FIX 6278), gathered
//! before anything releases them.
//!
//! Every later write of a record meets the erase in its own writer
//! ([`fence_replay_in_txn`]): a record whose owner row is erased, or whose
//! actor is gone, is written in its erased form, and the reply bodies it
//! names are released.
//!
//! The same scrub reaches the replies the actor's runs were delivered by
//! their waits (part 2, Engine ruling 2, `wait_holders`): the runs a wait's
//! membership names as the actor's join its scope, so the reply bodies they
//! resumed with are released here and retired by the hard erase, an
//! instance another holder keeps waiting on that holder's release.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use super::super::replay::{CodeRunRawOutput, CodeRunReplayRecord, ResultOccurrence};
use super::records::{RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS, REPLAY_RECORDS};
use super::replay_bodies::erase_replies;
use super::replay_capsule::{actor_gone_in_txn, capsule_bodies_in_txn, names_no_actor};
use super::response_owners::{
    ResponseOwner, mark_response_erased_in_txn, owner_rows_of_in_txn, response_owner_in_txn,
};
use super::spawn_erase::fence_spawn_targets_in_txn;
use super::wait_holders::{erase_actor_wait_holds_in_txn, wait_holder_runs_in_txn};
use crate::engine_executor::holds_reply_content;
use crate::provenance::body::{owned_body_in_txn, release_body_in_txn};
use crate::side_table::{Erased, SideKey};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// One body occurrence a run holds: the run, the path and the body's handle.
type Occurrence = (EntityId, String, String);

/// The actor scrub of `actor` over its runs' reply content, in the erase's
/// own writer: each replay record whose replies are `actor`'s (its owner
/// rows, a live run binding or a turn program's attempt naming it, the runs
/// of its capsules, `runs`, and the runs a wait's membership names as its)
/// is put back in its erased form, past the side-row wall, the reply bodies
/// it names are released, and its owner row says Erased; then the wait
/// replies those runs were delivered take their erased form (FIX 5718 part
/// 2). A record that does not decode keeps its row as it is, and erasing an
/// erased one again changes nothing. Nothing retires here: a soft delete
/// runs this too.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn erase_actor_responses_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
    runs: &[EntityId],
) -> Result<()> {
    let store = &vault.store;
    let mut scope = runs.to_vec();
    scope.extend(wait_holder_runs_in_txn(store, wtxn, actor)?);
    let records = actor_records_in_txn(store, wtxn, actor, &scope)?;
    for (&record_id, &run) in &records {
        if let Some(record) = REPLAY_RECORDS.get_lenient(store, wtxn, &record_id)? {
            release_reply_outputs_in_txn(store, wtxn, record.run_id, &record.outputs)?;
            REPLAY_RECORDS.put_erased(store, wtxn, &record_id, Erased::of(record)?)?;
        }
        mark_response_erased_in_txn(store, wtxn, record_id, run)?;
    }
    let held: BTreeSet<EntityId> = records
        .into_iter()
        .flat_map(|(id, run)| [id, run])
        .collect();
    erase_actor_wait_holds_in_txn(vault, wtxn, actor, &held)
}

/// `record` as its writer may put it, read in that writer (FIX 5718): as
/// given while its replies are kept, else its erased form, the reply bodies
/// it names released and its owner row erased. Its replies are erased once
/// its owner row says so, or once the actor that row or its live run
/// binding names is gone.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn fence_replay_in_txn<'r>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    mut record: Cow<'r, CodeRunReplayRecord>,
) -> Result<Cow<'r, CodeRunReplayRecord>> {
    // A spawn whose target an erase took keeps no ask, whether or not its
    // run's replies are erased (FIX 9180).
    record = fence_spawn_targets_in_txn(&vault.store, wtxn, record)?;
    let owner = response_owner_in_txn(&vault.store, wtxn, &record.run_id)?;
    let stamped = owner.and_then(ResponseOwner::actor);
    let live = record.live_run.as_ref().map(|live| live.actor);
    let txn: &heed::RoTxn<'_> = wtxn;
    let erased = owner.is_some_and(ResponseOwner::erased)
        || stamped
            .into_iter()
            .chain(live)
            .any(|actor| actor_gone_in_txn(vault, txn, &actor));
    if !erased {
        return Ok(record);
    }
    let run = owner.map_or(record.run_id, |owner| owner.run);
    release_reply_outputs_in_txn(&vault.store, wtxn, record.run_id, &record.outputs)?;
    erase_replies(record.to_mut())?;
    mark_response_erased_in_txn(&vault.store, wtxn, record.run_id, run)?;
    Ok(record)
}

/// Whether `actor` is gone here (FIX 5718), in a read transaction of its
/// own: soft-deleted or erased, as a capsule's writer reads it. A read that
/// fails counts as gone.
pub(crate) fn actor_gone(vault: &Vault, actor: &EntityId) -> bool {
    match vault.store.env.read_txn() {
        Ok(rtxn) => actor_gone_in_txn(vault, &rtxn, actor),
        Err(error) => {
            tracing::warn!(%error, "an actor's deletion markers were not read; its content is not kept");
            true
        }
    }
}

/// Whether the replies run `owner`'s record holds are erased (FIX 5718): its
/// owner row says so. A read of one of its results reads it as erased.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn response_erased_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    owner: &EntityId,
) -> Result<bool> {
    Ok(response_owner_in_txn(store, txn, owner)?.is_some_and(ResponseOwner::erased))
}

/// The hard erase of `actor`'s runs' reply content, from the provenance
/// door with the erase's own cause (FIX 5718 ruling 5, FIX 6278), before
/// the actor scrub runs: every reply body occurrence of each record whose
/// replies are `actor`'s, and the request, start and fork-answer bodies of
/// `actor`'s capsules, are released, each with its own marks, and the
/// instance of each whose last holder this releases retires; one another
/// holder keeps owes its retirement to that holder's release. An id whose
/// entity is no actor scans nothing.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn retire_actor_responses_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(store, wtxn, actor)? {
        return Ok(());
    }
    let capsules = capsule_bodies_in_txn(store, wtxn, actor)?;
    let mut runs: Vec<EntityId> = capsules.iter().map(|(run, _, _)| *run).collect();
    // The runs a wait's reply was delivered to as `actor`'s: the bodies they
    // resumed with retire beside their other replies (FIX 5718 part 2).
    runs.extend(wait_holder_runs_in_txn(store, wtxn, actor)?);
    let mut held: Vec<Occurrence> = capsules
        .into_iter()
        .map(|(run, body, path)| (run, path, CodeRunRawOutput::of_ref(body).handle))
        .collect();
    for (record_id, _) in actor_records_in_txn(store, wtxn, actor, &runs)? {
        if let Some(record) = REPLAY_RECORDS.get_lenient(store, wtxn, &record_id)? {
            held.extend(reply_occurrences(record.run_id, &record.outputs));
        }
    }
    let mut digests: BTreeMap<EntityId, Vec<[u8; 32]>> = BTreeMap::new();
    for (owner, path, handle) in held {
        if let Some(digest) = release_occurrence_in_txn(store, wtxn, owner, path, handle)? {
            digests.entry(owner).or_default().push(digest);
        }
    }
    for (owner, released) in digests {
        crate::store::erase_bodies_in_txn(store, wtxn, &owner, &released)?;
    }
    Ok(())
}

/// Every replay record whose replies are `actor`'s, by its run id, with the
/// run its content is: each its owner rows name, the record of each of
/// `runs`, and each record with no owner row whose turn program's attempt or
/// live run binding names `actor`. A record that does not decode names no
/// actor.
fn actor_records_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
    runs: &[EntityId],
) -> Result<BTreeMap<EntityId, EntityId>> {
    let mut records: BTreeMap<EntityId, EntityId> = owner_rows_of_in_txn(store, txn, actor)?
        .into_iter()
        .map(|(record, owner)| (record, owner.run))
        .collect();
    for run in runs {
        records.entry(*run).or_insert(*run);
    }
    let mut named = Vec::new();
    for row in REPLAY_RECORDS.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(run) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        // A record with an owner row is named by that row alone; one
        // written before any was stamped is named by its run's own stamps.
        if records.contains_key(&run) || response_owner_in_txn(store, txn, &run)?.is_some() {
            continue;
        }
        if crate::dreamer_runner::program_run_actor_in_txn(store, txn, &run)? == Some(*actor) {
            named.push(run);
            continue;
        }
        if REPLAY_RECORDS
            .decode_value(&bytes)
            .is_ok_and(|record| record.live_run.is_some_and(|live| live.actor == *actor))
        {
            named.push(run);
        }
    }
    for run in named {
        records.insert(run, run);
    }
    Ok(records)
}

/// The occurrences run `owner` holds of those of `outputs` that hold reply
/// content.
fn reply_occurrences(owner: EntityId, outputs: &[CodeRunRawOutput]) -> Vec<Occurrence> {
    outputs
        .iter()
        .filter(|output| holds_reply_content(&output.path))
        .map(|output| (owner, output.path.clone(), output.handle.clone()))
        .collect()
}

/// Releases run `owner`'s occurrence of each of `outputs` that holds reply
/// content, with that occurrence's own taint and secret marks and no
/// other's.
fn release_reply_outputs_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    outputs: &[CodeRunRawOutput],
) -> Result<()> {
    for (owner, path, handle) in reply_occurrences(owner, outputs) {
        release_occurrence_in_txn(store, wtxn, owner, path, handle)?;
    }
    Ok(())
}

/// Releases run `owner`'s occurrence at `path` of the body `handle` names,
/// with its own taint and secret marks: the digest it held, read before,
/// when it held one.
pub(super) fn release_occurrence_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    path: String,
    handle: String,
) -> Result<Option<[u8; 32]>> {
    let occurrence = ResultOccurrence::owned(owner, &path)?;
    let held = owned_body_in_txn(store, wtxn, &owner, &occurrence.id())?
        .and_then(|body| body.state.held().map(|held| held.blake3));
    let marks = occurrence.mark_key(&handle);
    RAW_OUTPUT_TAINTS.delete(store, wtxn, &marks)?;
    RAW_OUTPUT_SECRETS.delete(store, wtxn, &marks)?;
    release_body_in_txn(store, wtxn, &owner, &occurrence.id())?;
    Ok(held)
}
