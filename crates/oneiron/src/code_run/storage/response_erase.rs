//! An erase of a code run's actor, over the reply content its runs kept
//! (FIX 5718, KEY STORE = A): the replay rows (a run's own and its write
//! receipts', bridge outcomes and output previews) and the bodies of the
//! outputs that hold reply content. A run's reply bodies are the outputs its
//! record lists and each body its own descriptors hold at a code-run output
//! path that holds reply content, such as a raw put's (FIX 7365).
//!
//! The actor scrub only releases: each record keeps what its run did and
//! loses what it was answered ([`super::replay_bodies::erase_replies`]), and
//! each reply body's occurrence is released with its own taint and secret
//! marks. Another holder of the same bytes keeps them. A soft delete runs it
//! in its own writer, before the actor's body is truncated
//! ([`soft_delete_actor_responses_in_txn`], FIX 15532): the record's owner
//! row says Deleted and keeps the actor and each reply body it released
//! (FIX 6591). An erase runs it from the capsule table's one callback
//! ([`erase_actor_responses_in_txn`]): the row says Erased. The hard erase
//! cause comes from the provenance door alone
//! ([`retire_actor_responses_in_txn`], called with the erase's own cause,
//! before that scrub): it retires the body instances of the same
//! occurrences, of those a soft delete released, and of the actor's
//! capsules' request, start and fork answers (FIX 6278), gathered before
//! anything releases them.
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
use super::records::REPLAY_RECORDS;
use super::replay_bodies::{CODE_RUN_OUTPUT_PREVIEW_ERASED, erase_replies};
use super::replay_capsule::{
    actor_gone_in_txn, capsule_bodies_in_txn, capsule_runs_in_txn, names_no_actor,
};
use super::response_owners::{
    ReleasedReplyBody, ResponseOwner, mark_response_deleted_in_txn, mark_response_erased_in_txn,
    owner_rows_of_in_txn, response_owner_in_txn,
};
use super::spawn_erase::fence_spawn_targets_in_txn;
use super::wait_holders::{erase_actor_wait_holds_in_txn, wait_holder_runs_in_txn};
use crate::engine_executor::holds_reply_content;
use crate::provenance::body::{owned_bodies_in_txn, owned_body_in_txn, release_body_in_txn};
use crate::side_table::{Erased, SideKey};
use crate::store::Store;
use crate::store::result_body_rows::body_handle;
use crate::{EntityId, Result, Vault};

/// One body occurrence a run holds: the run, the path and the body's handle.
type Occurrence = (EntityId, String, String);

/// Which writer an actor scrub runs in, and what it leaves of each owner
/// row and wait membership it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponseScrub {
    /// A soft delete's (FIX 15532): each says Deleted, keeping the actor
    /// and the reply bodies released, for the actor's later erase (FIX
    /// 6591).
    Delete,
    /// An erase's: each says Erased, its actor link and kept bodies with it.
    Erase,
}

/// The actor scrub of `actor` over its runs' reply content, in the erase's
/// own writer: each replay record whose replies are `actor`'s (its owner
/// rows, a live run binding or a turn program's attempt naming it, the runs
/// of its capsules, `runs`, and the runs a wait's membership names as its)
/// is put back in its erased form, past the side-row wall, the reply bodies
/// it names are released, and its owner row says Erased; then the wait
/// replies those runs were delivered take their erased form (FIX 5718 part
/// 2). A record that does not decode keeps its row as it is, and erasing an
/// erased one again changes nothing. Nothing retires here: the provenance
/// door's retirement ran before it.
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
    scrub_actor_responses_in_txn(vault, wtxn, actor, runs, ResponseScrub::Erase)
}

/// The response scrub of a soft delete of `actor` (FIX 15532), in the
/// delete's own writer: a user delete's, before the actor's body is
/// truncated, or an accepted replayed soft tombstone's. It is
/// [`erase_actor_responses_in_txn`]'s scrub over the runs of `actor`'s
/// capsules, the records its owner rows name and the runs its wait
/// memberships name, release only, each row left Deleted (FIX 6591). The
/// capsules' requests, the actor's fields and every other record stay, and
/// an archive never runs it. An id whose entity is no actor scans nothing;
/// one whose entity is gone still scans, since rows it owned may remain.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn soft_delete_actor_responses_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(&vault.store, wtxn, actor)? {
        return Ok(());
    }
    let runs = capsule_runs_in_txn(&vault.store, wtxn, actor)?;
    scrub_actor_responses_in_txn(vault, wtxn, actor, &runs, ResponseScrub::Delete)
}

/// The actor scrub `scrub` of `actor` (FIX 5718): each record its replies
/// are in is put back in its erased form and its reply bodies are
/// released; its owner row says Deleted, with the bodies released, or
/// Erased; then the wait replies its runs were delivered take their erased
/// form, each membership as its owner row.
fn scrub_actor_responses_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
    runs: &[EntityId],
    scrub: ResponseScrub,
) -> Result<()> {
    let store = &vault.store;
    let mut scope = runs.to_vec();
    scope.extend(wait_holder_runs_in_txn(store, wtxn, actor)?);
    let records = actor_records_in_txn(store, wtxn, actor, &scope)?;
    for (&record_id, &run) in &records {
        let mut released = Vec::new();
        if let Some(record) = REPLAY_RECORDS.get_lenient(store, wtxn, &record_id)? {
            released = release_reply_outputs_in_txn(store, wtxn, &record)?;
            REPLAY_RECORDS.put_erased(store, wtxn, &record_id, Erased::of(record)?)?;
        }
        match scrub {
            ResponseScrub::Delete => {
                mark_response_deleted_in_txn(store, wtxn, record_id, run, *actor, released)?;
            }
            ResponseScrub::Erase => mark_response_erased_in_txn(store, wtxn, record_id, run)?,
        }
    }
    let held: BTreeSet<EntityId> = records
        .into_iter()
        .flat_map(|(id, run)| [id, run])
        .collect();
    erase_actor_wait_holds_in_txn(vault, wtxn, actor, &held, scrub)
}

/// `record` as its writer may put it, read in that writer (FIX 5718): as
/// given while its replies are kept, else its erased form, the reply bodies
/// it names released and its owner row erased. Its replies are erased once
/// its owner row says so, or once the actor that row or its live run
/// binding names is gone. A row that names an actor, a soft delete's or the
/// gone one, says Deleted and keeps the bodies released here for that
/// actor's later erase (FIX 6591); an erased row stays erased.
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
    record = fence_sourced_outputs_in_txn(&vault.store, wtxn, record)?;
    let owner = response_owner_in_txn(&vault.store, wtxn, &record.run_id)?;
    let stamped = owner.as_ref().and_then(ResponseOwner::actor);
    let live = record.live_run.as_ref().map(|live| live.actor);
    let txn: &heed::RoTxn<'_> = wtxn;
    let gone = stamped
        .into_iter()
        .chain(live)
        .find(|actor| actor_gone_in_txn(vault, txn, actor));
    if gone.is_none() && !owner.as_ref().is_some_and(ResponseOwner::erased) {
        return Ok(record);
    }
    let run = owner.as_ref().map_or(record.run_id, |owner| owner.run);
    let released = release_reply_outputs_in_txn(&vault.store, wtxn, &record)?;
    erase_replies(record.to_mut())?;
    match owner
        .as_ref()
        .and_then(ResponseOwner::retirement_actor)
        .or(gone)
    {
        Some(actor) => {
            mark_response_deleted_in_txn(&vault.store, wtxn, record.run_id, run, actor, released)?;
        }
        None => mark_response_erased_in_txn(&vault.store, wtxn, record.run_id, run)?,
    }
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
/// owner row says Deleted or Erased. A read of one of its results reads it
/// as erased.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn response_erased_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    owner: &EntityId,
) -> Result<bool> {
    Ok(response_owner_in_txn(store, txn, owner)?
        .as_ref()
        .is_some_and(ResponseOwner::erased))
}

/// The hard erase of `actor`'s runs' reply content, from the provenance
/// door with the erase's own cause (FIX 5718 ruling 5, FIX 6278), before
/// the actor scrub runs: every reply body occurrence of each record whose
/// replies are `actor`'s, and the request, start and fork-answer bodies of
/// `actor`'s capsules, are released, each with its own marks, and the
/// instance of each whose last holder this releases retires; one another
/// holder keeps owes its retirement to that holder's release. A record a
/// soft delete of `actor` left Deleted retires the reply bodies that delete
/// released too, by the digests its owner row kept, and then says Erased:
/// its actor link and those bodies go (FIX 6591). An id whose entity is no
/// actor scans nothing.
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
    let mut deleted = Vec::new();
    for (record_id, run) in actor_records_in_txn(store, wtxn, actor, &runs)? {
        if let Some(record) = REPLAY_RECORDS.get_lenient(store, wtxn, &record_id)? {
            held.extend(run_reply_occurrences_in_txn(store, wtxn, &record)?);
        }
        if let Some(released) =
            response_owner_in_txn(store, wtxn, &record_id)?.and_then(ResponseOwner::into_released)
        {
            deleted.push((record_id, run, released));
        }
    }
    let mut digests: BTreeMap<EntityId, Vec<[u8; 32]>> = BTreeMap::new();
    for (owner, path, handle) in held {
        if let Some(digest) = release_occurrence_in_txn(store, wtxn, owner, path, handle)? {
            digests.entry(owner).or_default().push(digest);
        }
    }
    for released in deleted.iter().flat_map(|(_, _, released)| released) {
        let owned = digests.entry(released.owner).or_default();
        if !owned.contains(&released.body.blake3) {
            owned.push(released.body.blake3);
        }
    }
    for (owner, released) in digests {
        crate::store::erase_bodies_in_txn(store, wtxn, &owner, &released)?;
    }
    for (record_id, run, _) in deleted {
        mark_response_erased_in_txn(store, wtxn, record_id, run)?;
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

/// The record's owned reply occurrences of the outputs it lists. An exact
/// canonical native receipt keeps its original standing independently of
/// its shared content hash.
fn reply_occurrences(record: &CodeRunReplayRecord) -> Vec<Occurrence> {
    record
        .outputs
        .iter()
        .filter(|output| {
            holds_reply_content(&output.path) && !record.output_is_retained_receipt(output)
        })
        .map(|output| (record.run_id, output.path.clone(), output.handle.clone()))
        .collect()
}

/// The path namespace of the bodies a run holds for its replay capsules and
/// contribution forks (`replay/capsule/`, `replay/contribution/`): the
/// capsule erase releases them, the hard erase retires them from the
/// capsule rows, and a soft delete keeps them, so no descriptor there is a
/// reply body.
const CAPSULE_BODY_PATH_PREFIX: &str = "replay/";

/// [`reply_occurrences`], then each reply body `record`'s run holds that
/// the record does not list (FIX 7365): a descriptor the run owns whose
/// code-run output path holds reply content, such as a raw put's
/// observation, once by its owner and occurrence, its handle its held
/// digest's. A descriptor with no such path, one whose occurrence that path
/// does not derive, and one that holds no bytes name none. The run's
/// control bodies, its fallback-speech marker among them, and its capsule
/// bodies ([`CAPSULE_BODY_PATH_PREFIX`]) stay.
fn run_reply_occurrences_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &CodeRunReplayRecord,
) -> Result<Vec<Occurrence>> {
    let run = record.run_id;
    let mut listed = BTreeSet::new();
    for output in &record.outputs {
        listed.insert(ResultOccurrence::owned(run, &output.path)?.id());
    }
    let mut held = reply_occurrences(record);
    for body in owned_bodies_in_txn(store, txn, &run)? {
        let (Some(origin), Some(bytes)) = (&body.code_run_output, body.state.held()) else {
            continue;
        };
        if origin.path.starts_with(CAPSULE_BODY_PATH_PREFIX)
            || !holds_reply_content(&origin.path)
            || ResultOccurrence::owned(run, &origin.path)?.id() != body.occurrence
            || !listed.insert(body.occurrence)
        {
            continue;
        }
        held.push((run, origin.path.clone(), body_handle(&bytes.blake3)));
    }
    Ok(held)
}

/// Releases each of `record`'s reply occurrences
/// ([`run_reply_occurrences_in_txn`]), with each occurrence's own taint and
/// secret marks, never another holder's or a retained receipt's: what each
/// held, read before, for a soft delete to keep (FIX 6591).
fn release_reply_outputs_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    record: &CodeRunReplayRecord,
) -> Result<Vec<ReleasedReplyBody>> {
    let mut released = Vec::new();
    for (owner, path, handle) in run_reply_occurrences_in_txn(store, wtxn, record)? {
        released.extend(release_held_occurrence_in_txn(
            store, wtxn, owner, path, handle,
        )?);
    }
    Ok(released)
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
    Ok(
        release_held_occurrence_in_txn(store, wtxn, owner, path, handle)?
            .map(|released| released.body.blake3),
    )
}

/// [`release_occurrence_in_txn`], returning the occurrence and the bytes it
/// held, read before (FIX 6591).
fn release_held_occurrence_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    path: String,
    handle: String,
) -> Result<Option<ReleasedReplyBody>> {
    let occurrence = ResultOccurrence::owned(owner, &path)?;
    let held = owned_body_in_txn(store, wtxn, &owner, &occurrence.id())?
        .as_ref()
        .and_then(ReleasedReplyBody::of);
    let marks = occurrence.mark_key(&handle);
    crate::code_run::drop_code_run_result_marks_in_txn(store, wtxn, &marks)?;
    release_body_in_txn(store, wtxn, &owner, &occurrence.id())?;
    Ok(held)
}

/// Retires only the persisted output occurrences whose frozen input rows
/// name `source`, in the source erase's accepted writer. The run's other
/// replies and its response owner are unchanged.
pub(crate) fn retire_sourced_code_outputs_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let mut records = Vec::new();
    for row in REPLAY_RECORDS.iter_raw_from(store, wtxn, &[])? {
        let (key, bytes) = row?;
        let Some(id) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        let Ok(record) = REPLAY_RECORDS.decode_value(&bytes) else {
            continue;
        };
        if record.outputs.iter().any(|output| {
            output
                .input_rows
                .as_ref()
                .is_some_and(|rows| rows.contains(source))
        }) {
            records.push((id, record));
        }
    }
    let at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let mut released: BTreeMap<EntityId, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for (id, record) in records {
        let mut paths = BTreeSet::new();
        for output in &record.outputs {
            if !output
                .input_rows
                .as_ref()
                .is_some_and(|rows| rows.contains(source))
            {
                continue;
            }
            let occurrence = ResultOccurrence::owned(record.run_id, &output.path)?;
            crate::ports::stage_stale_mark_in_txn(store, wtxn, &occurrence.id(), at)?;
            if let Some(digest) = release_occurrence_in_txn(
                store,
                wtxn,
                record.run_id,
                output.path.clone(),
                output.handle.clone(),
            )? {
                released.entry(record.run_id).or_default().insert(digest);
            }
            paths.insert(output.path.clone());
        }
        REPLAY_RECORDS.put_erased(
            store,
            wtxn,
            &id,
            Erased::code_run_output_previews(record, &paths),
        )?;
    }
    retire_released_outputs_in_txn(store, wtxn, released)
}

/// A later replay write cannot republish a retired occurrence's preview or
/// hold. The marker belongs to the occurrence, not its shared content hash.
fn fence_sourced_outputs_in_txn<'r>(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    mut record: Cow<'r, CodeRunReplayRecord>,
) -> Result<Cow<'r, CodeRunReplayRecord>> {
    let mut withdrawn = Vec::new();
    for (index, output) in record.outputs.iter().enumerate() {
        let occurrence = ResultOccurrence::owned(record.run_id, &output.path)?;
        if !crate::ports::body_readable_in_txn(
            store,
            wtxn,
            &occurrence.id(),
            &[],
            crate::ports::BodyStale::Withdrawn,
        )? {
            withdrawn.push(index);
        }
    }
    if withdrawn.is_empty() {
        return Ok(record);
    }
    let record_mut = record.to_mut();
    let mut released: BTreeMap<EntityId, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for index in withdrawn {
        let output = &mut record_mut.outputs[index];
        if let Some(digest) = release_occurrence_in_txn(
            store,
            wtxn,
            record_mut.run_id,
            output.path.clone(),
            output.handle.clone(),
        )? {
            released
                .entry(record_mut.run_id)
                .or_default()
                .insert(digest);
        }
        output.preview.text = CODE_RUN_OUTPUT_PREVIEW_ERASED.to_owned();
    }
    retire_released_outputs_in_txn(store, wtxn, released)?;
    Ok(record)
}

fn retire_released_outputs_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    released: BTreeMap<EntityId, BTreeSet<[u8; 32]>>,
) -> Result<()> {
    for (owner, digests) in released {
        let digests: Vec<_> = digests.into_iter().collect();
        crate::store::erase_bodies_in_txn(store, wtxn, &owner, &digests)?;
    }
    Ok(())
}
