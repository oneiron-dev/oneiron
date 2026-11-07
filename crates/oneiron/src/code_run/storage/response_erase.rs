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
use super::records::REPLAY_RECORDS;
use super::replay_bodies::{CODE_RUN_OUTPUT_PREVIEW_ERASED, erase_replies};
use super::replay_capsule::{actor_gone_in_txn, capsule_bodies_in_txn, names_no_actor};
use super::response_owners::{
    ResponseOwner, mark_response_erased_in_txn, owner_rows_of_in_txn, response_owner_in_txn,
};
use super::spawn_erase::fence_spawn_targets_in_txn;
use super::wait_holders::{erase_actor_wait_holds_in_txn, wait_holder_runs_in_txn};
use crate::engine_executor::holds_reply_content;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::provenance::body::{
    owned_bodies_in_txn, owned_body_in_txn, release_body_in_txn, release_owner_bodies_in_txn,
};
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
/// 2). A record that does not decode names no outputs: every body its run
/// holds is released, and its row keeps none of its bytes, written over
/// with the erased-unreadable mark, which still decodes as no record, so
/// nothing replays from it (FIX 6533). Erasing an erased one again changes
/// nothing. Nothing retires here: a soft delete runs this too.
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
            release_reply_outputs_in_txn(store, wtxn, &record, run)?;
            REPLAY_RECORDS.put_erased(store, wtxn, &record_id, Erased::of(record)?)?;
        } else if unreadable_record_in_txn(store, wtxn, &record_id)? {
            // Its bodies are held by its owner row's run (a decoded
            // record's `run_id`), which need not be the replay key.
            release_owner_bodies_in_txn(store, wtxn, &run)?;
            REPLAY_RECORDS.put_erased_unreadable(store, wtxn, &record_id)?;
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
    record = fence_sourced_outputs_in_txn(&vault.store, wtxn, record)?;
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
    release_reply_outputs_in_txn(&vault.store, wtxn, &record, run)?;
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
/// holder keeps owes its retirement to that holder's release. A record that
/// does not decode names no outputs, so every body its run holds goes so
/// (FIX 6533). An id whose entity is no actor scans nothing.
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
    let mut unreadable = Vec::new();
    for (record_id, run) in actor_records_in_txn(store, wtxn, actor, &runs)? {
        if let Some(record) = REPLAY_RECORDS.get_lenient(store, wtxn, &record_id)? {
            held.extend(reply_occurrences(&record, run));
            release_unpublished_outputs_in_txn(store, wtxn, record.run_id)?;
        } else if unreadable_record_in_txn(store, wtxn, &record_id)? {
            // Its bodies are held by its owner row's run (a decoded
            // record's `run_id`), which need not be the replay key.
            unreadable.push(run);
        }
    }
    let mut digests: BTreeMap<EntityId, Vec<[u8; 32]>> = BTreeMap::new();
    for (owner, path, handle) in held {
        if let Some(digest) = release_occurrence_in_txn(store, wtxn, owner, path, handle)? {
            digests.entry(owner).or_default().push(digest);
        }
    }
    for run in unreadable {
        for body in owned_bodies_in_txn(store, wtxn, &run)? {
            let digest = body.state.held().map(|held| held.blake3);
            release_body_in_txn(store, wtxn, &run, &body.occurrence)?;
            if let Some(digest) = digest {
                digests.entry(run).or_default().push(digest);
            }
        }
    }
    for (owner, released) in digests {
        crate::store::erase_bodies_in_txn(store, wtxn, &owner, &released)?;
    }
    Ok(())
}

/// Whether run `record`'s replay row is stored but does not decode (FIX
/// 6533). The erased-unreadable mark an erase already wrote counts too:
/// erasing it again changes nothing.
fn unreadable_record_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
) -> Result<bool> {
    Ok(REPLAY_RECORDS.contains(store, txn, record)?
        && REPLAY_RECORDS.get_lenient(store, txn, record)?.is_none())
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

/// The record's owned reply occurrences. An exact canonical native receipt
/// keeps its original standing independently of its shared content hash.
fn reply_occurrences(record: &CodeRunReplayRecord, run: EntityId) -> Vec<Occurrence> {
    let mut held: Vec<_> = record
        .outputs
        .iter()
        .filter(|output| {
            holds_reply_content(&output.path) && !record.output_is_retained_receipt(output)
        })
        .map(|output| (record.run_id, output.path.clone(), output.handle.clone()))
        .collect();
    // A write receipt can commit before the executor's checkpoint adopts its
    // reply. The native owner row, not metadata in the answer, names its run.
    held.extend(record.bridge_calls.iter().filter_map(|call| {
        let reply = crate::code_run::ExecutorReply::kept(&call.outcome, run)
            .ok()
            .flatten()?;
        holds_reply_content(&reply.output.path).then_some((
            run,
            reply.output.path,
            reply.output.handle,
        ))
    }));
    held
}

/// Releases the record's reply occurrences with each occurrence's own taint
/// and secret marks, never another holder's or a retained receipt's.
fn release_reply_outputs_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    record: &CodeRunReplayRecord,
    run: EntityId,
) -> Result<()> {
    release_unpublished_outputs_in_txn(store, wtxn, record.run_id)?;
    for (owner, path, handle) in reply_occurrences(record, run) {
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
///
/// FIX 9348: an occurrence can be captured after a source in its frozen
/// input rows took the hard-delete marker. That erase's writer never saw
/// it, so it has no stale mark yet. Here it gets that mark, and it retires on the same
/// path as an occurrence the erase did see. Other outputs, and other
/// holders of the same bytes, are unchanged.
fn fence_sourced_outputs_in_txn<'r>(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    mut record: Cow<'r, CodeRunReplayRecord>,
) -> Result<Cow<'r, CodeRunReplayRecord>> {
    let mut withdrawn = Vec::new();
    let mut late = Vec::new();
    let mut sources = BTreeMap::new();
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
        } else if source_hard_delete_marked_in_txn(store, wtxn, output, &mut sources)? {
            late.push(occurrence.id());
            withdrawn.push(index);
        }
    }
    if withdrawn.is_empty() {
        return Ok(record);
    }
    if !late.is_empty() {
        let at = crate::ports::recorded_at_in_txn(store, wtxn)?;
        for occurrence in &late {
            crate::ports::stage_stale_mark_in_txn(store, wtxn, occurrence, at)?;
        }
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

/// Whether a row in `output`'s frozen input rows carries the native
/// hard-delete marker (FIX 9348). Only that marker counts, and only its
/// presence is read. It marks the hard delete, not that every purge step
/// has finished. A soft delete, a missing row and a pending erasure
/// prove nothing; the pending erasure meets this output in its own writer.
/// Unknown input rows name no source. `sources` keeps each row's answer
/// for the rest of the record.
fn source_hard_delete_marked_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    output: &CodeRunRawOutput,
    sources: &mut BTreeMap<EntityId, bool>,
) -> Result<bool> {
    for row in output.input_rows.iter().flatten() {
        let erased = match sources.get(row) {
            Some(&erased) => erased,
            None => {
                let erased = store.port_deletion_marked(txn, DeletionMarker::HardDelete, row)?;
                sources.insert(*row, erased);
                erased
            }
        };
        if erased {
            return Ok(true);
        }
    }
    Ok(false)
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

/// Removes byte-free, unpublished occurrences when the run's replies are erased.
fn release_unpublished_outputs_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    owner: EntityId,
) -> Result<()> {
    for body in crate::provenance::body::owned_bodies_in_txn(store, wtxn, &owner)? {
        if matches!(
            body.state,
            crate::store::body_descriptor::BodyState::Incomplete { retained: None }
        ) {
            release_body_in_txn(store, wtxn, &owner, &body.occurrence)?;
        }
    }
    Ok(())
}
