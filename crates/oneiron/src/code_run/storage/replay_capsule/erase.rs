//! The erase of a capsule's actor (FIX 6144, KEY STORE = A), in the erase's
//! own writer. Each capsule of the actor's steps keeps what the step was and
//! loses what it held: its request, start, replay context, route prompt
//! (FIX 6255) and fork answers are released as the run's occurrences, each
//! with only its own taint and secret marks, so another holder of the same
//! bytes keeps them and its marks. It retires no body instance: the erase
//! cause comes from the provenance door alone (KS-2B1), and a release keeps
//! the restore window. A soft delete keeps the capsules and runs only the
//! response scrub (FIX 15532), reading their runs ([`capsule_runs_in_txn`]).
//! A restore runs this again for every erased actor, so a
//! restored capsule stays erased. It is also the one callback the actor's
//! erase reaches its runs' reply content by (FIX 5718,
//! `response_erase`); the hard erase's retirement of the same bodies comes
//! from the provenance door, which reads them here first
//! ([`capsule_bodies_in_txn`], FIX 6278).
//!
//! The same tombstone fences every later write: a late capture, a finalize
//! and a fork answer's publication read it in their own writer and keep
//! nothing for an actor that is gone.
//!
//! A capsule's request and start pieces are held once per run and actor
//! (FIX 4192), so every capsule that names them is the actor's: the erase
//! releases each piece its runs hold for the actor, found by the run's own
//! descriptors, after every capsule body.

use super::super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::super::replay_capsule::{CapsuleContent, CapsuleRequest, StepReplayCapsule};
use super::super::response_erase::erase_actor_responses_in_txn;
use super::pieces::actor_pieces_in_txn;
use super::{CAPSULES, FORKS, ForkValue};
use crate::compaction::output::OutputRef;
pub(in crate::code_run::storage) use crate::ports::names_no_actor_in_txn as names_no_actor;
use crate::provenance::body::release_body_in_txn;
use crate::side_table::{Erased, ErasedForm, SideKey, SideTableDbs};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// A capsule's key: its attempt, lease generation and step.
type CapsuleKey = (EntityId, u64, u64);

/// Erases `actor` from the capsules of its steps: each keeps what the step
/// was ([`erased`]) and releases every body it named. A capsule erased
/// before is left as it is, and a row that does not decode names no actor
/// and stays as it is. An id whose entity is no actor scans nothing. The
/// reply content of the actor's runs, these capsules' runs among them, is
/// erased beside them first (FIX 5718), release only as here. FIX 4192:
/// the request and start pieces each run holds for the actor are read
/// before anything is released, and released last.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn erase_capsule_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(&vault.store, wtxn, actor)? {
        return Ok(());
    }
    let owned = owned_capsules_in_txn(&vault.store, wtxn, actor)?;
    let runs: Vec<EntityId> = owned.iter().map(|(_, capsule)| capsule.run).collect();
    erase_actor_responses_in_txn(vault, wtxn, actor, &runs)?;
    if owned.is_empty() {
        return Ok(());
    }
    let answers = fork_answers_in_txn(&vault.store, wtxn)?;
    let pieces = actor_pieces_in_txn(&vault.store, wtxn, actor, runs)?;
    for (key, capsule) in owned {
        let bodies = capsule_bodies(&key, &capsule, &answers);
        release_bodies_in_txn(vault, wtxn, capsule.run, &bodies)?;
        CAPSULES.put_erased(&vault.store, wtxn, &key, Erased::of(capsule)?)?;
    }
    for (run, bodies) in pieces {
        release_bodies_in_txn(vault, wtxn, run, &bodies)?;
    }
    Ok(())
}

/// Every body `actor`'s capsules name, with the run that owns it: each
/// kept request, each start, each replay context, each kept route prompt
/// (FIX 6255), each fork answer and each fork's executed body, read before the erase releases them, so the
/// provenance door's hard erase retires their instances (FIX 6278). A
/// capsule erased before names none. Each request and start piece its runs
/// hold for the actor is one of them (FIX 4192).
///
/// # Errors
///
/// Storage errors.
pub(in crate::code_run::storage) fn capsule_bodies_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<(EntityId, OutputRef, String)>> {
    let owned = owned_capsules_in_txn(store, txn, actor)?;
    if owned.is_empty() {
        return Ok(Vec::new());
    }
    let answers = fork_answers_in_txn(store, txn)?;
    let mut bodies = Vec::new();
    for (key, capsule) in &owned {
        let run = capsule.run;
        bodies.extend(
            capsule_bodies(key, capsule, &answers)
                .into_iter()
                .map(|(body, path)| (run, body, path)),
        );
    }
    let runs = owned.iter().map(|(_, capsule)| capsule.run);
    for (run, pieces) in actor_pieces_in_txn(store, txn, actor, runs)? {
        bodies.extend(pieces.into_iter().map(|(body, path)| (run, body, path)));
    }
    Ok(bodies)
}

/// The runs of `actor`'s capsules, read for its soft delete's response
/// scrub (FIX 15532), which leaves the capsules as they are.
///
/// # Errors
///
/// Storage errors.
pub(in crate::code_run::storage) fn capsule_runs_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(owned_capsules_in_txn(dbs, txn, actor)?
        .into_iter()
        .map(|(_, capsule)| capsule.run)
        .collect())
}

/// The capsules that hold `actor`'s steps, by their keys. A row that does
/// not decode names no actor.
fn owned_capsules_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<(CapsuleKey, StepReplayCapsule)>> {
    let mut owned = Vec::new();
    for row in CAPSULES.iter_raw_from(dbs, txn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <CapsuleKey as SideKey>::decode_key(&key) else {
            continue;
        };
        if let Ok(capsule) = CAPSULES.decode_value(&bytes)
            && capsule.content.actor() == Some(*actor)
        {
            owned.push((key, capsule));
        }
    }
    Ok(owned)
}

/// The bodies the capsule at `key` names: its request when it kept one
/// (a withheld request kept none, FIX 6254), its start, its replay context
/// (FIX 6351), its route prompt when it kept one (FIX 6255), and each fork
/// answer among `answers` that regenerated it.
fn capsule_bodies(
    key: &CapsuleKey,
    capsule: &StepReplayCapsule,
    answers: &[(CapsuleKey, OutputRef, String)],
) -> Vec<(OutputRef, String)> {
    let mut bodies = Vec::new();
    if let CapsuleRequest::Kept { body, path, .. } = &capsule.request {
        bodies.push((*body, path.clone()));
    }
    if let Some(start) = &capsule.start {
        bodies.push((start.body, start.path.clone()));
    }
    if let Some(context) = &capsule.context {
        bodies.push((context.body, context.path.clone()));
    }
    if let Some(binding) = &capsule.binding
        && let Some(CapsuleRequest::Kept { body, path, .. }) = &binding.prompt
    {
        bodies.push((*body, path.clone()));
    }
    bodies.extend(
        answers
            .iter()
            .filter(|(at, _, _)| at == key)
            .map(|(_, body, path)| (*body, path.clone())),
    );
    bodies
}

use crate::dreamer_runner::step_replay::erased;

/// Every fork answer the contribution rows keep, and every body an engine
/// step's fork's program left (FIX 3607), by the capsule its fork
/// regenerated: its body and path. A row that does not decode names none.
fn fork_answers_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(CapsuleKey, OutputRef, String)>> {
    let mut answers = Vec::new();
    for row in FORKS.iter_raw_from(dbs, txn, &[])? {
        let (_, bytes) = row?;
        if let Ok(row) = FORKS.decode_value(&bytes)
            && let ForkValue::Fork(receipt) = row.value
        {
            let at = (
                receipt.attempt,
                u64::from(receipt.lease_generation),
                receipt.step,
            );
            answers.push((at, receipt.response, receipt.response_path));
            if let Some(execution) = &receipt.execution {
                let executed = execution.bodies();
                answers.extend(executed.map(|body| (at, body.body, body.stored_path.clone())));
            }
        }
    }
    Ok(answers)
}

/// Releases run `owner`'s occurrence of each of `bodies`, with that
/// occurrence's own taint and secret marks and no other's.
fn release_bodies_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    bodies: &[(OutputRef, String)],
) -> Result<()> {
    for (body, path) in bodies {
        let output = CodeRunRawOutput {
            path: path.clone(),
            ..CodeRunRawOutput::of_ref(*body)
        };
        let occurrence = ResultOccurrence::of(Some(owner), &output)?;
        let marks = occurrence.mark_key(&output.handle);
        crate::code_run::drop_code_run_result_marks_in_txn(&vault.store, wtxn, &marks)?;
        release_body_in_txn(&vault.store, wtxn, &owner, &occurrence.id())?;
    }
    Ok(())
}

/// Whether `actor` is gone here, as a turn program's step reads it (FIX
/// 5710): soft-deleted (its identity's soft-delete marker, or a deletion of
/// its row other than an archive), or hard-deleted and erased. A capsule's
/// content is then never captured, finalized or added to. A marker that
/// cannot be read counts as gone.
pub(crate) fn actor_gone_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, actor: &EntityId) -> bool {
    actor_gone_in_store(&vault.store, txn, actor)
}

/// [`actor_gone_in_txn`] on the vault's canonical store `store`, for a
/// reader that holds only a room session's composed view, whose base it is.
pub(crate) fn actor_gone_in_store(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> bool {
    let gone = crate::ports::owner_gone_in_txn(store, txn, actor);
    gone.unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "a capsule actor's deletion markers were not read; its content is not kept"
        );
        true
    })
}

/// Whether `actor`'s hard erasure is complete here (FIX 6591): it holds the
/// hard-delete marker, which the erase's writer puts beside its retirement,
/// so no later erase of it runs. A row a late write leaves for it then names
/// no actor. A gone actor without that marker (soft-deleted, or removed by a
/// delete that is still pending) is not: its row keeps the actor and the
/// bodies released, for the retirement still to come.
///
/// # Errors
///
/// A marker read error, which the writer returns.
pub(crate) fn actor_hard_erased_in_store(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<bool> {
    crate::ports::owner_hard_erased_in_txn(store, txn, actor)
}
