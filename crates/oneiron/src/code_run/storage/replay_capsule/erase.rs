//! The erase of a capsule's actor (FIX 6144, KEY STORE = A), in the erase's
//! own writer. Each capsule of the actor's steps keeps what the step was and
//! loses what it held: its request, start and fork answers are released as
//! the run's occurrences, each with only its own taint and secret marks, so
//! another holder of the same bytes keeps them and its marks. A soft delete
//! runs this scrub too, so it retires no body instance: the erase cause
//! comes from the provenance door alone (KS-2B1), and a release keeps the
//! restore window. A restore runs this again for every erased actor, so a
//! restored capsule stays erased. It is also the one callback the actor's
//! erase reaches its runs' reply content by (FIX 5718,
//! `response_erase`); the hard erase's retirement of the same bodies comes
//! from the provenance door, which reads them here first
//! ([`capsule_bodies_in_txn`], FIX 6278).
//!
//! The same tombstone fences every later write: a late capture, a finalize
//! and a fork answer's publication read it in their own writer and keep
//! nothing for an actor that is gone.

use super::super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::super::replay_capsule::{CapsuleContent, CapsuleRequest, StepReplayCapsule};
use super::super::records::{RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS};
use super::super::response_erase::erase_actor_responses_in_txn;
use super::{CAPSULES, FORKS, ForkRow};
use crate::compaction::output::OutputRef;
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::provenance::body::release_body_in_txn;
use crate::side_table::{SideKey, SideTableDbs};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// A capsule's key: its attempt, lease generation and step.
type CapsuleKey = (EntityId, u64, u64);

/// Erases `actor` from the capsules of its steps: each keeps what the step
/// was ([`erased`]) and releases every body it named. A capsule erased
/// before is left as it is, and a row that does not decode names no actor
/// and stays as it is. An id whose entity is no actor scans nothing. The
/// reply content of the actor's runs, these capsules' runs among them, is
/// erased beside them first (FIX 5718), release only as here.
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
    for (key, capsule) in owned {
        let bodies = capsule_bodies(&key, &capsule, &answers);
        release_bodies_in_txn(vault, wtxn, capsule.run, &bodies)?;
        CAPSULES.put(vault, wtxn, &key, &erased(capsule))?;
    }
    Ok(())
}

/// Every body `actor`'s capsules name, with the run that owns it: each
/// kept request, each start and each fork answer, read before the erase
/// releases them, so the provenance door's hard erase retires their
/// instances (FIX 6278). A capsule erased before names none.
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
    Ok(bodies)
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
/// (a withheld request kept none, FIX 6254), its start, and each fork answer
/// among `answers` that regenerated it.
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
    bodies.extend(
        answers
            .iter()
            .filter(|(at, _, _)| at == key)
            .map(|(_, body, path)| (*body, path.clone())),
    );
    bodies
}

/// What an erase leaves of a capsule (FIX 6144): what the step was (its
/// attempt, run, step and lease generation, its host, the model and
/// locality that answered it, both request hashes and its messages digest,
/// its exposures' skills, revisions and spans, its seed, its time, its
/// start's ref, digest and bridge count, and the route its rung went out on,
/// which holds the route prompt's digest only), its content Erased, naming
/// no actor, with its route prompt cleared. Its bodies are released beside it;
/// its fork receipts and scores stay in their own rows.
fn erased(mut capsule: StepReplayCapsule) -> StepReplayCapsule {
    capsule.content = CapsuleContent::Erased;
    if let Some(binding) = &mut capsule.binding {
        binding.prompt = None;
    }
    capsule
}

/// Every fork answer the contribution rows keep, by the capsule its fork
/// regenerated: its body and path. A row that does not decode names none.
fn fork_answers_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(CapsuleKey, OutputRef, String)>> {
    let mut answers = Vec::new();
    for row in FORKS.iter_raw_from(dbs, txn, &[])? {
        let (_, bytes) = row?;
        if let Ok(ForkRow::Fork(receipt)) = FORKS.decode_value(&bytes) {
            let at = (
                receipt.attempt,
                u64::from(receipt.lease_generation),
                receipt.step,
            );
            answers.push((at, receipt.response, receipt.response_path));
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
        RAW_OUTPUT_TAINTS.delete(&vault.store, wtxn, &marks)?;
        RAW_OUTPUT_SECRETS.delete(&vault.store, wtxn, &marks)?;
        release_body_in_txn(&vault.store, wtxn, &owner, &occurrence.id())?;
    }
    Ok(())
}

/// Whether `id`'s entity is here and is no actor: a person, a machine or an
/// agent is one, and an id with no entity here may have been one.
pub(in crate::code_run::storage) fn names_no_actor(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if let Some(raw) = store.port_entity_raw(txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Whether `actor` is gone here, as a turn program's step reads it (FIX
/// 5710): soft-deleted (its identity's soft-delete marker, or a deletion of
/// its row other than an archive), or hard-deleted and erased. A capsule's
/// content is then never captured, finalized or added to. A marker that
/// cannot be read counts as gone.
pub(in crate::code_run::storage) fn actor_gone_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> bool {
    let gone = (|| -> Result<bool> {
        Ok(crate::ports::removed_in_txn(&vault.store, txn, actor)?
            || vault
                .store
                .port_deletion_marked(txn, DeletionMarker::HardDelete, actor)?
            || vault
                .store
                .port_deletion_marked(txn, DeletionMarker::IdentitySoftDelete, actor)?)
    })();
    gone.unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "a capsule actor's deletion markers were not read; its content is not kept"
        );
        true
    })
}
