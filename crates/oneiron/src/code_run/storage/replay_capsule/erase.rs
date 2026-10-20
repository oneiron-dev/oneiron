//! The erase of a capsule's actor (FIX 6144, KEY STORE = A), in the erase's
//! own writer. Each capsule of the actor's steps keeps what the step was and
//! loses what it held: its request, start and fork answers are released as
//! the run's occurrences, each with only its own taint and secret marks,
//! and erased as kept copies (`store::erase_bodies_in_txn`), so another
//! holder of the same bytes keeps them and its marks, and the last holder's
//! release retires them. A restore runs this again for every erased actor,
//! so a restored capsule stays erased.
//!
//! The same tombstone fences every later write: a late capture, a finalize
//! and a fork answer's publication read it in their own writer and keep
//! nothing for an actor that is gone.

use super::super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::super::replay_capsule::{CapsuleContent, StepReplayCapsule};
use super::super::records::{RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS};
use super::{CAPSULES, FORKS, ForkRow};
use crate::compaction::output::OutputRef;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::provenance::body::{owned_body_in_txn, release_body_in_txn};
use crate::side_table::SideKey;
use crate::{EntityId, Result, Vault};

/// A capsule's key: its attempt, lease generation and step.
type CapsuleKey = (EntityId, u64, u64);

/// Erases `actor` from the capsules of its steps: each keeps what the step
/// was ([`erased`]) and releases every body it named. A capsule erased
/// before is left as it is, and a row that does not decode names no actor
/// and stays as it is. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn erase_capsule_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut owned = Vec::new();
    for row in CAPSULES.iter_raw_from(&vault.store, wtxn, &[])? {
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
    if owned.is_empty() {
        return Ok(());
    }
    let answers = fork_answers_in_txn(vault, wtxn)?;
    for (key, capsule) in owned {
        let mut bodies = vec![(capsule.request, capsule.request_path.clone())];
        if let Some(start) = &capsule.start {
            bodies.push((start.body, start.path.clone()));
        }
        bodies.extend(
            answers
                .iter()
                .filter(|(at, _, _)| *at == key)
                .map(|(_, body, path)| (*body, path.clone())),
        );
        let held = release_bodies_in_txn(vault, wtxn, capsule.run, &bodies)?;
        crate::store::erase_bodies_in_txn(&vault.store, wtxn, &capsule.run, &held)?;
        CAPSULES.put(vault, wtxn, &key, &erased(capsule))?;
    }
    Ok(())
}

/// What an erase leaves of a capsule (FIX 6144): what the step was (its
/// attempt, run, step and lease generation, its host, the model and
/// locality that answered it, both request hashes and its messages digest,
/// its exposures' skills, revisions and spans, its seed, its time, and its
/// start's ref, digest and bridge count), its content Erased, naming no
/// actor, with its route prompt cleared. Its bodies are released beside it;
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
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(CapsuleKey, OutputRef, String)>> {
    let mut answers = Vec::new();
    for row in FORKS.iter_raw_from(&vault.store, txn, &[])? {
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
/// occurrence's own taint and secret marks and no other's. Returns the
/// digest each released occurrence held, read before it went.
fn release_bodies_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    bodies: &[(OutputRef, String)],
) -> Result<Vec<[u8; 32]>> {
    let mut held = Vec::new();
    for (body, path) in bodies {
        let output = CodeRunRawOutput {
            path: path.clone(),
            ..CodeRunRawOutput::of_ref(*body)
        };
        let occurrence = ResultOccurrence::of(Some(owner), &output)?;
        let marks = occurrence.mark_key(&output.handle);
        RAW_OUTPUT_TAINTS.delete(&vault.store, wtxn, &marks)?;
        RAW_OUTPUT_SECRETS.delete(&vault.store, wtxn, &marks)?;
        let id = occurrence.id();
        if let Some(descriptor) = owned_body_in_txn(&vault.store, wtxn, &owner, &id)?
            && let Some(kept) = descriptor.state.held()
        {
            held.push(kept.blake3);
        }
        release_body_in_txn(&vault.store, wtxn, &owner, &id)?;
    }
    Ok(held)
}

/// Whether `id`'s entity is here and is no actor: a person, a machine or an
/// agent is one, and an id with no entity here may have been one.
fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, id)?
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
pub(super) fn actor_gone_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, actor: &EntityId) -> bool {
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
