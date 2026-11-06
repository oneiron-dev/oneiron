//! A projection-bound update proved not copy-derived, forwarded exactly
//! (FIX 7608 slice 2b-ii-A).
//!
//! Only an update the classification proved reaches no changed copy
//! object, carrying the canonical CAS triple it was pushed with, comes
//! here; the owner and an unmarked store never do. Its record and its
//! marks, carried to the canonical store from the ingress operation that
//! saw the bytes, are written before the canonical publication, which then
//! runs the ordinary canonical intent, authority and CAS under the
//! canonical coordinator. The actual ingress evidence stays linked, never
//! replaced, and each ref's Pending, NotApplied or Superseded is reported
//! as it lands.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::super::evidence::RefUpdate;
use super::super::landing_lfs::{
    admit_landing_lfs_pointers, attach_landing_lfs_pointers, ref_required_lfs_oids,
};
use super::{
    ReceivedPushTarget, RepoProjectionIngressProof, classify_received_projection,
    complete_received_push_target,
};
use crate::codebase::entity_id_from_hash_material;
use crate::error::{Error, ErrorKind, Result};
use crate::git_wire::{
    GitOid, GitRefName, GitWire, GitWireRepo, git_object_edges, lock_repository,
};
use crate::origin::document_candidate_types::ReceivedRefIngress;
use crate::origin::lfs::lfs_repo_id;
use crate::origin::publication::{
    OriginPublicationAnswer, OriginPublicationRequest, OriginPublicationStatus,
};
use crate::origin::secret_marks::{
    RepoMarkFacts, RepoSecretMark, RepoSecretMarkLookup, readdress_forward_secret_marks_in_txn,
};
use crate::origin::secret_projection::claims::{
    RepoProjectionClaim, RepoProjectionExactForward, RepoProjectionRecord,
};
use crate::origin::secret_projection::git::projection_ingress_dir;
use crate::{EntityId, TimeRange, Vault};

/// One exact forward: the canonical ref and the old and new tips the push
/// named, the old one the canonical CAS expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactForwardPlan {
    pub(crate) ref_name: String,
    pub(crate) old: Option<GitOid>,
    pub(crate) new: GitOid,
}

/// Records `plan` under `proof` and carries the ingress's `marks` to the
/// canonical store (`canonical_identity`), in the writer that precedes the
/// canonical publication. Says whether the forward record was new.
///
/// # Errors
/// A store failure, a failed id derivation, or another record under an id.
pub(crate) fn forward_exact_received_push_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    proof: &RepoProjectionIngressProof,
    plan: &ExactForwardPlan,
    marks: &[RepoSecretMark],
    canonical_identity: &str,
    at: u64,
) -> Result<bool> {
    // The marks land on the canonical store first, in this same writer.
    let mark_ids = readdress_forward_secret_marks_in_txn(
        vault,
        wtxn,
        marks,
        proof.canonical_store(),
        canonical_identity,
    )?;
    let record = RepoProjectionClaim::of(
        proof.graph(),
        RepoProjectionRecord::ExactForward(RepoProjectionExactForward {
            operation: proof.ingress.operation,
            ref_name: plan.ref_name.clone(),
            old: plan.old.clone(),
            new: plan.new.clone(),
            marks: mark_ids,
        }),
    );
    record.put_in_txn(vault, wtxn, at)
}

/// The projection facts an intake row carries, kept here instead of
/// widening the private document_candidates::projected_join module.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExactForwardSource {
    pub(crate) graph: EntityId,
    pub(crate) canonical_store: EntityId,
    pub(crate) operation: EntityId,
    pub(crate) ingress: EntityId,
}

fn retryable(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Storage | ErrorKind::Io | ErrorKind::CorruptedIndex | ErrorKind::MapFull
    )
}

/// A business, evidence or CAS failure returns to today's proposal path;
/// a store failure stays an error so the row remains pending and retries.
fn forward_error(error: Error) -> Result<bool> {
    if retryable(&error) {
        Err(error)
    } else {
        Ok(false)
    }
}

/// Imports every missing object of `new` from `ingress` into `canonical`.
/// Only `already` (the proven old canonical base) prunes the walk. In
/// particular, a present tip from an earlier partial attempt does not hide
/// missing ancestors on the retry.
fn import_ingress_history_to_canonical(
    wire: &GitWire<'_>,
    ingress: &GitWireRepo,
    canonical: &GitWireRepo,
    new: &GitOid,
    already: &[GitOid],
) -> Result<()> {
    let already: BTreeSet<GitOid> = already.iter().cloned().collect();
    let mut pending = vec![new.clone()];
    let mut seen = BTreeSet::new();
    while let Some(oid) = pending.pop() {
        if already.contains(&oid) || !seen.insert(oid.clone()) {
            continue;
        }
        let object = wire.read_object_to_spool(ingress, &oid)?;
        for edge in git_object_edges(&object)? {
            pending.push(edge.target().clone());
        }
        if !wire.object_exists(canonical, &oid)? {
            wire.write_projection_object(canonical, &object)?;
        }
    }
    Ok(())
}

/// Every incoming object, following all commit parents, trees and tags.
/// Only the proven old canonical tip prunes the walk.
fn incoming_history(
    wire: &GitWire<'_>,
    ingress: &GitWireRepo,
    new: &GitOid,
    old: Option<&GitOid>,
) -> Result<Vec<GitOid>> {
    let mut pending = vec![new.clone()];
    let mut seen = BTreeSet::new();
    while let Some(oid) = pending.pop() {
        if old == Some(&oid) || !seen.insert(oid.clone()) {
            continue;
        }
        let object = wire.read_object_to_spool(ingress, &oid)?;
        for edge in git_object_edges(&object)? {
            pending.push(edge.target().clone());
        }
    }
    Ok(seen.into_iter().collect())
}

/// Tries the ExactForward arm for one projected update. `false` always
/// means "run today's proposal path" and writes no candidate hold or
/// attachment. A failed attempt can leave an idempotent forward record,
/// intent or terminal publication row, never a synthetic candidate. Only
/// storage failures are returned as errors.
pub(crate) fn try_forward_exact_ingress_update(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    row: &ReceivedRefIngress,
    provenance: EntityId,
    source: ExactForwardSource,
) -> Result<bool> {
    if row.operations.is_empty()
        || lfs_repo_id(&canonical.identity().as_hex())? != source.canonical_store
    {
        return Ok(false);
    }
    let Some(new_hex) = &row.source.new_oid else {
        return Ok(false);
    };
    let new = GitOid::parse_hex(new_hex.clone())?;
    let old = row
        .source
        .old_oid
        .as_ref()
        .map(|hex| GitOid::parse_hex(hex.clone()))
        .transpose()?;
    let ingress_dir = projection_ingress_dir(vault, source.canonical_store, source.graph)?;
    let Some(ingress) = (match wire.existing_projection_ingress(&ingress_dir) {
        Ok(ingress) => ingress,
        Err(error) => return forward_error(error),
    }) else {
        return Ok(false);
    };
    if ingress.identity().as_hex() != row.source.object_store {
        return Ok(false);
    }
    let ids: Vec<GitOid> = old.iter().chain(std::iter::once(&new)).cloned().collect();
    let kinds = match wire.object_info(&ingress, &ids) {
        Ok(kinds) => kinds,
        Err(_) => return Ok(false),
    };
    if kinds.get(&new).map(String::as_str) != Some("commit")
        || old
            .as_ref()
            .is_some_and(|old| kinds.get(old).map(String::as_str) != Some("commit"))
    {
        return Ok(false);
    }
    if let Some(old) = &old {
        match wire.merge_base(&ingress, old.as_str(), new.as_str()) {
            Ok(base) if base == *old => {}
            _ => return Ok(false),
        }
        match wire.object_exists(canonical, old) {
            Ok(true) => {}
            _ => return Ok(false),
        }
    }
    let ref_name = match GitRefName::parse_full(row.source.ref_name.clone()) {
        Ok(name) => name,
        Err(error) => return forward_error(error),
    };
    let ingress_id = lfs_repo_id(&row.source.object_store)?;
    let Some(publication) = vault.find_origin_publication(ingress_id, |record| {
        record.provenance_claim_id == provenance
            && record.ref_name.as_str() == row.source.ref_name
            && record.new_oid == new
    })?
    else {
        return Ok(false);
    };
    if publication.status != OriginPublicationStatus::Published {
        return Ok(false);
    }
    let Some(pusher) = publication.actor_id.id() else {
        return Ok(false);
    };
    let Some((admission_proof, _)) =
        (match vault.forward_admission_for_operation(ingress.common_dir(), source.operation) {
            Ok(admission) => admission,
            Err(error) => return forward_error(error),
        })
    else {
        return Ok(false);
    };

    if admission_proof.canonical_store() != source.canonical_store
        || admission_proof.graph() != source.graph
    {
        return Ok(false);
    }
    let changed = {
        let txn = vault.store.env.read_txn()?;
        RepoProjectionClaim::changed_copies_in_txn(vault, &txn, &source.graph)?
    };
    let boundary = match incoming_history(wire, &ingress, &new, old.as_ref()) {
        Ok(history) => history,
        Err(_) => return Ok(false),
    };
    if complete_received_push_target(classify_received_projection(
        &changed,
        old.as_ref(),
        &boundary,
    )) != ReceivedPushTarget::Canonical
    {
        return Ok(false);
    }

    let already: Vec<GitOid> = old.iter().cloned().collect();
    let _ingress_guard = lock_repository(ingress.common_dir())?;
    if let Err(_) = import_ingress_history_to_canonical(wire, &ingress, canonical, &new, &already) {
        return Ok(false);
    }
    match wire.reachable_objects_present(canonical, &new, &already) {
        Ok(true) => {}
        _ => return Ok(false),
    }
    let Some((proof, authority)) =
        (match vault.forward_admission_for_operation(ingress.common_dir(), source.operation) {
            Ok(admission) => admission,
            Err(error) => return forward_error(error),
        })
    else {
        return Ok(false);
    };
    if proof.canonical_store() != source.canonical_store || proof.graph() != source.graph {
        return Ok(false);
    }
    let marks = {
        let txn = vault.store.env.read_txn()?;
        let facts = RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?;
        facts.for_operation(source.operation, ingress_id)
    };
    let pointers = match vault.forward_lfs_pointers_for_outcome(provenance) {
        Ok(pointers) => pointers,
        Err(error) => return forward_error(error),
    };
    let admitted = match admit_landing_lfs_pointers(vault, source.canonical_store, &pointers) {
        Ok(admitted) => admitted,
        Err(error) => return forward_error(error),
    };
    let required_lfs_oids = match ref_required_lfs_oids(wire, canonical, &admitted, &new) {
        Ok(required) => required,
        Err(_) => return Ok(false),
    };
    let at = vault.now_recorded_at();
    let plan = ExactForwardPlan {
        ref_name: row.source.ref_name.clone(),
        old: old.clone(),
        new: new.clone(),
    };
    let canonical_identity = canonical.identity().as_hex();
    let _ = vault.with_write_txn_grouped(|wtxn| {
        forward_exact_received_push_in_txn(
            vault,
            wtxn,
            &proof,
            &plan,
            &marks,
            &canonical_identity,
            at,
        )
    })?;

    let intent = entity_id_from_hash_material(
        b"oneiron:projection-forward-intent:v1",
        &[
            source.canonical_store.as_bytes(),
            source.operation.as_bytes(),
            row.source.ref_name.as_bytes(),
            old.as_ref().map_or("", GitOid::as_str).as_bytes(),
            new.as_str().as_bytes(),
        ],
    )?;
    let publication = OriginPublicationRequest {
        repo_id: source.canonical_store,
        repo: canonical.clone(),
        ref_name,
        expected_old_oid: old.clone(),
        new_oid: new.clone(),
        required_objects: vec![new.clone()],
        required_lfs_oids,
        provenance_claim_id: intent,
        actor_id: pusher,
        occurred: TimeRange { start: at, end: at },
        learned_at: at,
    };
    if let Err(error) = vault.put_origin_publication_intent(&publication) {
        return forward_error(error);
    }
    let receipt = match authority.as_ref() {
        Some(authority) => match authority.lease() {
            Ok(lease) => vault.publish_origin_ref_authorized(wire, publication, &lease),
            Err(error) => return forward_error(error),
        },
        None => vault.publish_origin_ref(wire, publication),
    };
    let receipt = match receipt {
        Ok(receipt) => receipt,
        Err(error) => return forward_error(error),
    };
    if receipt.wire_rejection().is_some()
        || (receipt.answer != OriginPublicationAnswer::ResolvedToOwner
            && receipt.record.status != OriginPublicationStatus::Published)
    {
        return Ok(false);
    }
    let update = RefUpdate {
        name: row.source.ref_name.clone(),
        old_oid: old,
        new_oid: Some(new),
    };
    attach_landing_lfs_pointers(
        vault,
        wire,
        canonical,
        source.canonical_store,
        &[update],
        &admitted,
        at,
    )?;
    Ok(true)
}
