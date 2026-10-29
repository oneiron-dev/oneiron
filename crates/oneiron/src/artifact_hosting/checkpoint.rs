//! The checkpoint getter of artifact hosting rows (FIX 10436): each blob
//! artifact's channel pointers, publish admissions and serving descriptors
//! under the artifact's own entity tree. A pointer or a serving descriptor
//! names no actor and goes byte-exact; an admission's actor is an actor
//! part, as a version's is. A code fork's pointer, or a blob row whose key
//! does not name its artifact, has no proved owner and stays unclassified.
//! Nothing calls this until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use super::serving_blob::SERVING_BLOBS;
use super::{ARTIFACT_ADMISSIONS, ARTIFACT_POINTERS, ArtifactExportRef, ArtifactPublishAdmission};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RowLocator, Unresolved,
};

/// The field the publish's actor fills.
const ACTOR: &str = "actor";

/// Moves the admission's actor out, leaving `owner` in its place.
fn take_actor(
    admission: &mut ArtifactPublishAdmission,
    owner: EntityId,
) -> Vec<(String, EntityId)> {
    let actor = std::mem::replace(&mut admission.actor, owner);
    vec![(ACTOR.to_owned(), actor)]
}

/// Puts an opened actor back where the split left the owner.
fn put_actor(admission: &mut ArtifactPublishAdmission, field: &str, actor: EntityId) -> Result<()> {
    if field != ACTOR {
        return Err(rows::bad_part());
    }
    admission.actor = actor;
    Ok(())
}

/// Every hosting row in `txn`, by artifact.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, ARTIFACT_POINTERS, &mut out)? {
        match row.value.export {
            ArtifactExportRef::BlobVersion { artifact_id, .. }
                if row.key.artifact == artifact_id.to_hex() =>
            {
                out.exact(OwnerRef::entity(&artifact_id), row.at, row.bytes);
            }
            _ => out.unclassified(row.at, None, Unresolved::NoOwner),
        }
    }
    for row in rows::typed_rows(dbs, txn, ARTIFACT_ADMISSIONS, &mut out)? {
        let owner_id = match row.value.export {
            ArtifactExportRef::BlobVersion { artifact_id, .. }
                if artifact_id == row.value.export_entity_id =>
            {
                Some(artifact_id)
            }
            _ => None,
        };
        match owner_id {
            Some(owner_id) => rows::split_actors(
                &mut out,
                OwnerRef::entity(&owner_id),
                ARTIFACT_ADMISSIONS,
                row,
                |admission| take_actor(admission, owner_id),
            )?,
            None => out.unclassified(row.at, None, Unresolved::NoOwner),
        }
    }
    for row in rows::typed_rows(dbs, txn, SERVING_BLOBS, &mut out)? {
        let artifact = row.key.0;
        out.exact(OwnerRef::entity(&artifact), row.at, row.bytes);
    }
    Ok(out)
}

/// Whether `at` is a hosting row.
pub(crate) fn owns(at: &RowLocator) -> bool {
    at.in_table(ARTIFACT_POINTERS.decl())
        || at.in_table(ARTIFACT_ADMISSIONS.decl())
        || at.in_table(SERVING_BLOBS.decl())
}

/// Checks `value` at `at` with its own codec.
pub(crate) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(ARTIFACT_POINTERS.decl()) {
        rows::check_row(ARTIFACT_POINTERS, at, value)
    } else if at.in_table(ARTIFACT_ADMISSIONS.decl()) {
        rows::check_row(ARTIFACT_ADMISSIONS, at, value)
    } else if at.in_table(SERVING_BLOBS.decl()) {
        rows::check_row(SERVING_BLOBS, at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// A hosting row with its actor back; `None` when the actor did not open.
pub(crate) fn join(
    _: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.in_table(ARTIFACT_POINTERS.decl()) || at.in_table(SERVING_BLOBS.decl()) {
        return Ok(Some(value.to_vec()));
    }
    if at.in_table(ARTIFACT_ADMISSIONS.decl()) {
        if parts.is_empty() {
            return Ok(None);
        }
        let admission = rows::join_actors(ARTIFACT_ADMISSIONS, value, parts, put_actor)?;
        return ARTIFACT_ADMISSIONS.encode_value(&admission).map(Some);
    }
    Err(rows::bad_part())
}
