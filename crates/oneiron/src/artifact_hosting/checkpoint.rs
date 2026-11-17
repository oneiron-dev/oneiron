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

use super::serving_blob::SERVING_BLOBS;
use super::{
    ARTIFACT_ADMISSIONS, ARTIFACT_POINTERS, ArtifactExportRef, ArtifactPointerRow,
    ArtifactPointerRowKey, ArtifactPublishAdmission,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::checkpoint_payload::rows::descriptor::{AdapterTable, ExactTable, PlacedTable};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RowLocator, TypedRow, Unresolved,
};

/// The field the publish's actor fills.
const ACTOR: &str = "actor";

/// The channel pointers, each byte-exact under the artifact its key names
/// when its export is a version of that artifact.
pub(crate) const POINTERS: &dyn AdapterTable = &PlacedTable {
    table: ARTIFACT_POINTERS,
    place: place_pointer,
};

/// The publish admissions, each under its export's artifact, its actor split
/// out.
pub(crate) const ADMISSIONS: &dyn AdapterTable = &PlacedTable {
    table: ARTIFACT_ADMISSIONS,
    place: place_admission,
};

/// The serving descriptors, each byte-exact under the artifact its key names.
pub(crate) const SERVING: &dyn AdapterTable = &ExactTable {
    table: SERVING_BLOBS,
    owner: serving_artifact,
};

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

/// A pointer under its artifact; a code fork's pointer, or one whose key
/// names another artifact, has no proved owner.
#[allow(
    clippy::unnecessary_wraps,
    reason = "a placement callback: PlacedTable's fn pointer returns Result"
)]
fn place_pointer(
    out: &mut Captured,
    row: TypedRow<ArtifactPointerRowKey, ArtifactPointerRow>,
) -> Result<()> {
    match row.value.export {
        ArtifactExportRef::BlobVersion { artifact_id, .. }
            if row.key.artifact == artifact_id.to_hex() =>
        {
            out.exact(OwnerRef::entity(&artifact_id), row.at, row.bytes);
        }
        _ => out.unclassified(row.at, None, Unresolved::NoOwner),
    }
    Ok(())
}

/// An admission under the artifact its export names, when that is its own
/// export entity.
fn place_admission(
    out: &mut Captured,
    row: TypedRow<EntityId, ArtifactPublishAdmission>,
) -> Result<()> {
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
            out,
            OwnerRef::entity(&owner_id),
            ARTIFACT_ADMISSIONS,
            row,
            |admission| take_actor(admission, owner_id),
        ),
        None => {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            Ok(())
        }
    }
}

/// The artifact a serving descriptor's key names.
fn serving_artifact(key: &(EntityId, u64)) -> OwnerRef {
    OwnerRef::entity(&key.0)
}

/// A hosting row with its actor back; `None` when the actor did not open.
pub(crate) fn join(at: &RowLocator, value: &[u8], parts: &[&ActorPart]) -> Result<Option<Vec<u8>>> {
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
