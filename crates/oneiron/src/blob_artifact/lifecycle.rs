//! Blob artifact delete path: version-chain, head, and asset-ref cleanup.

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ppr;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::Store;

use super::holders::artifact_hashes;
use super::references::{fence_released_asset, forget_claimed_hashes, held_by_live_artifact};
use super::store_keys::{ASSET_REF, BLOB_ARTIFACT_CONTENT_HASH_LEN};
use super::versions::{HEAD, VERSIONS, blob_artifact_asset_entity_id};

/// Outcome of blob-artifact lifecycle cleanup: index flags and graph
/// neighbors from any orphaned ASSET entities deleted with the chain, for
/// the caller to fold into its own deletion accounting.
#[derive(Debug, Default)]
pub(crate) struct BlobArtifactLifecycleCleanup {
    pub(crate) had_vector: bool,
    pub(crate) had_graph_mutation: bool,
    pub(crate) neighbors: Vec<EntityId>,
}

/// Removes an artifact's version chain, head record, born-from index rows and
/// asset-reference rows, hard-deleting every ASSET entity this artifact was the LAST
/// reference to — version bytes never outlive the last artifact that holds
/// them, on the vault that wrote them or on any replica (H125).
///
/// The artifact's bytes are its chain's hashes plus every hash its
/// replicated `blob.version` claims name: a replica has no chain of its own.
/// Those claims count only for an artifact row, or for an id with no row
/// here (an artifact whose delete arrived first), never for another kind of
/// row a claim names. Bytes stay while an `asset_ref` row (one per
/// content-hash × local artifact pair) or a live artifact's version claim
/// still holds them. Runs inside every entity delete path (batch delete,
/// purge, soft erase, remote tombstone replay).
///
/// A released ASSET gets a deletion fence, never a tombstone: its id is the
/// hash of its bytes, and a tombstone would refuse the same bytes uploaded
/// again on every peer for good. The fence refuses a stale carrier at
/// replicated ingest, and the export door deletes that carrier from the live
/// window as an ordinary delete. A new artifact holding the same bytes lifts it.
pub(crate) fn delete_blob_artifact_lifecycle_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<BlobArtifactLifecycleCleanup> {
    crate::ingest::invalidate_blob_fingerprint(store, wtxn, id)?;
    crate::artifact_hosting::remove_blob_pointers_in_txn(store, wtxn, id)?;
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    let hashes = artifact_hashes(store, wtxn, id)?;
    let keys = VERSIONS.scan_keys(store, wtxn, id.as_bytes())?;
    forget_claimed_hashes(store, wtxn, id)?;
    HEAD.delete(store, wtxn, id)?;
    for key in keys {
        if let Some(version) = VERSIONS.get_lenient(store, wtxn, &key)? {
            super::born_from::unindex_version_in_txn(store, wtxn, id, &version)?;
        }
        VERSIONS.delete(store, wtxn, &key)?;
    }
    for content_hash in hashes {
        ASSET_REF.delete(store, wtxn, &(content_hash, *id))?;
        release_unheld_bytes(store, wtxn, &content_hash, id, &mut cleanup)?;
    }
    cleanup.neighbors.sort_unstable();
    cleanup.neighbors.dedup();
    Ok(cleanup)
}

/// Releases the bytes under `content_hash` once `artifact` lets go of them, unless an
/// `asset_ref` row or another live artifact's version claim still holds them: their ASSET is
/// fenced, and deindexed when its row is stored here. Never the id being deleted, and never a
/// row of another kind stored at the content-addressed id.
fn release_unheld_bytes(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    artifact: &EntityId,
    cleanup: &mut BlobArtifactLifecycleCleanup,
) -> Result<()> {
    let still_referenced = ASSET_REF
        .iter_from(store, wtxn, content_hash)?
        .next()
        .transpose()?
        .is_some()
        || held_by_live_artifact(store, wtxn, content_hash, Some(artifact))?;
    if still_referenced {
        return Ok(());
    }
    let asset_id = blob_artifact_asset_entity_id(content_hash)?;
    if asset_id == *artifact {
        return Ok(());
    }
    let stored_type = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &asset_id)?
        .map(|raw| raw.first().copied());
    match stored_type {
        None => fence_released_asset(store, wtxn, &asset_id),
        Some(Some(ENTITY_TYPE_ASSET)) => {
            fence_released_asset(store, wtxn, &asset_id)?;
            let (_existed, had_vector, had_graph_mutation, neighbors) =
                crate::batch::deindex_entity(store, wtxn, &asset_id)?;
            ppr::invalidate_ppr_for_delete(store, wtxn, &asset_id, &neighbors)?;
            cleanup.had_vector |= had_vector;
            cleanup.had_graph_mutation |= had_graph_mutation;
            cleanup.neighbors.extend(neighbors);
            Ok(())
        }
        Some(_) => Ok(()),
    }
}

/// Settles the bytes a `blob.version` claim names when its artifact was deleted here before the
/// claim arrived: the delete already ran without this hash, so they go now unless something live
/// holds them.
pub(super) fn release_bytes_of_deleted_artifact(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<()> {
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    release_unheld_bytes(store, wtxn, content_hash, artifact, &mut cleanup)?;
    if cleanup.had_graph_mutation {
        ppr::increment_graph_version(store, wtxn)?;
    }
    if cleanup.had_vector {
        crate::hnsw::increment_vector_version(store, wtxn)?;
    }
    Ok(())
}
