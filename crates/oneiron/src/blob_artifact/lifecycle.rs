//! Blob artifact delete path: version-chain, head, and asset-ref cleanup.

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ppr;
use crate::store::Store;

use super::references::{claimed_hashes, fence_released_asset, held_by_live_artifact};
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

/// Removes an artifact's version chain, head record, and asset-reference
/// rows, hard-deleting every ASSET entity this artifact was the LAST
/// reference to — version bytes never outlive the last artifact that holds
/// them, on the vault that wrote them or on any replica (H125).
///
/// The artifact's bytes are its chain's hashes plus every hash its
/// replicated `blob.version` claims name: a replica has no chain of its own.
/// Bytes stay while an `asset_ref` row (one per content-hash × local
/// artifact pair) or a live artifact's version claim still holds them.
/// Runs inside every entity delete path (batch delete, purge, soft erase,
/// remote tombstone replay).
///
/// A released ASSET gets a deletion fence, never a tombstone: its id is the
/// hash of its bytes, and a tombstone would refuse the same bytes uploaded
/// again on every peer for good. The fence refuses a stale carrier at
/// replicated ingest, and the export door scrubs that carrier from the live
/// window history-free. A new artifact holding the same bytes lifts it.
pub(crate) fn delete_blob_artifact_lifecycle_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<BlobArtifactLifecycleCleanup> {
    crate::ingest::invalidate_blob_fingerprint(store, wtxn, id)?;
    crate::artifact_hosting::remove_blob_pointers_in_txn(store, wtxn, id)?;
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    let mut keys = Vec::new();
    let mut hashes: Vec<[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN]> = Vec::new();
    for entry in VERSIONS.iter_from(store, wtxn, id.as_bytes())? {
        let (key, record) = entry?;
        if !hashes.contains(&record.content_hash) {
            hashes.push(record.content_hash);
        }
        keys.push(key);
    }
    for content_hash in claimed_hashes(store, wtxn, id)? {
        if !hashes.contains(&content_hash) {
            hashes.push(content_hash);
        }
    }
    HEAD.delete(store, wtxn, id)?;
    for key in keys {
        VERSIONS.delete(store, wtxn, &key)?;
    }
    for content_hash in hashes {
        ASSET_REF.delete(store, wtxn, &(content_hash, *id))?;
        let still_referenced = ASSET_REF
            .iter_from(store, wtxn, &content_hash)?
            .next()
            .transpose()?
            .is_some()
            || held_by_live_artifact(store, wtxn, &content_hash, Some(id))?;
        if still_referenced {
            continue;
        }
        let asset_id = blob_artifact_asset_entity_id(&content_hash)?;
        let (_existed, had_vector, had_graph_mutation, neighbors) =
            crate::batch::deindex_entity(store, wtxn, &asset_id)?;
        fence_released_asset(store, wtxn, &asset_id)?;
        ppr::invalidate_ppr_for_delete(store, wtxn, &asset_id, &neighbors)?;
        cleanup.had_vector |= had_vector;
        cleanup.had_graph_mutation |= had_graph_mutation;
        cleanup.neighbors.extend(neighbors);
    }
    cleanup.neighbors.sort_unstable();
    cleanup.neighbors.dedup();
    Ok(cleanup)
}
