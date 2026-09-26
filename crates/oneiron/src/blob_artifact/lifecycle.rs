//! Blob artifact delete path: version-chain, head, and asset-ref cleanup.

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ppr;
use crate::store::Store;

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
/// rows, hard-deleting every ASSET entity this chain was the LAST reference
/// to — version bytes never outlive the last chain that references them.
/// The refcount is the `blob_artifact:asset_ref:v1:` rows (one per
/// content-hash × artifact pair, vault-scoped like the dedupe itself).
/// Runs inside every entity delete path (batch delete, purge, soft erase)
/// and is a cheap no-op for entities without a version chain. Side-deleted
/// assets carry no sync tombstone of their own: they are derived
/// content-addressed storage, and a replay-rematerialized asset is a
/// harmless orphan that the next last-reference delete removes again.
pub(crate) fn delete_blob_artifact_lifecycle_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<BlobArtifactLifecycleCleanup> {
    crate::ingest::invalidate_blob_fingerprint(store, wtxn, id)?;
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
            .is_some();
        if still_referenced {
            continue;
        }
        let asset_id = blob_artifact_asset_entity_id(&content_hash)?;
        let (_existed, had_vector, had_graph_mutation, neighbors) =
            crate::batch::deindex_entity(store, wtxn, &asset_id)?;
        ppr::invalidate_ppr_for_delete(store, wtxn, &asset_id, &neighbors)?;
        cleanup.had_vector |= had_vector;
        cleanup.had_graph_mutation |= had_graph_mutation;
        cleanup.neighbors.extend(neighbors);
    }
    cleanup.neighbors.sort_unstable();
    cleanup.neighbors.dedup();
    Ok(cleanup)
}
