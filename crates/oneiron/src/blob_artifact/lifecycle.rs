//! Blob artifact delete path: version-chain, head, and asset-ref cleanup.

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ppr;
use crate::store::Store;

use super::store_keys::{
    BLOB_ARTIFACT_CONTENT_HASH_LEN, blob_artifact_asset_ref_key, blob_artifact_asset_ref_prefix,
    blob_artifact_head_key, blob_artifact_version_prefix,
};
use super::versions::{blob_artifact_asset_entity_id, decode_blob_artifact_version_record};

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
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    let prefix = blob_artifact_version_prefix(id);
    let mut keys = Vec::new();
    let mut hashes: Vec<[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN]> = Vec::new();
    for entry in store.vault_meta.prefix_iter(wtxn, &prefix)? {
        let (key, raw) = entry?;
        let record = decode_blob_artifact_version_record(&raw)?;
        if !hashes.contains(&record.content_hash) {
            hashes.push(record.content_hash);
        }
        keys.push(key.to_vec());
    }
    store.vault_meta.delete(wtxn, &blob_artifact_head_key(id))?;
    for key in keys {
        store.vault_meta.delete(wtxn, &key)?;
    }
    for content_hash in hashes {
        store
            .vault_meta
            .delete(wtxn, &blob_artifact_asset_ref_key(&content_hash, id))?;
        let ref_prefix = blob_artifact_asset_ref_prefix(&content_hash);
        let still_referenced = store
            .vault_meta
            .prefix_iter(wtxn, &ref_prefix)?
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
