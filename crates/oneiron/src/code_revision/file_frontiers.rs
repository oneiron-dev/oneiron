//! Canonical tested-file maps and their fold input, verified from persisted operations.

use super::CodeRevision;
use crate::code_document::{CodeDocumentFrontier, verify_frontier_in_txn};
use crate::error::{ArtifactError, Error, Result};
use crate::store::Store;
use heed::RoTxn;
use rmpv::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) use crate::store::code_revision_record::file_frontiers::{
    from_value, invalid, to_value, validate,
};

pub(super) fn artifact_hash(
    store: &Store,
    txn: &RoTxn<'_>,
    revision: &CodeRevision,
    body: &[u8],
) -> Result<[u8; 32]> {
    validate(revision)?;
    super::tree_inventory::CodeTreeInventory::validate_partition(revision)?;
    let body_hash: [u8; 32] = Sha256::digest(body).into();
    if revision.file_frontiers.is_empty()
        && revision.commit_metadata.is_none()
        && revision.blob_frontiers.is_empty()
        && revision.tested_queue.is_none()
        && revision.snapshot_anchor.is_none()
        && revision.retired_paths.is_empty()
    {
        return Ok(body_hash);
    }
    let mut h = Sha256::new();
    h.update(b"oneiron:code-revision-tested-files:v1");
    h.update(body_hash);
    if let Some(metadata) = &revision.commit_metadata {
        super::commit_metadata::validate(revision)?;
        let encoded = super::codec::encode_value(
            &super::commit_metadata::to_value(Some(metadata)),
            "commit metadata encode",
        )?;
        h.update(b"commit-metadata:v1");
        h.update((encoded.len() as u64).to_be_bytes());
        h.update(encoded);
    }

    h.update((revision.file_frontiers.len() as u64).to_be_bytes());
    for frontier in revision.file_frontiers.values() {
        // Never trust a caller's file fold. Decode the immutable snapshot and
        // recompute every operation, actor stamp, version and rendered body.
        verify_frontier_in_txn(store, txn, frontier)?;
        let encoded = rmp_serde::to_vec_named(frontier).map_err(|_| invalid())?;
        h.update((encoded.len() as u64).to_be_bytes());
        h.update(encoded);
    }
    // A tested queue revision's blobs and record fold after its documents;
    // an ordinary revision adds nothing (G2 PR3).
    super::tree_codec::hash_queue_fields(&mut h, revision)?;
    // Its import binding and retirements fold last; none adds nothing (G4).
    super::tree_codec::hash_import_fields(&mut h, revision)?;
    Ok(h.finalize().into())
}
