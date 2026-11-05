//! Pure complete-tree partition, digest and recorded mode vocabulary.

use crate::code_document_values::CodeDocumentFrontier;
use crate::code_tree_blob::CodeTreeBlob;
use crate::code_tree_blob::MODE_GITLINK;
use crate::git_wire::ids::GitOid;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use std::collections::{BTreeMap, BTreeSet};

pub fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(reason))
}

/// Folds every blob's path, object, hash, size and mode, in path order.
pub fn hash_blobs(hasher: &mut blake3::Hasher, blobs: &BTreeMap<String, CodeTreeBlob>) {
    hasher.update(&(blobs.len() as u64).to_be_bytes());
    for (path, blob) in blobs {
        for part in [path.as_bytes(), blob.git_oid.as_bytes()] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        hasher.update(&blob.content_hash);
        hasher.update(&blob.size_bytes.to_be_bytes());
        hasher.update(&blob.mode.to_be_bytes());
    }
}
