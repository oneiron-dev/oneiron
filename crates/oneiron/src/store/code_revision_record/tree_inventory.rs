//! Pure complete-tree partition, digest and recorded mode vocabulary.

use super::CodeRevision;
use crate::error::{ArtifactError, Error, Result};
use crate::git_wire::{GitOid, git_path_bytes};
use crate::store::code_document_values::CodeDocumentFrontier;
use crate::store::code_tree_blob::{CodeTreeBlob, MODE_GITLINK};
use std::collections::{BTreeMap, BTreeSet};

/// A captured complete tree: documents by id with their modes, and blobs
/// by path. A read-only value: it issues, reviews and promotes nothing
/// (G4 PR1 makes it public so a checker reads the same body).
#[derive(Debug, Default)]
pub struct CodeTreeInventory {
    pub(crate) documents: BTreeMap<[u8; 32], CodeDocumentFrontier>,
    pub(crate) modes: BTreeMap<[u8; 32], u32>,
    pub(crate) blobs: BTreeMap<String, CodeTreeBlob>,
}

pub(crate) fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(reason))
}

impl CodeTreeInventory {
    /// The untouched paths, by path.
    #[must_use]
    pub fn blobs(&self) -> &BTreeMap<String, CodeTreeBlob> {
        &self.blobs
    }

    /// The disjoint, well-formed partition `revision` keeps. Blobs belong
    /// to a tested queue revision alone.
    ///
    /// # Errors
    /// Overlapping paths, an unsafe path or mode, or blobs on an ordinary
    /// revision.
    pub(crate) fn validate_partition(revision: &CodeRevision) -> Result<()> {
        if revision.tested_queue.is_none() && !revision.blob_frontiers.is_empty() {
            return Err(invalid("blob frontiers belong to a tested queue revision"));
        }
        let documents: BTreeSet<&str> = revision
            .file_frontiers
            .values()
            .map(|frontier| frontier.path.as_str())
            .collect();
        for (path, blob) in &revision.blob_frontiers {
            if documents.contains(path.as_str())
                || path.is_empty()
                || path.split('/').any(|part| {
                    part.is_empty()
                        || matches!(part, "." | ".." | ".git")
                        || git_path_bytes(part).is_err()
                })
                || GitOid::parse_hex(blob.git_oid.clone()).is_err()
                || !matches!(blob.mode, 0o100_644 | 0o100_755 | 0o120_000 | MODE_GITLINK)
            {
                return Err(invalid("invalid tested tree blob"));
            }
        }
        validate_import_fields(revision, &documents)
    }

    /// The one digest of `revision`'s complete inventory: every document's
    /// path, id, frontier and mode, and every blob's path, object, hash,
    /// size and mode.
    ///
    /// # Errors
    /// An encoding failure.
    pub(crate) fn digest(revision: &CodeRevision) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:code-tree-inventory:v1");
        let documents: BTreeMap<&str, &CodeDocumentFrontier> = revision
            .file_frontiers
            .values()
            .map(|frontier| (frontier.path.as_str(), frontier))
            .collect();
        hasher.update(&(documents.len() as u64).to_be_bytes());
        for (path, frontier) in documents {
            let encoded = rmp_serde::to_vec_named(frontier)
                .map_err(|_| invalid("tested tree document encode"))?;
            for part in [path.as_bytes(), encoded.as_slice()] {
                hasher.update(&(part.len() as u64).to_be_bytes());
                hasher.update(part);
            }
            hasher.update(&document_mode(revision, &frontier.document_id).to_be_bytes());
        }
        hash_blobs(&mut hasher, &revision.blob_frontiers);
        Ok(*hasher.finalize().as_bytes())
    }

    /// [`Self::digest`] of a tree with no documents and exactly `blobs`:
    /// the same bytes, so an import manifest and the checked baseline it
    /// matches name one digest (G4 PR1).
    pub(crate) fn blob_digest(blobs: &BTreeMap<String, CodeTreeBlob>) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:code-tree-inventory:v1");
        hasher.update(&0_u64.to_be_bytes());
        hash_blobs(&mut hasher, blobs);
        *hasher.finalize().as_bytes()
    }
}

/// Folds every blob's path, object, hash, size and mode, in path order.
fn hash_blobs(hasher: &mut blake3::Hasher, blobs: &BTreeMap<String, CodeTreeBlob>) {
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

/// The import binding and retired paths belong to a tested queue revision
/// alone, and a retired path is gone from its final tree: a well-formed
/// predecessor at a supported mode, its document (if any) at that path
/// (G4 PR1). Their producers and verifier are G4 PR2's.
fn validate_import_fields(revision: &CodeRevision, documents: &BTreeSet<&str>) -> Result<()> {
    if revision.tested_queue.is_none()
        && (revision.snapshot_anchor.is_some() || !revision.retired_paths.is_empty())
    {
        return Err(invalid(
            "an import binding or retired path belongs to a tested queue revision",
        ));
    }
    for (path, retirement) in &revision.retired_paths {
        let previous = &retirement.previous;
        if documents.contains(path.as_str())
            || revision.blob_frontiers.contains_key(path)
            || path.is_empty()
            || path.split('/').any(|part| {
                part.is_empty()
                    || matches!(part, "." | ".." | ".git")
                    || git_path_bytes(part).is_err()
            })
            || GitOid::parse_hex(previous.git_oid.clone()).is_err()
            || crate::store::code_snapshot::validate_code_file_mode(previous.mode).is_err()
            || retirement
                .document
                .as_ref()
                .is_some_and(|document| document.path != *path)
        {
            return Err(invalid("invalid retired tested tree path"));
        }
    }
    Ok(())
}

/// A document's recorded mode; an unlisted one is an ordinary file.
pub(crate) fn document_mode(revision: &CodeRevision, document: &[u8; 32]) -> u32 {
    revision
        .commit_metadata
        .as_ref()
        .and_then(|metadata| metadata.file_modes.get(document))
        .copied()
        .unwrap_or(crate::store::code_snapshot::DEFAULT_CODE_FILE_MODE)
}
