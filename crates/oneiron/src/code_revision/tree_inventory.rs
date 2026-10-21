//! A tested revision's complete tree (FIX 6868, G2 PR3): the reviewed
//! documents and every other path as a blob reference with its mode.
//!
//! The two parts are a disjoint, complete partition of the checked Git
//! tree. A blob is untouched bytes the queue tested, never a document and
//! never review authority. Capture reads the pinned tree through the
//! shipped bounded reader, never a live checkout; render rebuilds the exact
//! files the origin export writes.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::CodeRevision;
use crate::Vault;
use crate::code_document::CodeDocumentFrontier;
use crate::error::{ArtifactError, Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::origin::tree::{OriginTreeFile, read_tree_files};

/// Git's mode of a submodule link. Kept visible, never exported.
pub(crate) const MODE_GITLINK: u32 = 0o160_000;
const MODE_TREE: u32 = 0o040_000;
/// The same bounds the shipped tree reader keeps.
const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 128;

/// One untouched path of a tested tree: the Git object the checked tree
/// names, the BLAKE3 hash and size of its exact bytes, and its mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeTreeBlob {
    pub git_oid: String,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub mode: u32,
}

/// A captured complete tree: documents by id with their modes, and blobs
/// by path. A read-only value: it issues, reviews and promotes nothing
/// (G4 PR1 makes it public so a checker reads the same body).
#[derive(Debug, Default)]
pub struct CodeTreeInventory {
    pub(crate) documents: BTreeMap<[u8; 32], CodeDocumentFrontier>,
    pub(crate) modes: BTreeMap<[u8; 32], u32>,
    pub(crate) blobs: BTreeMap<String, CodeTreeBlob>,
}

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(reason))
}

impl CodeTreeInventory {
    /// The untouched paths, by path.
    #[must_use]
    pub fn blobs(&self) -> &BTreeMap<String, CodeTreeBlob> {
        &self.blobs
    }

    /// The complete tree `commit` names, captured with no documents: every
    /// path a blob (G4 PR1). The commit must name `expected_tree` in this
    /// object store before anything is enumerated.
    ///
    /// # Errors
    /// A commit naming another tree, an object that cannot be read or a
    /// tree past the shipped bounds.
    pub fn capture_pinned(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        commit: &GitOid,
        expected_tree: &GitOid,
    ) -> Result<Self> {
        if git
            .commit_trees(repo, std::slice::from_ref(commit))?
            .get(commit)
            != Some(expected_tree)
        {
            return Err(invalid("the pinned commit names another tree"));
        }
        Self::capture(vault, git, repo, expected_tree, &BTreeMap::new())?
            .map_err(|_| invalid("a capture with no documents names a document"))
    }

    /// The exact files this captured tree holds, through the one render
    /// body the tested export uses.
    ///
    /// # Errors
    /// A missing or changed object, a duplicate path or a submodule link.
    pub fn render_captured(
        &self,
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
    ) -> Result<BTreeMap<String, OriginTreeFile>> {
        let documents = self.documents.values().map(|frontier| {
            let mode = self
                .modes
                .get(&frontier.document_id)
                .copied()
                .unwrap_or(crate::codebase::DEFAULT_CODE_FILE_MODE);
            (frontier, mode)
        });
        render_files(vault, git, repo, documents, &self.blobs)
    }

    /// Every entry of `tree` by path: its object id and mode, read from
    /// tree objects alone.
    ///
    /// # Errors
    /// A missing object, an unsafe path or a tree past the shipped bounds.
    pub(crate) fn entries(
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        tree: &GitOid,
    ) -> Result<BTreeMap<String, (String, u32)>> {
        let mut out = BTreeMap::new();
        let mut pending = vec![(String::new(), tree.clone(), 0_usize)];
        while let Some((prefix, oid, depth)) = pending.pop() {
            if depth > MAX_DEPTH {
                return Err(Error::IndexOverflow("tested tree depth"));
            }
            for entry in git.read_tree(repo, &oid)? {
                let name = String::from_utf8(entry.name)
                    .map_err(|_| invalid("tested tree paths must be UTF-8"))?;
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                if entry.mode == MODE_TREE {
                    pending.push((path, entry.oid, depth + 1));
                } else if out
                    .insert(path, (entry.oid.as_str().to_owned(), entry.mode))
                    .is_some()
                {
                    return Err(invalid("tested tree repeats a path"));
                }
                if out.len() > MAX_ENTRIES {
                    return Err(Error::IndexOverflow("tested tree entries"));
                }
            }
        }
        Ok(out)
    }

    /// Captures the complete tree `tree` names. `documents` names, by path,
    /// the reviewed document frontier and mode each document path holds;
    /// every other path is a blob. `Ok(Err(_))` names a document whose
    /// regenerated bytes or mode differ from the tree's own.
    ///
    /// # Errors
    /// An object that cannot be read or a tree past the shipped bounds.
    pub(crate) fn capture(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        tree: &GitOid,
        documents: &BTreeMap<String, (CodeDocumentFrontier, u32)>,
    ) -> Result<std::result::Result<Self, String>> {
        let files = read_tree_files(git, repo, tree)?;
        let entries = Self::entries(git, repo, tree)?;
        if files.len() != entries.len() {
            return Err(invalid("the tested tree reads disagree"));
        }
        let mut inventory = Self::default();
        for (path, file) in &files {
            let (oid, mode) = entries
                .get(path)
                .ok_or_else(|| invalid("the tested tree reads disagree"))?;
            if *mode != file.mode {
                return Err(invalid("the tested tree reads disagree"));
            }
            if let Some((frontier, document_mode)) = documents.get(path) {
                if frontier.path != *path
                    || *document_mode != file.mode
                    || vault.code_document_at(frontier)?.as_bytes() != file.content.as_slice()
                {
                    return Ok(Err(format!(
                        "{path}: the reviewed document is not the checked tree's bytes and mode"
                    )));
                }
                inventory.modes.insert(frontier.document_id, file.mode);
                if inventory
                    .documents
                    .insert(frontier.document_id, frontier.clone())
                    .is_some()
                {
                    return Ok(Err(format!("{path}: one document names two paths")));
                }
            } else {
                inventory.blobs.insert(
                    path.clone(),
                    CodeTreeBlob {
                        git_oid: oid.clone(),
                        content_hash: *blake3::hash(&file.content).as_bytes(),
                        size_bytes: file.content.len() as u64,
                        mode: file.mode,
                    },
                );
            }
        }
        if let Some(path) = documents.keys().find(|path| !files.contains_key(*path)) {
            return Ok(Err(format!(
                "{path}: a reviewed document is not in the checked tree"
            )));
        }
        Ok(Ok(inventory))
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
                    part.is_empty() || matches!(part, "." | ".." | ".git") || part.contains('\0')
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

    /// The exact files `revision`'s complete tree holds, for the origin
    /// export: documents regenerated from their authenticated folds, blobs
    /// read at their recorded object and checked against their size, hash
    /// and mode. A submodule link stays a visible refusal.
    ///
    /// # Errors
    /// A missing or changed object, a duplicate path or a submodule link.
    pub(crate) fn render(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        revision: &CodeRevision,
    ) -> Result<BTreeMap<String, OriginTreeFile>> {
        Self::validate_partition(revision)?;
        let documents = revision
            .file_frontiers
            .values()
            .map(|frontier| (frontier, document_mode(revision, &frontier.document_id)));
        render_files(vault, git, repo, documents, &revision.blob_frontiers)
    }
}

/// The one render body: documents regenerated from their authenticated
/// folds at their modes, blobs read at their recorded object and checked
/// against their size and hash. A submodule link stays a visible refusal.
fn render_files<'d>(
    vault: &Vault,
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    documents: impl Iterator<Item = (&'d CodeDocumentFrontier, u32)>,
    blobs: &BTreeMap<String, CodeTreeBlob>,
) -> Result<BTreeMap<String, OriginTreeFile>> {
    let mut files = BTreeMap::new();
    for (frontier, mode) in documents {
        let file = OriginTreeFile {
            mode,
            content: vault.code_document_at(frontier)?.into_bytes(),
        };
        if files.insert(frontier.path.clone(), file).is_some() {
            return Err(Error::InvariantViolation(
                "tested revision duplicates a file path",
            ));
        }
    }
    for (path, blob) in blobs {
        if blob.mode == MODE_GITLINK {
            return Err(Error::InvariantViolation(
                "the tested tree holds a submodule link the origin export does not write",
            ));
        }
        let content = git.read_object(repo, &GitOid::parse_hex(blob.git_oid.clone())?)?;
        if content.len() as u64 != blob.size_bytes
            || blake3::hash(&content).as_bytes() != &blob.content_hash
        {
            return Err(Error::InvariantViolation(
                "a tested tree blob differs from its recorded bytes",
            ));
        }
        let file = OriginTreeFile {
            mode: blob.mode,
            content,
        };
        if files.insert(path.clone(), file).is_some() {
            return Err(Error::InvariantViolation(
                "tested revision duplicates a file path",
            ));
        }
    }
    Ok(files)
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
                part.is_empty() || matches!(part, "." | ".." | ".git") || part.contains('\0')
            })
            || GitOid::parse_hex(previous.git_oid.clone()).is_err()
            || crate::codebase::validate_code_file_mode(previous.mode).is_err()
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
        .unwrap_or(crate::codebase::DEFAULT_CODE_FILE_MODE)
}
