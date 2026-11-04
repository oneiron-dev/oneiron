//! A tested revision's complete tree (FIX 6868, G2 PR3): the reviewed
//! documents and every other path as a blob reference with its mode.
//!
//! The two parts are a disjoint, complete partition of the checked Git
//! tree. A blob is untouched bytes the queue tested, never a document and
//! never review authority. Capture reads the pinned tree through the
//! shipped counted reader, never a live checkout; render rebuilds the exact
//! files the origin export writes.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::CodeRevision;
use crate::Vault;
use crate::code_document::CodeDocumentFrontier;
use crate::error::{ArtifactError, Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::origin::tree::{OriginTreeFile, read_tree_files, start_tree_count};

pub(crate) use crate::store::code_tree_blob::MODE_GITLINK;
const MODE_TREE: u32 = 0o040_000;

pub use crate::store::code_tree_blob::CodeTreeBlob;

pub use crate::store::code_revision_record::CodeTreeInventory;
pub(crate) use crate::store::code_revision_record::tree_inventory::document_mode;
use crate::store::code_revision_record::tree_inventory::invalid;

/// Complete-tree operations that read code documents and Git objects.
pub trait CodeTreeInventoryRuntime: Sized {
    fn capture_pinned(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        commit: &GitOid,
        expected_tree: &GitOid,
    ) -> Result<Self>;
    fn render_captured(
        &self,
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
    ) -> Result<BTreeMap<String, OriginTreeFile>>;
    fn entries(
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        tree: &GitOid,
    ) -> Result<BTreeMap<String, (String, u32)>>;
    fn capture(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        tree: &GitOid,
        documents: &BTreeMap<String, (CodeDocumentFrontier, u32)>,
    ) -> Result<std::result::Result<Self, String>>;
    fn render(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        revision: &CodeRevision,
    ) -> Result<BTreeMap<String, OriginTreeFile>>;
}

impl CodeTreeInventoryRuntime for CodeTreeInventory {
    /// The complete tree `commit` names, captured with no documents: every
    /// path a blob (G4 PR1). The commit must name `expected_tree` in this
    /// object store before anything is enumerated.
    ///
    /// # Errors
    /// A commit naming another tree, an object that cannot be read or a
    /// file past the reader's byte floors.
    fn capture_pinned(
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
    fn render_captured(
        &self,
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
    ) -> Result<BTreeMap<String, OriginTreeFile>> {
        let documents: Vec<(&CodeDocumentFrontier, u32)> = self
            .documents
            .values()
            .map(|frontier| {
                let mode = self
                    .modes
                    .get(&frontier.document_id)
                    .copied()
                    .unwrap_or(crate::codebase::DEFAULT_CODE_FILE_MODE);
                (frontier, mode)
            })
            .collect();
        render_files(vault, git, repo, &documents, &self.blobs)
    }

    /// Every entry of `tree` by path: its object id and mode, read from
    /// tree objects alone. The walk reads every level and entry however
    /// many (rule 5, FIX 9692): past its scan row it raises a check.
    ///
    /// # Errors
    /// A missing object or an unsafe path.
    fn entries(
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        tree: &GitOid,
    ) -> Result<BTreeMap<String, (String, u32)>> {
        let mut count = start_tree_count(git, repo)?;
        let mut out = BTreeMap::new();
        let mut pending = vec![(String::new(), tree.clone())];
        while let Some((prefix, oid)) = pending.pop() {
            for entry in git.read_tree(repo, &oid)? {
                count.row();
                let name = String::from_utf8(entry.name)
                    .map_err(|_| invalid("tested tree paths must be UTF-8"))?;
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                if entry.mode == MODE_TREE {
                    pending.push((path, entry.oid));
                } else if out
                    .insert(path, (entry.oid.as_str().to_owned(), entry.mode))
                    .is_some()
                {
                    return Err(invalid("tested tree repeats a path"));
                }
            }
        }
        count.finish(git.vault());
        Ok(out)
    }

    /// Captures the complete tree `tree` names. `documents` names, by path,
    /// the reviewed document frontier and mode each document path holds;
    /// every other path is a blob. `Ok(Err(_))` names a document whose
    /// regenerated bytes or mode differ from the tree's own.
    ///
    /// # Errors
    /// An object that cannot be read or a file past the reader's byte floors.
    fn capture(
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

    /// The exact files `revision`'s complete tree holds, for the origin
    /// export: documents regenerated from their authenticated folds, blobs
    /// read at their recorded object and checked against their size, hash
    /// and mode. A submodule link stays a visible refusal.
    ///
    /// # Errors
    /// A missing or changed object, a duplicate path or a submodule link.
    fn render(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        revision: &CodeRevision,
    ) -> Result<BTreeMap<String, OriginTreeFile>> {
        Self::validate_partition(revision)?;
        let documents: Vec<(&CodeDocumentFrontier, u32)> = revision
            .file_frontiers
            .values()
            .map(|frontier| (frontier, document_mode(revision, &frontier.document_id)))
            .collect();
        render_files(vault, git, repo, &documents, &revision.blob_frontiers)
    }
}

/// The one render body: documents regenerated from their authenticated
/// folds at their modes, blobs read at their recorded object and checked
/// against their size and hash. A submodule link stays a visible refusal.
fn render_files(
    vault: &Vault,
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    documents: &[(&CodeDocumentFrontier, u32)],
    blobs: &BTreeMap<String, CodeTreeBlob>,
) -> Result<BTreeMap<String, OriginTreeFile>> {
    let mut files = BTreeMap::new();
    for &(frontier, mode) in documents {
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
