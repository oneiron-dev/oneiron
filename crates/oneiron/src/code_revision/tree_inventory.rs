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
use crate::origin::tree::{MAX_TREE_FILE_BYTES, OriginTreeFile, start_tree_count};

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
    /// An object that cannot be read or a file past the reader's byte floor.
    fn capture(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        tree: &GitOid,
        documents: &BTreeMap<String, (CodeDocumentFrontier, u32)>,
    ) -> Result<std::result::Result<Self, String>> {
        let entries = Self::entries(git, repo, tree)?;
        Self::capture_entries(
            vault,
            git,
            repo,
            &entries,
            documents,
            &BTreeMap::new(),
            &BTreeSet::new(),
        )
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
impl CodeTreeInventory {
    /// [`Self::capture`] of a tree whose `entries` were already walked (FIX
    /// 7349). Only the bytes it must judge are read, in bounded batches: a
    /// blob whose Git object `known` already measured (a sealed parent's
    /// blob, by object id) is taken as measured, and a document path in
    /// `verified` (one a sealed parent proved at the same object) is not
    /// read again. Every read file stays under the per-file byte floor.
    ///
    /// # Errors
    /// An unsafe path or mode, an object that cannot be read, or a file past
    /// the reader's byte floor.
    pub(crate) fn capture_entries(
        vault: &Vault,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        entries: &BTreeMap<String, (String, u32)>,
        documents: &BTreeMap<String, (CodeDocumentFrontier, u32)>,
        known: &BTreeMap<String, CodeTreeBlob>,
        verified: &BTreeSet<String>,
    ) -> Result<std::result::Result<Self, String>> {
        let mut wanted: Vec<(&str, GitOid)> = Vec::new();
        for (path, (oid, mode)) in entries {
            if path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".." | ".git"))
            {
                return Err(Error::InvariantViolation("unsafe code tree path"));
            }
            if !matches!(*mode, 0o100_644 | 0o100_755 | 0o120_000 | MODE_GITLINK) {
                return Err(Error::InvariantViolation("unsupported code tree mode"));
            }
            let read = *mode != MODE_GITLINK
                && if documents.contains_key(path) {
                    !verified.contains(path)
                } else {
                    !known.contains_key(oid)
                };
            if read {
                wanted.push((path.as_str(), GitOid::parse_hex(oid.clone())?));
            }
        }
        let mut measured: BTreeMap<&str, ([u8; 32], u64)> = BTreeMap::new();
        let mut differs: Option<&str> = None;
        let oids: Vec<GitOid> = wanted.iter().map(|(_, oid)| oid.clone()).collect();
        git.read_objects_in_order(repo, &oids, "blob", &mut |index, content| {
            if content.len() > MAX_TREE_FILE_BYTES {
                return Err(Error::IndexOverflow("origin file bytes"));
            }
            let path = wanted[index].0;
            match documents.get(path) {
                Some((frontier, _)) => {
                    if vault.code_document_at(frontier)?.as_bytes() != content {
                        differs = Some(path);
                        return Ok(false);
                    }
                }
                None => {
                    let hash = *blake3::hash(content).as_bytes();
                    measured.insert(path, (hash, content.len() as u64));
                }
            }
            Ok(true)
        })?;
        if let Some(path) = differs {
            return Ok(Err(format!(
                "{path}: the reviewed document is not the checked tree's bytes and mode"
            )));
        }
        let mut inventory = Self::default();
        for (path, (oid, mode)) in entries {
            if let Some((frontier, document_mode)) = documents.get(path) {
                if frontier.path != *path || *document_mode != *mode {
                    return Ok(Err(format!(
                        "{path}: the reviewed document is not the checked tree's bytes and mode"
                    )));
                }
                inventory.modes.insert(frontier.document_id, *mode);
                if inventory
                    .documents
                    .insert(frontier.document_id, frontier.clone())
                    .is_some()
                {
                    return Ok(Err(format!("{path}: one document names two paths")));
                }
                continue;
            }
            let (content_hash, size_bytes) = if *mode == MODE_GITLINK {
                (*blake3::hash(oid.as_bytes()).as_bytes(), oid.len() as u64)
            } else if let Some(read) = measured.get(path.as_str()) {
                *read
            } else {
                let blob = known
                    .get(oid)
                    .ok_or_else(|| invalid("the tested tree reads disagree"))?;
                (blob.content_hash, blob.size_bytes)
            };
            inventory.blobs.insert(
                path.clone(),
                CodeTreeBlob {
                    git_oid: oid.clone(),
                    content_hash,
                    size_bytes,
                    mode: *mode,
                },
            );
        }
        if let Some(path) = documents.keys().find(|path| !entries.contains_key(*path)) {
            return Ok(Err(format!(
                "{path}: a reviewed document is not in the checked tree"
            )));
        }
        Ok(Ok(inventory))
    }

    /// The file paths `tree` holds otherwise than `parent` (added, changed
    /// or retyped), and the file paths only `parent` holds, read one tree
    /// level at a time and descending only into trees that differ (FIX
    /// 7349): an unchanged subtree is never read.
    ///
    /// # Errors
    /// A missing object or a path that is not UTF-8.
    pub(crate) fn changed_against(
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        tree: &GitOid,
        parent: &GitOid,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
        let mut count = start_tree_count(git, repo)?;
        let (mut changed, mut gone) = (BTreeSet::new(), BTreeSet::new());
        let mut pending = vec![(String::new(), Some(tree.clone()), Some(parent.clone()))];
        let level = |oid: Option<GitOid>| -> Result<Vec<crate::git_wire::GitTreeEntry>> {
            Ok(match oid {
                Some(oid) => git.read_tree(repo, &oid)?,
                None => Vec::new(),
            })
        };
        let joined = |prefix: &str, name: Vec<u8>| -> Result<String> {
            let name =
                String::from_utf8(name).map_err(|_| invalid("tested tree paths must be UTF-8"))?;
            Ok(if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            })
        };
        while let Some((prefix, new, old)) = pending.pop() {
            let mut before: BTreeMap<Vec<u8>, crate::git_wire::GitTreeEntry> = level(old)?
                .into_iter()
                .map(|entry| (entry.name.clone(), entry))
                .collect();
            for entry in level(new)? {
                count.row();
                let prior = before.remove(&entry.name);
                if prior
                    .as_ref()
                    .is_some_and(|prior| prior.oid == entry.oid && prior.mode == entry.mode)
                {
                    continue;
                }
                let path = joined(&prefix, entry.name)?;
                let prior_tree = prior
                    .as_ref()
                    .filter(|prior| prior.mode == MODE_TREE)
                    .map(|prior| prior.oid.clone());
                if entry.mode == MODE_TREE {
                    if prior.is_some() && prior_tree.is_none() {
                        gone.insert(path.clone());
                    }
                    pending.push((path, Some(entry.oid), prior_tree));
                } else {
                    if prior_tree.is_some() {
                        pending.push((path.clone(), None, prior_tree));
                    }
                    changed.insert(path);
                }
            }
            for (name, prior) in before {
                count.row();
                let path = joined(&prefix, name)?;
                if prior.mode == MODE_TREE {
                    pending.push((path, None, Some(prior.oid)));
                } else {
                    gone.insert(path);
                }
            }
        }
        count.finish(git.vault());
        Ok((changed, gone))
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
