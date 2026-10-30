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

/// Git's mode of a submodule link. Kept visible, never exported.
pub(crate) const MODE_GITLINK: u32 = 0o160_000;
const MODE_TREE: u32 = 0o040_000;

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
    /// file past the reader's byte floors.
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
    pub(crate) fn entries(
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
    pub(crate) fn capture(
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
