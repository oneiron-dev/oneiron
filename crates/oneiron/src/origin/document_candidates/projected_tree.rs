//! A projected candidate's canonical files and target tree (FIX 7608
//! slice 2b-ii-B2): the trees and bytes it reads, and the blobs and trees
//! its translation writes into the canonical store, from the ORIGINAL base
//! tree, each edited path set to its blob and mode or removed.

use std::collections::BTreeMap;

use super::super::tree::OriginTreeFile;
use crate::code_document::CodeFilePresence;
use crate::code_revision::CodeTreeBlob;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitTreeEntry, GitWire, GitWirePlan, GitWireRepo};

/// A tree's Git mode.
const MODE_TREE: u32 = 0o040_000;

pub(super) fn commit_tree(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    commit: &GitOid,
) -> Result<GitOid> {
    wire.commit_trees(repo, std::slice::from_ref(commit))?
        .remove(commit)
        .ok_or(Error::EntityNotFound)
}

pub(super) fn presence(blob: Option<&CodeTreeBlob>) -> CodeFilePresence {
    blob.map_or_else(CodeFilePresence::absent, |blob| {
        CodeFilePresence::file(blob.mode)
    })
}

pub(super) fn tree_blob(
    entries: &BTreeMap<String, (String, u32)>,
    files: &BTreeMap<String, OriginTreeFile>,
    path: &str,
) -> Option<CodeTreeBlob> {
    let (oid, mode) = entries.get(path)?;
    let content = files
        .get(path)
        .map_or(&[][..], |file| file.content.as_slice());
    Some(CodeTreeBlob {
        git_oid: oid.clone(),
        content_hash: *blake3::hash(content).as_bytes(),
        size_bytes: content.len() as u64,
        mode: *mode,
    })
}

/// One side of a changed file: its blob and its bytes, when present.
pub(super) fn file_input<'f>(
    entries: &BTreeMap<String, (String, u32)>,
    files: &'f BTreeMap<String, OriginTreeFile>,
    path: &str,
) -> Result<Option<(GitOid, &'f [u8])>> {
    let Some((oid, _)) = entries.get(path) else {
        return Ok(None);
    };
    let bytes = files
        .get(path)
        .map_or(&[][..], |file| file.content.as_slice());
    Ok(Some((GitOid::parse_hex(oid.clone())?, bytes)))
}

pub(super) fn write_blob(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    bytes: &[u8],
    now: u64,
) -> Result<GitOid> {
    let mut plan = GitWirePlan::new();
    plan.write_blob(bytes.to_vec())?;
    wire.write_objects(repo, &plan, now)?
        .into_iter()
        .next()
        .ok_or(Error::InvariantViolation("a written blob has its id"))
}

/// The tree `tree` (none: an empty one) with `edits` applied, written
/// into `repo`: each edited path set to its blob and mode, or removed.
/// `None` for an emptied subtree; the root is always written.
pub(super) fn rebuild_tree(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    tree: Option<&GitOid>,
    edits: &BTreeMap<String, Option<(GitOid, u32)>>,
    now: u64,
    root: bool,
) -> Result<Option<GitOid>> {
    let mut entries: BTreeMap<Vec<u8>, GitTreeEntry> = match tree {
        Some(tree) => wire
            .read_tree(repo, tree)?
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect(),
        None => BTreeMap::new(),
    };
    let mut nested: BTreeMap<String, BTreeMap<String, Option<(GitOid, u32)>>> = BTreeMap::new();
    for (path, edit) in edits {
        match path.split_once('/') {
            None => match edit {
                None => {
                    entries.remove(path.as_bytes());
                }
                Some((oid, mode)) => {
                    entries.insert(
                        path.as_bytes().to_vec(),
                        GitTreeEntry {
                            mode: *mode,
                            name: path.as_bytes().to_vec(),
                            oid: oid.clone(),
                        },
                    );
                }
            },
            Some((dir, rest)) => {
                nested
                    .entry(dir.to_owned())
                    .or_default()
                    .insert(rest.to_owned(), edit.clone());
            }
        }
    }
    for (dir, sub) in nested {
        let existing = entries
            .get(dir.as_bytes())
            .filter(|entry| entry.mode == MODE_TREE)
            .map(|entry| entry.oid.clone());
        match rebuild_tree(wire, repo, existing.as_ref(), &sub, now, false)? {
            Some(oid) => {
                entries.insert(
                    dir.as_bytes().to_vec(),
                    GitTreeEntry {
                        mode: MODE_TREE,
                        name: dir.into_bytes(),
                        oid,
                    },
                );
            }
            None => {
                entries.remove(dir.as_bytes());
            }
        }
    }
    if entries.is_empty() && !root {
        return Ok(None);
    }
    let mut plan = GitWirePlan::new();
    plan.write_tree(entries.into_values().collect())?;
    Ok(wire.write_objects(repo, &plan, now)?.into_iter().next())
}
