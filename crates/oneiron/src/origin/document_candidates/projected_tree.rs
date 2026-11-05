//! Core half of `origin::document_candidates::projected_tree`: its store-layer items live in `oneiron_store::origin::document_candidates::projected_tree` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::origin::document_candidates::projected_tree::*;

use super::super::tree::OriginTreeFile;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitTreeEntry, GitWire, GitWirePlan, GitWireRepo};
use crate::store::code_document_values::CodeFilePresence;
use crate::store::code_tree_blob::CodeTreeBlob;
use std::collections::BTreeMap;

pub(super) fn commit_tree(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    commit: &GitOid,
) -> Result<GitOid> {
    wire.commit_trees(repo, std::slice::from_ref(commit))?
        .remove(commit)
        .ok_or(Error::EntityNotFound)
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
