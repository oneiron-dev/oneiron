//! A candidate's file set (G4 PR2): every changed path of one accepted push
//! against its exact base, with its old and incoming entries and its
//! reviewed state change. No rename is inferred.
use std::collections::{BTreeMap, BTreeSet};

use super::super::ReceivedFileOperation;
use super::super::document_candidate_types::{
    CodePushCandidateHold, CodePushCandidateState, ReceivedRefIngress, ResolvedCandidateFile,
};
use super::super::tree::{OriginTreeFile, read_tree_files};
use super::{Held, MODE_GITLINK};
use crate::EntityId;
use crate::code_document::{CodeFileMetadataEdit, CodeFilePresence};
use crate::code_revision::{CodeRevision, CodeTreeBlob, CodeTreeInventory};
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::repo_mutation::received_file_operation;

fn presence(blob: Option<&CodeTreeBlob>) -> CodeFilePresence {
    blob.map_or_else(CodeFilePresence::absent, |blob| {
        CodeFilePresence::file(blob.mode)
    })
}

fn tree_blob(
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

/// Prepares every changed file of the push `row` against its base: each
/// source operation must be exactly the old and new trees' change at its
/// path; its exact old and incoming entries, its base document, its
/// reviewed state change (CALL M: absent and empty differ, every present
/// state names its Git mode) and its document operation. A submodule link
/// or bytes that are not UTF-8 hold; no rename is inferred.
pub(super) fn prepare_push_candidate_documents(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    base: &CodeRevision,
    row: &ReceivedRefIngress,
    old: &GitOid,
    new_tree: &GitOid,
    proposal: EntityId,
) -> Result<Held<Vec<(ResolvedCandidateFile, Option<Vec<u8>>)>>> {
    let held = |reason: &str| {
        Ok(Err(CodePushCandidateHold {
            state: CodePushCandidateState::HeldShape,
            reason: reason.to_owned(),
        }))
    };
    let old_tree = wire
        .commit_trees(repo, std::slice::from_ref(old))?
        .remove(old)
        .ok_or(Error::EntityNotFound)?;
    let old_entries = CodeTreeInventory::entries(wire, repo, &old_tree)?;
    let new_entries = CodeTreeInventory::entries(wire, repo, new_tree)?;
    let old_files = read_tree_files(wire, repo, &old_tree)?;
    let new_files = read_tree_files(wire, repo, new_tree)?;
    let changed: BTreeSet<&str> = old_entries
        .keys()
        .chain(new_entries.keys())
        .map(String::as_str)
        .filter(|path| old_entries.get(*path) != new_entries.get(*path))
        .collect();
    let named: BTreeSet<&str> = row
        .operations
        .iter()
        .map(|operation| operation.path.as_str())
        .collect();
    if changed != named || named.len() != row.operations.len() {
        return held("source_operation_mismatch");
    }
    let mut operations: Vec<_> = row.operations.iter().collect();
    operations.sort_by(|left, right| left.path.cmp(&right.path));
    let mut files = Vec::with_capacity(operations.len());
    for operation in operations {
        let path = operation.path.as_str();
        let before = tree_blob(&old_entries, &old_files, path);
        let after = tree_blob(&new_entries, &new_files, path);
        if !validate_received_operation(operation, before.as_ref(), after.as_ref()) {
            return held("source_operation_mismatch");
        }
        if before
            .iter()
            .chain(after.iter())
            .any(|blob| blob.mode == MODE_GITLINK)
        {
            return held("submodule_entry");
        }
        let before_bytes = old_files.get(path).map(|file| file.content.clone());
        let after_bytes = new_files.get(path).map(|file| file.content.clone());
        if before_bytes
            .iter()
            .chain(after_bytes.iter())
            .any(|bytes| std::str::from_utf8(bytes).is_err())
        {
            return held("binary_entry");
        }
        let metadata_edit = CodeFileMetadataEdit::between(
            path,
            presence(before.as_ref()),
            presence(after.as_ref()),
        );
        if metadata_edit.expected.validate().is_err()
            || metadata_edit.replacement.validate().is_err()
        {
            return held("unsupported_mode");
        }
        let base_frontier = base
            .file_frontiers
            .values()
            .find(|frontier| frontier.path == path)
            .cloned();
        let source_operation = EntityId::from_hex(&operation.operation_id)?;
        let document_operation = if after.is_some() || base_frontier.is_some() {
            Some(received_file_operation(proposal, source_operation)?)
        } else {
            None
        };
        files.push((
            ResolvedCandidateFile {
                source_operation,
                path: path.to_owned(),
                before,
                after,
                base_frontier,
                metadata_edit,
                document_operation,
            },
            after_bytes,
        ));
    }
    Ok(Ok(files))
}

/// Whether `operation` is exactly the change from `before` to `after`: its
/// modes and its before and after content hashes. Shared by the ordinary
/// candidate and a masked copy's, whose COPY trees it judges (FIX 7608).
pub(super) fn validate_received_operation(
    operation: &ReceivedFileOperation,
    before: Option<&CodeTreeBlob>,
    after: Option<&CodeTreeBlob>,
) -> bool {
    let empty = *blake3::hash(b"").as_bytes();
    before.map(|blob| blob.mode) == operation.old_mode
        && after.map(|blob| blob.mode) == operation.new_mode
        && before.map_or(empty, |blob| blob.content_hash) == operation.before_hash
        && after.map_or(empty, |blob| blob.content_hash) == operation.after_hash
}
