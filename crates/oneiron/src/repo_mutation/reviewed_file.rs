//! The tested stack's per-member checks (moved from `reviewed_stack.rs`,
//! G4 PR2): the tested change is exactly its immutable reviewed operation,
//! its receipt binds it, and its document base has not moved.
use super::proposal::{RepoProposal, invalid};
use super::snapshot::{StoredRepoSnapshot, StoredRepoSnapshotEntry, StoredRepoSnapshotEntryKind};
use super::types::{RepoForkHash, RepoMutationOplogEntry};
use crate::{
    Vault,
    codebase::RepoRef,
    error::{Error, Result},
};

pub(super) fn require_candidate(
    row: &RepoProposal,
    candidate: &crate::merge_queue::MergeProposal,
    pre_snapshot: RepoForkHash,
    repo: &RepoRef,
    snapshot: &StoredRepoSnapshot,
) -> Result<()> {
    let canonical = super::oplog::repo_mutation_repo_key_hash;
    if canonical(&RepoRef::parse(&row.repo)?) != canonical(repo)
        || row.pre_action_fork_hash != pre_snapshot
        || row.id.to_hex() != candidate.id
    {
        return Err(invalid(
            "tested change is not exactly one reviewed proposal",
        ));
    }
    if row.is_file_bundle() {
        return require_bundle_candidate(row, candidate, snapshot);
    }
    let (path, content) = row.ordinary_file()?;
    if candidate.files.len() != 1 || candidate.files[0].metadata_edit.is_some() {
        return Err(invalid(
            "tested change is not exactly one reviewed proposal",
        ));
    }
    let file = &candidate.files[0];
    let old = snapshot.entries.iter().find(|entry| entry.path == path);
    if old.is_some_and(|entry| entry.kind != StoredRepoSnapshotEntryKind::File) {
        return Err(invalid("reviewed stack requires regular files"));
    }
    let expected = old.map(|entry| entry.content.as_slice());
    if file.path != path
        || file.content.as_deref() != Some(content)
        || file.expected.as_deref() != expected
    {
        return Err(invalid(
            "tested bytes differ from immutable reviewed operation",
        ));
    }
    std::str::from_utf8(expected.unwrap_or(b""))
        .map_err(|_| invalid("reviewed code requires UTF-8"))?;
    std::str::from_utf8(content).map_err(|_| invalid("reviewed code requires UTF-8"))?;
    Ok(())
}

/// Whether the snapshot `entry` is exactly `state`: absent, or a kept
/// regular file, executable file or symlink at that Git mode.
pub(super) fn snapshot_state_is(
    entry: Option<&StoredRepoSnapshotEntry>,
    state: &crate::code_document::CodeFilePresence,
) -> bool {
    let mode = match entry {
        None => None,
        Some(entry) => match entry.kind {
            StoredRepoSnapshotEntryKind::File if entry.executable => Some(0o100_755),
            StoredRepoSnapshotEntryKind::File => Some(0o100_644),
            StoredRepoSnapshotEntryKind::Symlink => Some(0o120_000),
            StoredRepoSnapshotEntryKind::Withheld => return false,
        },
    };
    state.present == mode.is_some() && state.mode == mode
}

/// The bytes a snapshot `entry` holds: a file's content, a symlink's
/// target text, nothing when absent.
fn snapshot_bytes(entry: Option<&StoredRepoSnapshotEntry>) -> Option<Vec<u8>> {
    entry.map(|entry| match entry.kind {
        StoredRepoSnapshotEntryKind::Symlink => entry
            .symlink_target
            .clone()
            .unwrap_or_default()
            .into_bytes(),
        _ => entry.content.clone(),
    })
}

/// A file bundle's tested change is its whole reviewed file set, in
/// order: each path's reviewed bytes and state change, and the bytes and
/// state the stack's snapshot holds there as the expected base. No file of
/// it is a single-file surrogate.
fn require_bundle_candidate(
    row: &RepoProposal,
    candidate: &crate::merge_queue::MergeProposal,
    snapshot: &StoredRepoSnapshot,
) -> Result<()> {
    if candidate.files.len() != row.files.len() || row.files.is_empty() {
        return Err(invalid("tested change is not the bundle's file set"));
    }
    for (tested, reviewed) in candidate.files.iter().zip(&row.files) {
        let state = reviewed
            .metadata_edit
            .as_ref()
            .ok_or(invalid("a bundle file carries its reviewed state change"))?;
        let entry = snapshot
            .entries
            .iter()
            .find(|entry| entry.path == reviewed.path);
        if tested.path != reviewed.path
            || tested.content != reviewed.content
            || tested.metadata_edit.as_ref() != Some(state)
            || !snapshot_state_is(entry, &state.expected)
            || tested.expected != snapshot_bytes(entry)
        {
            return Err(invalid(
                "tested bytes differ from immutable reviewed operation",
            ));
        }
    }
    Ok(())
}

pub(super) fn require_receipt(
    row: &RepoProposal,
    entry: &RepoMutationOplogEntry,
    expected: RepoForkHash,
) -> Result<()> {
    let request = row.request()?;
    if entry.pre_action_fork_hash != expected
        || entry.repo_ref != request.repo_ref
        || entry.operation_kind != request.operation.kind()
        || entry.operation_subject.as_deref() != Some(row.operation_subject().as_str())
        || entry.actor_id != row.actor.id()
        || entry.session_id != Some(row.session)
    {
        return Err(invalid("reviewed stack receipt binding differs"));
    }
    Ok(())
}

// Read-only preflight catches an already-stale later document before any member
// lands. The normal document door still rechecks at execution, then replays by ID.
pub(super) fn require_document_base(
    vault: &Vault,
    row: &RepoProposal,
    snapshot: &StoredRepoSnapshot,
) -> Result<()> {
    let repo = RepoRef::parse(&row.repo)?;
    let scope = super::oplog::repo_mutation_repo_key(&repo);
    if row.is_file_bundle() {
        return require_bundle_document_bases(vault, row, snapshot, &scope);
    }
    let (path, content) = row.ordinary_file()?;
    let old = snapshot
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .map_or(b"".as_slice(), |entry| entry.content.as_slice());
    let old = std::str::from_utf8(old).map_err(|_| invalid("reviewed code requires UTF-8"))?;
    let new = std::str::from_utf8(content).map_err(|_| invalid("reviewed code requires UTF-8"))?;
    if old == new {
        return Ok(());
    }
    let session = vault.open_code_document(&scope, path, old, row.session)?;
    let class = row.document_class()?;
    match vault.code_file_edit_receipt(row.id)? {
        None if session.text() != old => Err(Error::ConcurrentWrite(
            "document changed since stack review",
        )),
        Some(receipt)
            if receipt.document_id != session.document_id()
                || receipt.session_id != row.session
                || receipt.actor
                    != row
                        .actor
                        .id()
                        .map(|actor| crate::write_envelope::WriteActor::new(actor, class))
                || receipt.provenance != row.op_provenance
                || receipt.edit != crate::code_document::CodeFileEdit::between(path, old, new) =>
        {
            Err(invalid("stack document receipt identity differs"))
        }
        _ => Ok(()),
    }
}

/// A file bundle's read-only preflight: each file's document, when one
/// lives at its path and no receipt of its operation landed yet, still
/// holds the text the stack's snapshot holds there. The grouped ingress
/// rechecks every file at execution.
fn require_bundle_document_bases(
    vault: &Vault,
    row: &RepoProposal,
    snapshot: &StoredRepoSnapshot,
    scope: &str,
) -> Result<()> {
    for (index, file) in row.files.iter().enumerate() {
        let operation = row.file_operation(index)?;
        if vault.code_file_edit_receipt(operation)?.is_some()
            || vault.code_document_frontier(scope, &file.path)?.is_none()
        {
            continue;
        }
        let entry = snapshot
            .entries
            .iter()
            .find(|entry| entry.path == file.path);
        let old = snapshot_bytes(entry).unwrap_or_default();
        let old = std::str::from_utf8(&old).map_err(|_| invalid("reviewed code requires UTF-8"))?;
        let session = vault.open_code_document(scope, &file.path, old, row.session)?;
        if session.text() != old {
            return Err(Error::ConcurrentWrite(
                "document changed since stack review",
            ));
        }
    }
    Ok(())
}
