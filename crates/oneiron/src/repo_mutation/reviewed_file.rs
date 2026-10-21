//! The tested stack's per-member checks (moved from `reviewed_stack.rs`,
//! G4 PR2): the tested change is exactly its immutable reviewed operation,
//! its receipt binds it, and its document base has not moved.
use super::proposal::{RepoProposal, invalid};
use super::snapshot::{StoredRepoSnapshot, StoredRepoSnapshotEntryKind};
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
        || candidate.files.len() != 1
    {
        return Err(invalid(
            "tested change is not exactly one reviewed proposal",
        ));
    }
    let file = &candidate.files[0];
    let old = snapshot.entries.iter().find(|entry| entry.path == row.path);
    if old.is_some_and(|entry| entry.kind != StoredRepoSnapshotEntryKind::File) {
        return Err(invalid("reviewed stack requires regular files"));
    }
    let expected = old.map(|entry| entry.content.as_slice());
    if file.path != row.path
        || file.content.as_deref() != Some(row.content.as_slice())
        || file.expected.as_deref() != expected
    {
        return Err(invalid(
            "tested bytes differ from immutable reviewed operation",
        ));
    }
    std::str::from_utf8(expected.unwrap_or(b""))
        .map_err(|_| invalid("reviewed code requires UTF-8"))?;
    std::str::from_utf8(&row.content).map_err(|_| invalid("reviewed code requires UTF-8"))?;
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
        || entry.operation_subject.as_deref() != Some(row.path.as_str())
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
    let old = snapshot
        .entries
        .iter()
        .find(|entry| entry.path == row.path)
        .map_or(b"".as_slice(), |entry| entry.content.as_slice());
    let old = std::str::from_utf8(old).map_err(|_| invalid("reviewed code requires UTF-8"))?;
    let new =
        std::str::from_utf8(&row.content).map_err(|_| invalid("reviewed code requires UTF-8"))?;
    if old == new {
        return Ok(());
    }
    let repo = RepoRef::parse(&row.repo)?;
    let scope = super::oplog::repo_mutation_repo_key(&repo);
    let session = vault.open_code_document(&scope, &row.path, old, row.session)?;
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
                || receipt.edit
                    != crate::code_document::CodeFileEdit::between(&row.path, old, new) =>
        {
            Err(invalid("stack document receipt identity differs"))
        }
        _ => Ok(()),
    }
}
