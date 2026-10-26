//! The repo mutation operations' validation, write class and oplog subject
//! (moved from `queue.rs`, G4 PR2).

use super::super::git::{
    validate_base_ref, validate_commit_message, validate_git_ref_label,
    validate_relative_repo_path, validate_worktree_path,
};
use super::super::support::hex_bytes;
use super::super::types::RepoMutationOperation;
use crate::error::Result;

pub(in crate::repo_mutation) fn validate_operation(
    operation: &RepoMutationOperation,
) -> Result<()> {
    match operation {
        RepoMutationOperation::CommitFile { path, message, .. } => {
            validate_relative_repo_path(path)?;
            validate_commit_message(message)
        }
        RepoMutationOperation::CreateWorktree {
            worktree_path,
            base_ref,
        } => {
            validate_worktree_path(worktree_path)?;
            validate_base_ref(base_ref)
        }
        RepoMutationOperation::RecordConflict {
            branch_name,
            ours_ref,
            theirs_ref,
            ..
        } => {
            validate_git_ref_label(branch_name)?;
            validate_base_ref(ours_ref)?;
            validate_base_ref(theirs_ref)
        }
        RepoMutationOperation::RemoveWorktree { worktree_path } => {
            validate_worktree_path(worktree_path)
        }
        RepoMutationOperation::RecoverSnapshot { .. } => Ok(()),
        RepoMutationOperation::ResolveConflictFile {
            branch_name,
            path,
            message,
            ..
        } => {
            validate_git_ref_label(branch_name)?;
            validate_relative_repo_path(path)?;
            validate_commit_message(message)
        }
        RepoMutationOperation::ReceivedFiles {
            source_operations,
            message,
            ..
        } => {
            // CALL R: a bundle carries at least one changed file.
            if source_operations.is_empty() {
                return Err(crate::Error::Code(
                    crate::error::CodeError::InvalidRepoMutationRecord(
                        "a received bundle carries at least one changed file",
                    ),
                ));
            }
            validate_commit_message(message)
        }
        RepoMutationOperation::CommitFiles { files, message } => {
            super::super::bundle::validate_bundle_files(files)?;
            validate_commit_message(message)
        }
    }
}

pub(super) fn writes_file(operation: &RepoMutationOperation) -> bool {
    matches!(
        operation,
        RepoMutationOperation::CommitFile { .. }
            | RepoMutationOperation::ResolveConflictFile { .. }
            | RepoMutationOperation::ReceivedFiles { .. }
            | RepoMutationOperation::CommitFiles { .. }
    )
}

pub(super) fn operation_subject(operation: &RepoMutationOperation) -> String {
    match operation {
        RepoMutationOperation::CommitFile { path, .. } => path.clone(),
        RepoMutationOperation::CreateWorktree { worktree_path, .. }
        | RepoMutationOperation::RemoveWorktree { worktree_path } => {
            worktree_path.to_string_lossy().into_owned()
        }
        RepoMutationOperation::RecordConflict {
            branch_name,
            ours_ref,
            theirs_ref,
            ..
        } => format!("{branch_name}:{ours_ref}..{theirs_ref}"),
        RepoMutationOperation::RecoverSnapshot { fork_hash } => hex_bytes(fork_hash),
        RepoMutationOperation::ResolveConflictFile { path, .. } => path.clone(),
        RepoMutationOperation::ReceivedFiles { candidate, .. } => candidate.to_hex(),
        RepoMutationOperation::CommitFiles { message, .. } => {
            super::super::bundle::bundle_operation_subject(message)
        }
    }
}
