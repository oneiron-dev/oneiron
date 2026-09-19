//! Review-approved repository file updates lower to idempotent document edits.
use super::mount::RepoMountRef;
use crate::code_document::{CodeFileEdit, CodeFileIngress};
use crate::codebase::RepoRef;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

pub(super) fn land_reviewed_document(vault: &Vault, proposal_id: EntityId) -> Result<()> {
    let proposal = vault
        .repo_proposal(proposal_id)?
        .ok_or(Error::EntityNotFound)?;
    let repo = RepoRef::parse(&proposal.repo)?;
    let before = vault.mount_repo_ref(&repo, RepoMountRef::Fork(proposal.pre_action_fork_hash))?;
    let old = before.read_file(&proposal.path)?.unwrap_or(b"");
    let old = std::str::from_utf8(old)
        .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))?;
    let new = std::str::from_utf8(&proposal.content)
        .map_err(|_| Error::InvalidClaimBody("code document requires UTF-8"))?;
    if old == new {
        return Ok(());
    }
    let scope = super::oplog::repo_mutation_repo_key(&repo);
    let session = vault.open_code_document(&scope, &proposal.path, old, proposal.session)?;
    vault.apply_code_file_ingress_exact(&mut [CodeFileIngress {
        operation: proposal_id,
        session,
        edit: CodeFileEdit::between(&proposal.path, old, new),
        actor: WriteActor::new(proposal.actor, EdgeActorClass::Agent),
        expected_text: old.to_owned(),
    }])?;
    Ok(())
}

/// Finishes a standalone reviewed write interrupted after durable document ingress.
/// The caller already proved the repository is exactly the recorded pre-state.
/// Stack members retain their sealed merge-queue recovery path.
pub(super) fn resume_reviewed_document(
    vault: &Vault,
    repo: &RepoRef,
    root: &std::path::Path,
    stale: &super::types::RepoMutationOplogEntry,
    commit: Option<&super::oplog::StoredPreparedCommit>,
    resolution: Option<&super::oplog::StoredPreparedConflictResolution>,
) -> Result<Option<super::types::RepoMutationOutcome>> {
    use super::proposal::{RepoProposalStatus, invalid};
    use super::queue::{
        PreparedCommitFile, PreparedConflictResolution, PreparedRepoMutation,
        PreparedRepoMutationExecution, execute_repo_mutation, expected_post_action_fork_hash,
    };
    use super::types::{RepoMutationOutcome, RepoMutationStatus};
    let Some(row) = super::proposal::for_operation(vault, repo, stale.seq)? else {
        return Ok(None);
    };
    if row.merge_stack.is_some() || vault.code_file_edit_receipt(row.id)?.is_none() {
        return Ok(None);
    }
    let request = row.request()?;
    if row.status != RepoProposalStatus::Approved
        || !row.eligible()?
        || row.pre_action_fork_hash != stale.pre_action_fork_hash
        || Some(row.actor) != stale.actor_id
        || Some(row.session) != stale.session_id
        || stale.operation_subject.as_deref() != Some(row.path.as_str())
        || stale.operation_kind != request.operation.kind()
    {
        return Err(invalid("reviewed recovery authority differs"));
    }
    let commit = commit.ok_or(invalid("reviewed recovery staged commit missing"))?;
    if !super::git::git_commit_object_available(root, &commit.new_head, &commit.base_head)? {
        return Err(invalid("reviewed recovery staged commit unavailable"));
    }
    super::proposal::validate_conflict(vault, &row, root)?;
    super::trailer::validate_repo_provenance_request(vault, &request)?;
    let prepared = PreparedCommitFile {
        // Recovery uses pinned objects, never recreates a worktree or commit.
        worktree_path: std::path::PathBuf::new(),
        base_head: commit.base_head.clone(),
        new_head: commit.new_head.clone(),
    };
    let execution = match &row.operation {
        super::proposal::RepoProposalOperation::CommitFile => {
            if resolution.is_some() {
                return Err(invalid("unexpected reviewed conflict recovery"));
            }
            PreparedRepoMutationExecution::CommitFile(prepared)
        }
        super::proposal::RepoProposalOperation::ResolveConflictFile {
            branch_subject,
            open_conflict_claim_id,
            branch_name,
        } => {
            let recovery = resolution.ok_or(invalid("reviewed conflict recovery missing"))?;
            if recovery.branch_subject != *branch_subject.as_bytes()
                || recovery.open_conflict_claim_id != *open_conflict_claim_id.as_bytes()
                || recovery.branch_name != *branch_name
                || recovery.path != row.path
                || recovery.resolved_tree
                    != super::conflict::tree_hash_for_ref(root, &commit.new_head)?
            {
                return Err(invalid("reviewed conflict recovery differs"));
            }
            PreparedRepoMutationExecution::ResolveConflictFile {
                commit: prepared,
                recovery: PreparedConflictResolution {
                    resolution_claim_id: EntityId::from_bytes(recovery.resolution_claim_id)?,
                    branch_subject: *branch_subject,
                    open_conflict_claim_id: *open_conflict_claim_id,
                    branch_name: branch_name.clone(),
                    path: row.path.clone(),
                    resolved_tree: recovery.resolved_tree.clone(),
                },
            }
        }
    };
    let (hash, snapshot) = super::snapshot::capture_repo_snapshot(root)?;
    if hash != stale.pre_action_fork_hash
        || Some(expected_post_action_fork_hash(
            &request.operation,
            &super::snapshot::decode_snapshot(&snapshot)?,
            hash,
            &execution,
        )?) != stale.expected_post_action_fork_hash
    {
        return Err(invalid("reviewed recovery pre/post commitment differs"));
    }
    // Replay authenticates the exact actor/session/edit receipt without appending
    // another document operation. Every failure retains Prepared for safe retry.
    land_reviewed_document(vault, row.id)?;
    let repo_conflict_claim_id = execute_repo_mutation(vault, repo, root, &request, &execution)?;
    if Some(super::snapshot::capture_repo_snapshot(root)?.0) != stale.expected_post_action_fork_hash
    {
        return Err(Error::ConcurrentWrite("reviewed recovery result differs"));
    }
    let entry = vault.finish_repo_mutation(
        &PreparedRepoMutation {
            repo_key_hash: super::oplog::repo_mutation_repo_key_hash(repo),
            seq: stale.seq,
        },
        RepoMutationStatus::Applied,
        None,
        super::support::now_millis(),
    )?;
    Ok(Some(RepoMutationOutcome {
        entry,
        repo_conflict_claim_id,
    }))
}
