//! Owner-bound admission of real overlaps, retaining both proposed changes.
use super::git::{
    admitted_repo_ref, git_common_dir, require_pinned_head, resolve_mutable_repo_root,
};
use super::proposal::{RepoProposalOperation, RepoProposalStatus, invalid};
use super::snapshot::capture_repo_snapshot;
use super::worktree::{prepare_commit_file_through_queue_worktree, remove_queue_worktree};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::git_wire::lock_repository;
use crate::{EntityId, Result, Vault};

impl Vault {
    /// The existing queue staging primitive builds each candidate off the
    /// shared retained base. Only detached worktrees change; no live ref moves.
    pub(crate) fn record_repo_proposal_conflict_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        repository: EntityId,
        repo: &RepoRef,
        subject: EntityId,
        branch: &str,
        sources: [EntityId; 2],
    ) -> Result<EntityId> {
        owner.revalidate(self)?;
        if sources[0] == sources[1] {
            return Err(invalid("conflict needs two distinct proposals"));
        }
        let root = resolve_mutable_repo_root(repo)?;
        let canonical = admitted_repo_ref(repo, &root)?;
        let _guard = lock_repository(&git_common_dir(&root)?)?;
        let proposals = sources
            .iter()
            .map(|id| self.repo_proposal(*id)?.ok_or(crate::Error::EntityNotFound))
            .collect::<Result<Vec<_>>>()?;
        let (base, snapshot) = capture_repo_snapshot(self, &root)?;
        let snapshot = super::snapshot::decode_snapshot(&snapshot)?;
        require_pinned_head(repo, snapshot.head.as_deref())?;
        for row in &proposals {
            if !super::oplog::same_repository(&canonical, &RepoRef::parse(&row.repo)?)
                || row.pre_action_fork_hash != base
                || !matches!(row.operation, RepoProposalOperation::CommitFile)
                || !matches!(
                    row.status,
                    RepoProposalStatus::Proposed | RepoProposalStatus::Approved
                )
            {
                return Err(invalid(
                    "conflict source is not an open proposal at this retained base",
                ));
            }
        }
        let mut sides = Vec::new();
        for row in &proposals {
            let message = super::trailer::commit_message_with_provenance_trailer(
                &row.message,
                Some(row.provenance_claim),
            )?;
            let prepared = prepare_commit_file_through_queue_worktree(
                &root,
                &row.path,
                &row.content,
                &message,
            )?;
            remove_queue_worktree(&root, &prepared.worktree_path)?;
            sides.push(prepared.new_head);
        }
        super::conflict::record_repo_conflict_checked(
            self,
            repo,
            &root,
            subject,
            branch,
            &sides[0],
            &sides[1],
            Some((owner, repository)),
            &proposals,
        )
    }
}

/// The immutable source proposals a typed conflict retains, including after resolution.
pub(crate) fn conflict_proposals(body: &crate::claim::ClaimBody) -> Result<Vec<EntityId>> {
    if body.predicate != crate::claim::PREDICATE_CONFLICT_OPEN {
        return Err(invalid("not a repository conflict claim"));
    }
    Ok(super::conflict_value::decode_repo_conflict_open_value(&body.value)?.proposals)
}
