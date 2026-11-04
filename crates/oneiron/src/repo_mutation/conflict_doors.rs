//! Owner-bound admission of real overlaps, retaining both proposed changes.
use super::bundle::tree::{bundle_tree_edits, prepare_bundle_files_commit};
use super::git::{
    admitted_repo_ref, git_common_dir, require_pinned_head, resolve_mutable_repo_root,
};
use super::proposal::{RepoProposalOperation, RepoProposalStatus, invalid};
use super::snapshot::capture_repo_snapshot;
use super::worktree::{prepare_commit_file_through_queue_worktree, remove_queue_worktree};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::git_wire::{GitOid, GitWire, GitWireRepo, lock_repository};
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
        // The base and each side are pinned before its worktree goes, so the
        // recorded conflict's commits stay inspectable, as the queue's are
        // (FIX 8834).
        let wire = GitWire::new(self)?;
        let pinned_repo = wire.open_repo(canonical.clone(), &root)?;
        let base_head = snapshot
            .head
            .clone()
            .ok_or_else(|| invalid("conflict base has no HEAD commit"))?;
        let _pinned = wire.write_keep_ref(&pinned_repo, &GitOid::parse_hex(base_head)?, 0)?;
        let mut sides = Vec::new();
        for row in &proposals {
            let message = super::trailer::commit_message_with_provenance_trailer(
                &row.message,
                Some(row.provenance_claim),
            )?;
            let (path, content) = row.ordinary_file()?;
            let prepared =
                prepare_commit_file_through_queue_worktree(&root, path, content, &message)?;
            let pinned = GitOid::parse_hex(prepared.new_head.clone())
                .and_then(|side| wire.write_keep_ref(&pinned_repo, &side, 0));
            let removed = remove_queue_worktree(&root, &prepared.worktree_path);
            let _pinned = pinned?;
            removed?;
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

    /// The merge queue's retained-base overlap handoff (FIX 6868, G2 PR2):
    /// both accepted sources are built on an isolated detached worktree of
    /// their common green commit, never on live HEAD, after the retained
    /// snapshot is proven to be that commit's. The base and both sides are
    /// pinned before the scratch tree goes, so they stay inspectable. The
    /// claim, its TASK or held disposition and every batch link commit in
    /// one writer. No bytes are merged and the owner's door is untouched.
    pub(crate) fn record_queue_proposal_conflict(
        &self,
        repo: &GitWireRepo,
        overlap: &crate::merge_queue::QueueStageOverlap,
        admission: &crate::federation::QueueReconciliationAdmission,
    ) -> Result<crate::merge_queue::QueueConflictLink> {
        if overlap.sources.len() != 2 || overlap.sources[0] == overlap.sources[1] {
            return Err(invalid("a queue conflict needs two distinct proposals"));
        }
        let rows = overlap
            .sources
            .iter()
            .map(|id| self.repo_proposal(*id)?.ok_or(crate::Error::EntityNotFound))
            .collect::<Result<Vec<_>>>()?;
        for row in &rows {
            // A whole-file proposal writes a shared path; a source-bound
            // received bundle writes one among its files (FIX 9976).
            let shares = match row.operation {
                RepoProposalOperation::CommitFile => row
                    .ordinary_file()
                    .is_ok_and(|(path, _)| overlap.paths.iter().any(|shared| shared == path)),
                RepoProposalOperation::ReceivedFiles { .. } => {
                    row.is_source_bound_received()
                        && row
                            .paths()
                            .iter()
                            .any(|path| overlap.paths.iter().any(|shared| shared == path))
                }
                _ => false,
            };
            if !super::oplog::same_repository(repo.repo_ref(), &RepoRef::parse(&row.repo)?)
                || row.pre_action_fork_hash != overlap.snapshot
                || !shares
            {
                return Err(invalid(
                    "queue conflict source is not a same-base proposal of the overlap",
                ));
            }
        }
        let _guard = lock_repository(repo.common_dir())?;
        let wire = GitWire::new(self)?;
        let base = GitOid::parse_hex(overlap.base_green.clone())?;
        if self.capture_repo_snapshot_at_commit(repo, &base)?.fork_hash != overlap.snapshot {
            return Err(crate::Error::ConcurrentWrite(
                "the retained snapshot is not the overlap's green commit",
            ));
        }
        let identity = rmp_serde::to_vec(&overlap.sources)
            .map_err(|_| invalid("queue conflict identity encoding failed"))?;
        let scratch = std::env::temp_dir().join(format!(
            "oneiron-queue-conflict-{}-{}",
            repo.identity().as_hex(),
            blake3::hash(&identity).to_hex()
        ));
        if wire.worktree_registered(repo, &scratch)? {
            wire.remove_worktree(repo, &scratch, 0)?;
        }
        if scratch.symlink_metadata().is_ok() {
            return Err(invalid("the queue conflict scratch path is occupied"));
        }
        wire.add_worktree(repo, &scratch, &base, 0)?;
        let sides = queue_conflict_sides(&scratch, &rows);
        let removed = wire.remove_worktree(repo, &scratch, 0);
        let sides = sides?;
        removed?;
        for oid in std::iter::once(&base).chain(&sides) {
            let _pinned = wire.write_keep_ref(repo, oid, 0)?;
        }
        let tree =
            |commit: &GitOid| super::conflict::tree_hash_for_ref(repo.repo_root(), commit.as_str());
        let trees = super::conflict::QueueConflictTrees {
            base: tree(&base)?,
            ours: tree(&sides[0])?,
            theirs: tree(&sides[1])?,
        };
        let recorded = super::conflict::record_queue_conflict_claim(
            self,
            repo.repo_ref(),
            overlap,
            admission,
            trees,
            &rows,
            |txn, link| {
                crate::merge_queue::MergeQueue::of_repo(self, repo.clone())
                    .attach_queue_conflict_in_txn(txn, link)
            },
        );
        // A refused claim keeps none of the side commits it made: the next
        // try makes its own, so a retried handoff never grows the pins (FIX
        // 7305). The shared base stays pinned.
        if recorded.is_err() {
            for side in &sides {
                let _released = wire.delete_keep_ref(repo, side, 0);
            }
        }
        recorded
    }
}

/// Each source's commit on the historical base `root`, in source order: a
/// whole-file proposal's one file with its provenance trailer, or a received
/// bundle's whole tree change under its own message, as it would land.
fn queue_conflict_sides(
    root: &std::path::Path,
    rows: &[super::proposal::RepoProposal],
) -> Result<Vec<GitOid>> {
    let mut sides = Vec::new();
    for row in rows {
        let prepared = if row.is_source_bound_received() {
            let edits = bundle_tree_edits(&row.files)?;
            prepare_bundle_files_commit(root, &edits, &row.message)?
        } else {
            let message = super::trailer::commit_message_with_provenance_trailer(
                &row.message,
                Some(row.provenance_claim),
            )?;
            let (path, content) = row.ordinary_file()?;
            prepare_commit_file_through_queue_worktree(root, path, content, &message)?
        };
        remove_queue_worktree(root, &prepared.worktree_path)?;
        sides.push(GitOid::parse_hex(prepared.new_head)?);
    }
    Ok(sides)
}

/// The immutable source proposals a typed conflict retains, including after resolution.
pub(crate) fn conflict_proposals(body: &crate::claim::ClaimBody) -> Result<Vec<EntityId>> {
    if body.predicate != crate::claim::PREDICATE_CONFLICT_OPEN {
        return Err(invalid("not a repository conflict claim"));
    }
    Ok(super::conflict_value::decode_repo_conflict_open_value(&body.value)?.proposals)
}
