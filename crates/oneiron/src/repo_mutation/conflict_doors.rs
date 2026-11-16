//! Owner-bound admission of real overlaps, retaining both proposed changes.
use super::bundle::tree::{bundle_tree_edits, prepare_bundle_files_commit};
use super::git::{admitted_repo_ref, git_common_dir, resolve_mutable_repo_root};
use super::proposal::{RepoProposal, RepoProposalOperation, RepoProposalStatus, invalid};
use super::worktree::{prepare_commit_file_through_queue_worktree, remove_queue_worktree};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::git_wire::{GitOid, GitWire, GitWireRepo, lock_repository};
use crate::{EntityId, Result, Vault};

impl Vault {
    /// The owner's manual overlap door: both stored proposals build on a
    /// detached scratch worktree of the canonical pointer's commit, never
    /// on the live checkout, and the recorded conflict retains that base
    /// with both sides. Only detached worktrees change; no live ref moves.
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
        let wire = GitWire::new(self)?;
        let pinned_repo = wire.open_repo(canonical.clone(), &root)?;
        // An owner proposal's base is the tree of the commit the stored
        // pointer names, not the live checkout (FIX 4367): both sources
        // must still be open proposals at that commit's snapshot.
        // `admitted_repo_ref` has refused a pointer without a 40-hex commit.
        let base = GitOid::parse_hex(canonical.commit_hash().unwrap_or_default())?;
        let base_snapshot = self.capture_repo_snapshot_at_commit(&pinned_repo, &base)?;
        for row in &proposals {
            if !super::oplog::same_repository(&canonical, &RepoRef::parse(&row.repo)?)
                || row.pre_action_fork_hash != base_snapshot.fork_hash
                || !row.conflict_side_buildable()
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
        let sides = self.build_conflict_sides_at(&pinned_repo, &base, &proposals)?;
        let [ours, theirs] = sides.as_slice() else {
            return Err(invalid("a recorded conflict keeps two built sides"));
        };
        let recorded = super::conflict::record_repo_conflict_checked(
            self,
            repo,
            &root,
            subject,
            branch,
            ours.as_str(),
            theirs.as_str(),
            Some((owner, repository)),
            &proposals,
        );
        // A refused claim keeps none of the side commits it made: the next
        // try makes its own, so a retried record never grows the pins (FIX
        // 7305). The shared base stays pinned.
        if recorded.is_err() {
            for side in &sides {
                let _released = wire.delete_keep_ref(&pinned_repo, side, 0);
            }
        }
        recorded
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
            // Any stored change whose side builds shares the overlap when
            // one of its paths is among the overlap's.
            let shares = row.conflict_side_buildable()
                && row
                    .paths()
                    .iter()
                    .any(|path| overlap.paths.iter().any(|shared| shared == path));
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
        let sides = self.build_conflict_sides_at(repo, &base, &rows)?;
        let [ours, theirs] = sides.as_slice() else {
            return Err(invalid("a recorded conflict keeps two built sides"));
        };
        let tree =
            |commit: &GitOid| super::conflict::tree_hash_for_ref(repo.repo_root(), commit.as_str());
        let trees = super::conflict::QueueConflictTrees {
            base: tree(&base)?,
            ours: tree(ours)?,
            theirs: tree(theirs)?,
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

    /// Both conflict doors' shared side builder: a detached scratch
    /// worktree at `base`, each source's commit on it in source order,
    /// then the base and both sides pinned before the scratch tree goes,
    /// so the recorded conflict's commits stay inspectable (FIX 8834).
    fn build_conflict_sides_at(
        &self,
        repo: &GitWireRepo,
        base: &GitOid,
        rows: &[RepoProposal],
    ) -> Result<Vec<GitOid>> {
        let wire = GitWire::new(self)?;
        let sources: Vec<_> = rows.iter().map(|row| row.id).collect();
        let identity = rmp_serde::to_vec(&sources)
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
        wire.add_worktree(repo, &scratch, base, 0)?;
        let sides = conflict_side_commits(&scratch, rows);
        let removed = wire.remove_worktree(repo, &scratch, 0);
        let sides = sides?;
        removed?;
        for oid in std::iter::once(base).chain(&sides) {
            let _pinned = wire.write_keep_ref(repo, oid, 0)?;
        }
        Ok(sides)
    }
}

/// Each source's commit on the historical base `root`, in source order: a
/// whole-file proposal's one file with its provenance trailer, a native
/// bundle's whole tree change under its message with its provenance
/// trailer as it would land, or a source-bound received bundle's whole
/// tree change under its own message.
fn conflict_side_commits(root: &std::path::Path, rows: &[RepoProposal]) -> Result<Vec<GitOid>> {
    let mut sides = Vec::new();
    for row in rows {
        let prepared = match row.operation {
            RepoProposalOperation::ReceivedFiles { .. } if row.is_source_bound_received() => {
                let edits = bundle_tree_edits(&row.files)?;
                prepare_bundle_files_commit(root, &edits, &row.message)?
            }
            RepoProposalOperation::CommitFiles => {
                let edits = bundle_tree_edits(&row.files)?;
                let message = super::trailer::commit_message_with_provenance_trailer(
                    &row.message,
                    Some(row.provenance_claim),
                )?;
                prepare_bundle_files_commit(root, &edits, &message)?
            }
            RepoProposalOperation::CommitFile
            | RepoProposalOperation::ResolveConflictFile { .. } => {
                let message = super::trailer::commit_message_with_provenance_trailer(
                    &row.message,
                    Some(row.provenance_claim),
                )?;
                let (path, content) = row.ordinary_file()?;
                prepare_commit_file_through_queue_worktree(root, path, content, &message)?
            }
            RepoProposalOperation::ReceivedFiles { .. } => {
                return Err(invalid(
                    "a conflict side is a stored file change or a source-bound bundle",
                ));
            }
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
