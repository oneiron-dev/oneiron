//! Bounded speculation, materialization and cleanup through the shared repo writer.
use super::types::QueueRecord;
use super::{BatchState, MergeBatch, MergeProposal, MergeQueue, RepoQueueOrder, SpeculativePath};
use crate::{
    contract_oracle::{invalid, safe_path},
    error::{CodeError, Error, Result},
    git_wire::{GitOid, GitWire, lock_repository, redact_bridged_failure, run_bridged_git_argv},
    repo_mutation::{RepoMutationOperation, RepoMutationRequest, RepoMutationStatus},
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

impl MergeQueue<'_> {
    /// Admit reviewed proposals from the last green tree, without applying them.
    pub fn enqueue(&self, proposals: Vec<MergeProposal>) -> Result<MergeBatch> {
        let formed =
            self.enqueue_checked::<std::convert::Infallible>(proposals, |_| Ok(Ok(None)))?;
        Ok(formed.unwrap_or_else(|never| match never {}))
    }

    /// The one batch formation. `admit` is the batch writer's first act: it
    /// answers the run order the batch keeps (FIX 6867), none for an owner
    /// or trusted batch, or a refusal, which writes nothing.
    pub(super) fn enqueue_checked<R>(
        &self,
        proposals: Vec<MergeProposal>,
        admit: impl FnOnce(&heed::RoTxn<'_>) -> Result<std::result::Result<Option<RepoQueueOrder>, R>>,
    ) -> Result<std::result::Result<MergeBatch, R>> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let mut queue = self.queue()?;
        self.require_current(&queue)?;
        self.require_clean(self.repo.repo_root())?;
        validate_proposals(&proposals, &queue.pointers.green)?;
        let id = self.next_batch_id(&mut queue, &proposals)?;
        let changed = proposals
            .iter()
            .flat_map(|p| p.files.iter().map(|f| f.path.as_str()));
        let selected_tests = queue.graph.affected_tests(changed)?;
        let mut batch = MergeBatch {
            schema_version: 1,
            id,
            expected_head: queue.pointers.head.clone(),
            base_green: queue.pointers.green.clone(),
            baseline_id: queue.baseline_id.clone(),
            proposals,
            state: BatchState::Queued,
            paths: Vec::new(),
            pre_snapshot: None,
            landed_head: None,
            slow_verdict: None,
            quarantine: None,
            selected_tests,
            run_order: None,
            drive: None,
        };
        if let Err(refused) = self.save_checked(&queue, &mut batch, admit)? {
            return Ok(Err(refused));
        }
        Ok(Ok(batch))
    }

    /// The id a new batch of `proposals` takes. The sequence only salts the
    /// batch id, so it rolls over rather than ending the queue (rule 5),
    /// past any id a kept batch holds.
    pub(super) fn next_batch_id(
        &self,
        queue: &mut QueueRecord,
        proposals: &[MergeProposal],
    ) -> Result<String> {
        loop {
            queue.sequence = queue.sequence.wrapping_add(1);
            let encoded = rmp_serde::to_vec_named(&(
                self.repo.identity().as_hex(),
                queue.sequence,
                proposals,
            ))
            .map_err(|_| invalid("merge batch identity encoding failed"))?;
            let id = blake3::hash(&encoded).to_hex().to_string();
            if !self.batch_exists(&id)? {
                return Ok(id);
            }
        }
    }

    /// Stage every inclusion/exclusion path. Staging may be resumed after a crash;
    /// already registered partial worktrees are removed and rebuilt, never trusted.
    pub fn stage(&self, id: &str) -> Result<MergeBatch> {
        self.stage_with(id, &mut |_| Ok(()))
    }

    /// [`Self::stage`]'s one body. `pin` runs on the staged batch before it
    /// is saved: the owner's stage pins nothing; the driver's pins every
    /// candidate commit first (FIX 6868).
    pub(super) fn stage_with(
        &self,
        id: &str,
        pin: &mut dyn FnMut(&mut MergeBatch) -> Result<()>,
    ) -> Result<MergeBatch> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        self.require_current(&queue)?;
        let mut batch = self.batch(id)?;
        if batch.state != BatchState::Queued {
            return Ok(batch);
        }
        // A run's entry waits Queued behind its live predecessors, never
        // refused; an owner or trusted batch waits on none (FIX 6867).
        if !self.run_batch_ready(&batch)? {
            return Ok(batch);
        }
        if batch.expected_head != queue.pointers.head {
            return Err(Error::ConcurrentWrite(
                "batch base moved; no automatic rebase",
            ));
        }
        self.require_clean(self.repo.repo_root())?;
        let wire = GitWire::new(self.vault)?;
        let count = (1_u64 << batch.proposals.len()) - 1;
        batch.paths.clear();
        for mask in 1..=count {
            let path = self.worktree_path(id, mask);
            if wire.worktree_registered(&self.repo, &path)? {
                wire.remove_worktree(&self.repo, &path, 0)?;
            }
            if path.exists() || path.symlink_metadata().is_ok() {
                return Err(invalid(
                    "speculative path is occupied outside its registration",
                ));
            }
            // This existing mutation captures the exact pre-action snapshot used
            // for rollback, in the same journal and repository lock as landing.
            let outcome = self.vault.apply_repo_mutation(RepoMutationRequest::new(
                self.repo.repo_ref().clone(),
                RepoMutationOperation::CreateWorktree {
                    worktree_path: path.clone(),
                    base_ref: batch.expected_head.clone(),
                },
            ))?;
            if outcome.entry.status != RepoMutationStatus::Applied {
                return Err(invalid("worktree creation was not applied"));
            }
            if let Some(snapshot) = batch.pre_snapshot {
                if snapshot != outcome.entry.pre_action_fork_hash {
                    return Err(Error::ConcurrentWrite("live tree changed during staging"));
                }
            } else {
                batch.pre_snapshot = Some(outcome.entry.pre_action_fork_hash);
            }
            let staged = self.materialize(&batch, mask, &path);
            let (commit, tree) = match staged {
                Ok(value) => value,
                Err(error) => {
                    wire.remove_worktree(&self.repo, &path, 0)?;
                    return Err(error);
                }
            };
            batch.paths.push(SpeculativePath {
                mask,
                worktree: path,
                commit,
                tree,
                verdict: None,
            });
        }
        batch.state = BatchState::Staged;
        pin(&mut batch)?;
        self.save(&queue, &[&batch])?;
        Ok(batch)
    }

    fn materialize(&self, batch: &MergeBatch, mask: u64, root: &Path) -> Result<(String, String)> {
        for (index, proposal) in batch.proposals.iter().enumerate() {
            if mask & (1 << index) == 0 {
                continue;
            }
            // A received bundle applies its exact entries through the index.
            if proposal
                .files
                .iter()
                .any(|file| file.metadata_edit.is_some())
            {
                super::file_metadata::materialize_received_merge_files(root, &proposal.files)?;
                continue;
            }
            for file in &proposal.files {
                let path = safe_path(root, &file.path)?;
                let actual = match std::fs::read(&path) {
                    Ok(bytes) => Some(bytes),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
                if actual != file.expected {
                    return Err(Error::ConcurrentWrite(
                        "proposal bytes overlap or base is stale",
                    ));
                }
                if let Some(content) = &file.content {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(path, content)?;
                } else if actual.is_some() {
                    std::fs::remove_file(path)?;
                }
                git(root, &["add", "--all", "--", &file.path])?;
            }
        }
        git(
            root,
            &[
                "-c",
                "user.name=Oneiron",
                "-c",
                "user.email=oneiron@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "Speculative merge candidate",
            ],
        )?;
        let commit = oid(root, "HEAD")?;
        let tree = oid(root, "HEAD^{tree}")?;
        self.require_clean(root)?;
        Ok((commit, tree))
    }

    /// Requeue only survivors of a diagnosed red batch. No changed base is silently
    /// accepted; the caller must submit a fresh reviewed proposal in that case.
    pub fn requeue_survivors(&self, id: &str) -> Result<Option<MergeBatch>> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let batch = self.batch(id)?;
        let quarantine = batch
            .quarantine
            .ok_or_else(|| invalid("batch has not been diagnosed"))?;
        if self.queue()?.pointers.head != batch.expected_head {
            return Err(Error::ConcurrentWrite(
                "survivors need a newly reviewed base",
            ));
        }
        let survivors: Vec<_> = batch
            .proposals
            .into_iter()
            .filter(|p| !quarantine.proposal_ids.contains(&p.id))
            .collect();
        if survivors.is_empty() {
            Ok(None)
        } else {
            self.enqueue(survivors).map(Some)
        }
    }

    /// Abandon only unlanded work. Landing/rollback intents require recovery.
    pub fn cancel(&self, id: &str) -> Result<MergeBatch> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        let mut batch = self.batch(id)?;
        if !matches!(
            batch.state,
            BatchState::Queued | BatchState::Staged | BatchState::Ready | BatchState::Cancelled
        ) {
            return Err(invalid(
                "effectful or settled merge batch cannot be cancelled",
            ));
        }
        batch.state = BatchState::Cancelled;
        self.save(&queue, &[&batch])?;
        Ok(batch)
    }

    pub fn cleanup(&self, id: &str) -> Result<()> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let batch = self.batch(id)?;
        if !matches!(
            batch.state,
            BatchState::GreenAdvanced
                | BatchState::Quarantined
                | BatchState::RolledBack
                | BatchState::Cancelled
        ) {
            return Err(invalid("live speculation cannot be collected"));
        }
        let wire = GitWire::new(self.vault)?;
        for mask in 1..(1 << batch.proposals.len()) {
            wire.remove_worktree(&self.repo, &self.worktree_path(id, mask), 0)?;
        }
        let slow = self.worktree_path(id, u64::MAX);
        if wire.worktree_registered(&self.repo, &slow)? {
            wire.remove_worktree(&self.repo, &slow, 0)?;
        }
        Ok(())
    }

    pub(super) fn worktree_path(&self, id: &str, mask: u64) -> PathBuf {
        std::env::temp_dir().join(format!(
            "oneiron-merge-{}-{id}-{mask}",
            self.repo.identity().as_hex()
        ))
    }
    pub(super) fn landed_check_path(
        &self,
        batch: &MergeBatch,
        speculative: &SpeculativePath,
    ) -> Result<SpeculativePath> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let current = self.batch(&batch.id)?;
        if current.state != BatchState::HeadAdvanced || current.landed_head != batch.landed_head {
            return Err(Error::ConcurrentWrite(
                "landed batch changed before slow check",
            ));
        }
        let commit = batch
            .landed_head
            .clone()
            .ok_or(Error::CorruptedIndex("landed HEAD missing"))?;
        let worktree = self.worktree_path(&batch.id, u64::MAX);
        let wire = GitWire::new(self.vault)?;
        if !wire.worktree_registered(&self.repo, &worktree)? {
            if worktree.symlink_metadata().is_ok() {
                return Err(invalid(
                    "slow check path is occupied outside its registration",
                ));
            }
            let outcome = self.vault.apply_repo_mutation(RepoMutationRequest::new(
                self.repo.repo_ref().clone(),
                RepoMutationOperation::CreateWorktree {
                    worktree_path: worktree.clone(),
                    base_ref: commit.clone(),
                },
            ))?;
            if outcome.entry.status != RepoMutationStatus::Applied {
                return Err(invalid("slow worktree creation was not applied"));
            }
        }
        let path = SpeculativePath {
            mask: speculative.mask,
            worktree,
            commit,
            tree: speculative.tree.clone(),
            verdict: None,
        };
        self.verify_worktree(&path)?;
        Ok(path)
    }

    pub(super) fn capture_current_snapshot(&self, batch: &MergeBatch) -> Result<[u8; 32]> {
        let path = self.worktree_path(&batch.id, 0);
        let wire = GitWire::new(self.vault)?;
        if wire.worktree_registered(&self.repo, &path)? {
            wire.remove_worktree(&self.repo, &path, 0)?;
        }
        let outcome = self.vault.apply_repo_mutation(RepoMutationRequest::new(
            self.repo.repo_ref().clone(),
            RepoMutationOperation::CreateWorktree {
                worktree_path: path.clone(),
                base_ref: self.head()?,
            },
        ))?;
        wire.remove_worktree(&self.repo, &path, 0)?;
        if outcome.entry.status != RepoMutationStatus::Applied {
            return Err(invalid("snapshot observation was not applied"));
        }
        Ok(outcome.entry.pre_action_fork_hash)
    }
    pub(super) fn head(&self) -> Result<String> {
        oid(self.repo.repo_root(), "HEAD")
    }
    pub(super) fn tree(&self) -> Result<String> {
        oid(self.repo.repo_root(), "HEAD^{tree}")
    }
    pub(super) fn require_clean(&self, root: &Path) -> Result<()> {
        if !git(root, &["status", "--porcelain", "--untracked-files=all"])?.is_empty() {
            return Err(Error::ConcurrentWrite(
                "merge check requires an unchanged materialized tree",
            ));
        }
        Ok(())
    }
    pub(super) fn verify_worktree(&self, path: &SpeculativePath) -> Result<()> {
        let wire = GitWire::new(self.vault)?;
        if !wire.worktree_registered(&self.repo, &path.worktree)?
            || oid(&path.worktree, "HEAD")? != path.commit
            || oid(&path.worktree, "HEAD^{tree}")? != path.tree
        {
            return Err(Error::ConcurrentWrite("speculative tree identity changed"));
        }
        self.require_clean(&path.worktree)
    }
}

pub(super) fn validate_proposals(proposals: &[MergeProposal], green: &str) -> Result<()> {
    if proposals.is_empty() || proposals.len() > 6 {
        return Err(invalid("merge batch must contain one to six proposals"));
    }
    let mut ids = BTreeSet::new();
    let mut total = 0_usize;
    for proposal in proposals {
        if proposal.id.is_empty()
            || proposal.id.len() > 256
            || !ids.insert(&proposal.id)
            || proposal.base_green != green
            || proposal.files.is_empty()
        {
            return Err(invalid("merge proposal identity or green base is invalid"));
        }
        let mut paths = BTreeSet::new();
        // A received bundle's files all carry their reviewed state change;
        // an ordinary proposal's carry none (G4 PR2).
        let received = proposal
            .files
            .iter()
            .any(|file| file.metadata_edit.is_some());
        for file in &proposal.files {
            match &file.metadata_edit {
                Some(edit) => super::file_metadata::validate_received_merge_file(file, edit)?,
                None if received => {
                    return Err(invalid("a received bundle's every file carries its state"));
                }
                None if file.content.is_none() => {
                    return Err(invalid(
                        "merge deletion requires a reviewed delete operation",
                    ));
                }
                None if file.expected == file.content => {
                    return Err(invalid("duplicate, oversized or empty merge edit"));
                }
                None => {}
            }
            if !paths.insert(&file.path) || file.path.len() > 4096 {
                return Err(invalid("duplicate, oversized or empty merge edit"));
            }
            total = total
                .saturating_add(file.content.as_ref().map_or(0, Vec::len))
                .saturating_add(file.expected.as_ref().map_or(0, Vec::len));
        }
    }
    if total > 64 * 1024 * 1024 {
        return Err(invalid("merge batch content exceeds limit"));
    }
    Ok(())
}

pub(super) fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let args: Vec<_> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let output = run_bridged_git_argv(root, &args)?;
    if !output.success || output.timed_out || output.truncated {
        return Err(Error::Code(CodeError::RepoMutationFailed(
            redact_bridged_failure(&args, output.exit_code, &output.stderr),
        )));
    }
    Ok(output.stdout)
}
fn oid(root: &Path, revision: &str) -> Result<String> {
    let bytes = git(root, &["rev-parse", "--verify", revision])?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("git OID is not UTF-8"))?
        .trim();
    Ok(GitOid::parse_hex(value)?.as_str().to_owned())
}
