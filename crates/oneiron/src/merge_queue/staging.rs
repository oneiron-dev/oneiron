//! Bounded speculation, materialization and cleanup through the shared repo writer.
use super::{BatchState, MergeBatch, MergeProposal, MergeQueue, SpeculativePath};
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
        let _guard = lock_repository(self.repo.common_dir())?;
        let mut queue = self.queue()?;
        self.require_current(&queue)?;
        self.require_clean(self.repo.repo_root())?;
        validate_proposals(&proposals, &queue.pointers.green)?;
        if queue.sequence == 100_000 {
            return Err(invalid("merge queue row limit reached"));
        }
        queue.sequence += 1;
        let encoded =
            rmp_serde::to_vec_named(&(self.repo.identity().as_hex(), queue.sequence, &proposals))
                .map_err(|_| invalid("merge batch identity encoding failed"))?;
        let id = blake3::hash(&encoded).to_hex().to_string();
        let changed = proposals
            .iter()
            .flat_map(|p| p.files.iter().map(|f| f.path.as_str()));
        let selected_tests = queue.graph.affected_tests(changed)?;
        let batch = MergeBatch {
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
        };
        self.save(&queue, &[&batch])?;
        Ok(batch)
    }

    /// Stage every inclusion/exclusion path. Staging may be resumed after a crash;
    /// already registered partial worktrees are removed and rebuilt, never trusted.
    pub fn stage(&self, id: &str) -> Result<MergeBatch> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        self.require_current(&queue)?;
        let mut batch = self.batch(id)?;
        if batch.state != BatchState::Queued {
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
        self.save(&queue, &[&batch])?;
        Ok(batch)
    }

    fn materialize(&self, batch: &MergeBatch, mask: u64, root: &Path) -> Result<(String, String)> {
        for (index, proposal) in batch.proposals.iter().enumerate() {
            if mask & (1 << index) == 0 {
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
        Ok(())
    }

    pub(super) fn worktree_path(&self, id: &str, mask: u64) -> PathBuf {
        std::env::temp_dir().join(format!(
            "oneiron-merge-{}-{id}-{mask}",
            self.repo.identity().as_hex()
        ))
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

fn validate_proposals(proposals: &[MergeProposal], green: &str) -> Result<()> {
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
        for file in &proposal.files {
            if !paths.insert(&file.path) || file.path.len() > 4096 || file.expected == file.content
            {
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
