//! The merge queue's green evidence for an origin mirror (FIX 6866 part 2;
//! CALLS "FIX 6866 full-auto green").
//!
//! A full-auto mirror pushes a head only when this repository's queue
//! advanced green on exactly that commit: a `GreenAdvanced` batch of this
//! object store whose landed head is the commit, whose every speculative
//! path passed its Fast check, whose Slow verdict passed on that landed
//! head and its full path's tree against the batch's own baseline, and whose
//! landed commit names that tree. Nothing else is green: not a publication,
//! not a receive-pack, not `HeadAdvanced`. The queue saves each batch
//! before it wakes the mirror, so a woken pass reads durable evidence. No
//! read here takes the repository's coordinator, and nothing here is a new
//! check runner.

use std::collections::BTreeMap;

use super::{BatchState, CheckPhase, MergeBatch, MergeQueue};
use crate::Vault;
use crate::contract_oracle::ContractOracle;
use crate::error::Result;
use crate::git_wire::{GitOid, GitWire, GitWireRepo};

/// One head the queue advanced green: the tree its full path tested, which
/// the commit must name. Its batch, verdicts and baseline were checked when
/// it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MirrorGreenEvidence {
    pub(crate) tree: String,
}

impl Vault {
    /// The green pointer of `repo`'s queue, or `None` when it has no queue.
    pub(crate) fn mirror_green_pointer(&self, repo: &GitWireRepo) -> Result<Option<String>> {
        let queue = MergeQueue {
            vault: self,
            repo: repo.clone(),
        };
        Ok(queue.read_queue()?.map(|record| record.pointers.green))
    }

    /// Every head of `repo`'s queue with exact green evidence, by commit.
    /// A batch whose evidence is missing or binds another commit, tree or
    /// baseline is no evidence; a store error ends the read.
    pub(crate) fn mirror_green_heads(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
    ) -> Result<BTreeMap<GitOid, MirrorGreenEvidence>> {
        let queue = MergeQueue {
            vault: self,
            repo: repo.clone(),
        };
        if queue.read_queue()?.is_none() {
            return Ok(BTreeMap::new());
        }
        let batches = {
            let txn = self.store.env.read_txn()?;
            queue.repo_batches_in_txn(&txn)?
        };
        let mut candidates = Vec::new();
        for batch in &batches {
            if batch.state != BatchState::GreenAdvanced {
                continue;
            }
            if let Some(found) = queue.green_evidence(batch)? {
                candidates.push(found);
            }
        }
        let heads: Vec<GitOid> = candidates.iter().map(|(head, _)| head.clone()).collect();
        let trees = wire.commit_trees(repo, &heads)?;
        Ok(candidates
            .into_iter()
            .filter(|(head, evidence)| {
                trees
                    .get(head)
                    .is_some_and(|tree| tree.as_str() == evidence.tree)
            })
            .collect())
    }
}

impl MergeQueue<'_> {
    /// The evidence one `GreenAdvanced` batch carries for its landed head,
    /// or `None` when any part is missing or binds something else.
    fn green_evidence(&self, batch: &MergeBatch) -> Result<Option<(GitOid, MirrorGreenEvidence)>> {
        let (Some(head), Some(verdict_id)) = (&batch.landed_head, &batch.slow_verdict) else {
            return Ok(None);
        };
        let Ok(commit) = GitOid::parse_hex(head.clone()) else {
            return Ok(None);
        };
        let Ok(path) = self.landed_path(batch) else {
            return Ok(None);
        };
        let Some(verdict) = ContractOracle::new(self.vault).verdict(verdict_id)? else {
            return Ok(None);
        };
        // The one binding rule both verdict formats share: a callback verdict's
        // candidate, or a bound checker's receipt rebuilt for this path (FIX 9979).
        let bound = self.require_check_binding(
            batch,
            path.mask,
            &path.tree,
            head,
            CheckPhase::Slow,
            &verdict,
            None,
        );
        if !matches!(bound, Ok(true))
            || !verdict.passes()
            || !matches!(self.all_paths_green(batch), Ok(true))
        {
            return Ok(None);
        }
        Ok(Some((
            commit,
            MirrorGreenEvidence {
                tree: path.tree.clone(),
            },
        )))
    }
}
