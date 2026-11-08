//! A removed public name routes to a person review (FIX 4365).
//!
//! The contract oracle marks a removed public name as a red verdict. Both
//! check bodies, the callback `check` and the bound check, route such a
//! fast verdict to a person review on every stored proposal of the tree it
//! judged, in the writer that settles its slot. The request binds the
//! verdict, its baseline, that exact tree and the proposal ids. The driver
//! holds the red batch before its diagnosis until a person decides every
//! such request. The verdict stays red: a person can require a repair, and
//! Approve never turns the check green.
use std::collections::BTreeSet;

use super::{
    BatchState, CheckPhase, MergeBatch, MergeQueue, QueueDriveHoldReason, QueueDriveOutcome,
};
use crate::error::{Error, Result};
use crate::repo_mutation::proposal::ContractReviewEvidence;
use crate::store::contract_oracle::{ContractDiff, ContractOracle, ContractVerdict};

impl MergeQueue<'_> {
    /// Holds red staged batch `id` before its diagnosis while a removed
    /// public name on one of its paths waits for a person review (FIX
    /// 4365). Each settled path's verdict is routed again in one writer, so
    /// a request is never left out. Once every request has a decision, a
    /// kept review hold is cleared and `None` lets the diagnosis run.
    ///
    /// # Errors
    /// A store failure, a missing verdict, or a kept request whose binding
    /// differs.
    pub(super) fn hold_for_contract_review(&self, id: &str) -> Result<Option<QueueDriveOutcome>> {
        let batch = self.batch(id)?;
        if batch.state != BatchState::Staged {
            return Ok(None);
        }
        let oracle = ContractOracle::new(self.vault);
        let mut reviews = Vec::new();
        for path in &batch.paths {
            let Some(verdict) = &path.verdict else {
                continue;
            };
            let verdict = oracle
                .verdict(verdict)?
                .ok_or(Error::CorruptedIndex("merge verdict is missing"))?;
            let review =
                contract_review_evidence(&batch, path.mask, CheckPhase::Fast, &path.tree, &verdict);
            if let Some(evidence) = review {
                let removed: Vec<String> = removed_names(&verdict)
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                reviews.push((evidence, removed));
            }
        }
        let mut proposals = Vec::new();
        let mut names = BTreeSet::new();
        if !reviews.is_empty() {
            let mut txn = self.vault.store.env.write_txn()?;
            for (evidence, removed) in reviews {
                let waiting = self
                    .vault
                    .route_contract_review_in_txn(&mut txn, &evidence)?;
                if waiting.is_empty() {
                    continue;
                }
                names.extend(removed);
                for proposal in waiting {
                    if !proposals.contains(&proposal) {
                        proposals.push(proposal);
                    }
                }
            }
            txn.commit()?;
        }
        if !proposals.is_empty() {
            let names: Vec<String> = names.into_iter().collect();
            let detail = format!(
                "proposals {} removed the public names {} and wait for a person review of that \
                 evidence; the verdict stays red",
                proposals.join(", "),
                names.join(", "),
            );
            return self
                .hold(id, QueueDriveHoldReason::WaitingReview, detail)
                .map(Some);
        }
        let kept = batch
            .drive
            .as_ref()
            .and_then(|drive| drive.hold.as_ref())
            .is_some_and(|hold| hold.reason == QueueDriveHoldReason::WaitingReview);
        if kept {
            self.record_hold(id, None)?;
        }
        Ok(None)
    }
}

/// The person review evidence of `verdict`, judged on `batch`'s path `mask`
/// at `tree`, when it lists a removed public name (FIX 4365). The writer
/// that settles the verdict's slot routes it, after that writer's own
/// checks. A slow check judges the tree its fast path already judged, and
/// its red rolls the landed head back at once, so only a fast verdict has
/// evidence.
pub(super) fn contract_review_evidence(
    batch: &MergeBatch,
    mask: u64,
    phase: CheckPhase,
    tree: &str,
    verdict: &ContractVerdict,
) -> Option<ContractReviewEvidence> {
    if phase != CheckPhase::Fast || removed_names(verdict).is_empty() {
        return None;
    }
    Some(ContractReviewEvidence {
        verdict: verdict.id.clone(),
        baseline: verdict.baseline_id.clone(),
        batch: batch.id.clone(),
        tree: tree.to_owned(),
        proposals: batch
            .proposals
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, proposal)| proposal.id.clone())
            .collect(),
    })
}

/// The public names `verdict` lists as removed, in its order.
fn removed_names(verdict: &ContractVerdict) -> Vec<&str> {
    verdict
        .diffs
        .iter()
        .filter_map(|diff| match diff {
            ContractDiff::RemovedPublicName { name } => Some(name.as_str()),
            ContractDiff::SchemaDrift { .. }
            | ContractDiff::OutputDrift { .. }
            | ContractDiff::SchemaBytesDrift { .. } => None,
        })
        .collect()
}
