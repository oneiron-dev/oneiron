//! A received push's own entry into its merge queue (FIX 8268, CALL
//! `REVIEW_POLICY_DEFAULT = LandOnGreen`).
//!
//! An accepted push's candidate attaches ONE Proposed bundle that names no
//! catalog. With no vault review policy set, nothing reviews it, so nothing
//! would enqueue it: the queue's intake enqueues it here, once, as its own
//! batch at the current green, into the same checks as every other batch:
//! fast-tested head, slow-tested green, bound checker receipts. A restart
//! finds the already attached ones the same way, by the retained source
//! rows, never by a candidate index or scheduler of its own. Nothing is
//! approved, rebased or landed here, and a bundle any batch of this queue
//! ever listed (queued, landed, quarantined, rolled back or cancelled) is
//! never queued again. With a policy set, or one that does not read, the
//! bundle keeps today's explicit review and owner enqueue.

use super::{BatchState, MergeQueue, QueueReviewRequirement, queue_review_requirement_in_txn};
use crate::codebase::RepoRef;
use crate::error::Result;
use crate::repo_mutation::proposal::{RepoProposal, RepoProposalStatus};
use crate::{EntityId, Vault};

/// Whether `row` is still the open, unbound received bundle of `candidate`,
/// pinned at the queue green `green`.
fn open_at_green(row: &RepoProposal, candidate: EntityId, green: &str) -> bool {
    matches!(
        row.status,
        RepoProposalStatus::Proposed | RepoProposalStatus::Approved
    ) && row.operation_seq.is_none()
        && row.merge_stack.is_none()
        && row.received_candidate() == Some(candidate)
        && RepoRef::parse(&row.repo).is_ok_and(|pointer| pointer.commit_hash() == Some(green))
}

impl MergeQueue<'_> {
    /// Enqueues, once each, every attached received bundle of this queue's
    /// store that its review holds to nothing (no catalog of its own, no
    /// vault review policy) and that is pinned at the current green.
    /// Answers how many batches it formed. A bundle off the green waits for
    /// its owner: nothing rebases.
    ///
    /// # Errors
    /// A store failure reading the queue or the source rows. One bundle's
    /// own failure is logged and leaves it as it is.
    pub(super) fn enqueue_unreviewed_received_candidates(&self) -> Result<usize> {
        let green = self.queue()?.pointers.green;
        let mut formed = 0_usize;
        for (provenance, row) in self
            .vault
            .received_code_ingress_rows(&self.repo.identity().as_hex())?
        {
            let Some((candidate, proposal)) = row.candidate.and_then(|attached| {
                attached
                    .resolved
                    .map(|resolved| (attached.candidate, resolved.proposal_id))
            }) else {
                continue;
            };
            match self.enqueue_received_once(provenance, candidate, proposal, &green) {
                Ok(true) => formed += 1,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a received push bundle did not enter its queue; it stays proposed"
                    );
                }
            }
        }
        Ok(formed)
    }

    /// One bundle's entry: judged once before the batch is built, then
    /// again, with the queue's batch rows, in the batch writer under the
    /// repository lock, so it enters exactly once.
    fn enqueue_received_once(
        &self,
        provenance: EntityId,
        candidate: EntityId,
        proposal: EntityId,
        green: &str,
    ) -> Result<bool> {
        let Some(row) = self.vault.repo_proposal(proposal)? else {
            return Ok(false);
        };
        {
            let txn = self.vault.store.env.read_txn()?;
            if !self.received_unqueued_in_txn(&txn, &row, provenance, candidate, green)? {
                return Ok(false);
            }
        }
        let merge = crate::repo_mutation::received_merge_proposal(self.vault, &row, green)?;
        let entered = self.enqueue_checked::<()>(vec![merge], |txn| {
            let Some(current) = self.vault.repo_proposal_in_txn(txn, proposal)? else {
                return Ok(Err(()));
            };
            Ok(
                if self.received_unqueued_in_txn(txn, &current, provenance, candidate, green)? {
                    Ok(None)
                } else {
                    Err(())
                },
            )
        })?;
        Ok(entered.is_ok())
    }

    /// The whole judgement in `txn`: the bundle is open, unbound and pinned
    /// at the green; its candidate still resolves to it; the vault holds it
    /// to no review; and no batch of this queue ever listed it.
    fn received_unqueued_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &RepoProposal,
        provenance: EntityId,
        candidate: EntityId,
        green: &str,
    ) -> Result<bool> {
        if !open_at_green(row, candidate, green)
            || !self
                .vault
                .received_candidate_resolution_in_txn(txn, provenance, candidate)?
                .is_some_and(|resolved| resolved.proposal_id == row.id)
            || !matches!(
                queue_review_requirement_in_txn(self.vault, txn, &row.review)?,
                QueueReviewRequirement::LandOnGreen
            )
        {
            return Ok(false);
        }
        let id = row.id.to_hex();
        Ok(!self
            .repo_batches_in_txn(txn)?
            .iter()
            .any(|batch| batch.proposals.iter().any(|proposal| proposal.id == id)))
    }
}

impl Vault {
    /// The batches of the queue of object store `store` that list the
    /// proposal `proposal` and are still in flight (queued, staged, tested
    /// or landing), in key order: a received candidate's view reads it as
    /// queued before its stack binds it (FIX 8268). A pure read.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_batches_listing(
        &self,
        store: &str,
        proposal: EntityId,
    ) -> Result<Vec<String>> {
        let txn = self.store.env.read_txn()?;
        let prefix = format!("{store}:");
        let id = proposal.to_hex();
        Ok(super::storage::BATCHES
            .scan_from(&self.store, &txn, prefix.as_bytes())?
            .into_iter()
            .map(|(_, batch)| batch)
            .filter(|batch| {
                matches!(
                    batch.state,
                    BatchState::Queued
                        | BatchState::Staged
                        | BatchState::Ready
                        | BatchState::Landing
                ) && batch.proposals.iter().any(|listed| listed.id == id)
            })
            .map(|batch| batch.id)
            .collect())
    }
}
