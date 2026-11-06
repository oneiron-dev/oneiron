//! A tested queue revision's derivation belongs to each admitted run that
//! authored one of its applied proposals, not to the queue's aggregation
//! session or its checker. Proposal run stamps were captured under the host's
//! lease before the proposal's first write; reading one grants no authority.

use std::collections::BTreeSet;

use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::code_revision::CodeRevision;
use crate::merge_queue::QueueTestedTarget;
use crate::repo_mutation::proposal::RepoProposalStatus;

use super::derivation_witness::{self, WitnessProducer};
use super::run_writes::RunWriteToken;

/// Witnesses the seal's stored DerivedFrom edge for every distinct source
/// run, in the seal's own writer. A failed capture leaves the seal unchanged.
/// An exact retry records no duplicate; a completed run reconciles its late
/// credit without rewriting the receipt it froze at close.
pub(crate) fn note_queue_revision_derivations_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    revision: &CodeRevision,
) {
    let Some(tested) = &revision.tested_queue else {
        return;
    };
    let QueueTestedTarget::Landed { applied, .. } = &tested.target else {
        return;
    };
    derivation_witness::capture_in_txn(&vault.store, wtxn, "queue revision", |txn| {
        let queue = AttemptQueue::from_store(&vault.store);
        let mut seen = BTreeSet::new();
        for source in applied {
            let Some(proposal) = vault.repo_proposal_in_txn(txn, source.proposal)? else {
                continue;
            };
            if proposal.id != source.proposal
                || proposal.status != RepoProposalStatus::Applied
                || proposal.operation_seq != Some(source.operation_seq)
                || proposal.session != source.session
                || proposal.provenance_claim != source.provenance_claim
                || proposal.actor.id().is_none()
            {
                continue;
            }
            let Some(stamp) = &proposal.run else {
                continue;
            };
            // A retained proposal is not proof that its run still exists:
            // compaction may have retired the attempt since it submitted.
            let Some(attempt) = queue.get_in_txn(txn, stamp.attempt)? else {
                continue;
            };
            if attempt.attempt_count < stamp.generation
                || !seen.insert((*stamp.attempt.as_bytes(), stamp.generation))
            {
                continue;
            }
            let token =
                RunWriteToken::of(stamp.attempt, stamp.lease_owner.clone(), stamp.generation);
            if derivation_witness::record_pairs_in_txn(
                &vault.store,
                txn,
                &token,
                &[(revision.revision_id, revision.session_id)],
                WitnessProducer::QueueSeal,
            )? {
                derivation_witness::reconcile_landed_in_txn(vault, txn, &token);
            }
        }
        Ok(())
    });
}
