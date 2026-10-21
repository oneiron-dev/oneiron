//! The candidate leaf's pure reads (G4 PR2): retained received refs, their
//! admitting publication, a candidate's frozen resolution and its
//! complete-push link, and the owner's projection of its progress, a
//! queue batch listing its proposal included.
use heed::RoTxn;

use super::super::document_candidate_types::{
    CodePushCandidateState, CodePushCandidateView, ReceivedRefIngress, ResolvedPushCandidate,
};
use super::super::document_ingress::CODE_OPERATIONS;
use super::super::publication::OriginPublicationStatus;
use super::candidate_digest;
use crate::error::Result;
use crate::merge_queue::CodePushSourceLink;
use crate::repo_mutation::proposal::RepoProposalStatus;
use crate::{EntityId, Vault};

impl Vault {
    /// Every retained received ref of the object store `store`, with its
    /// push provenance, in key order: the owner workbench's links. A pure
    /// read.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn received_code_ingress_rows(
        &self,
        store: &str,
    ) -> Result<Vec<(EntityId, ReceivedRefIngress)>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for row in CODE_OPERATIONS.iter_from(&self.store, &txn, &[])? {
            let (key, row) = row?;
            if row.source.object_store == store {
                rows.push((key.provenance, row));
            }
        }
        Ok(rows)
    }

    /// The publication that admitted the received ref `row` of the push
    /// `provenance`, and whether it is Published. A pure read.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn received_ref_publication(
        &self,
        provenance: EntityId,
        row: &ReceivedRefIngress,
    ) -> Result<Option<(EntityId, bool)>> {
        let Some(new) = row.source.new_oid.as_deref() else {
            return Ok(None);
        };
        let repo_id = super::super::lfs::lfs_repo_id(&row.source.object_store)?;
        Ok(self
            .find_origin_publication(repo_id, |record| {
                record.provenance_claim_id == provenance
                    && record.ref_name.as_str() == row.source.ref_name
                    && record.new_oid.as_str() == new
            })?
            .map(|record| {
                (
                    record.publication_id,
                    record.status == OriginPublicationStatus::Published,
                )
            }))
    }

    /// The source row of the candidate `candidate` among the push
    /// `provenance`'s refs, in `txn`.
    fn received_candidate_row_in_txn(
        &self,
        txn: &RoTxn<'_>,
        provenance: EntityId,
        candidate: EntityId,
    ) -> Result<Option<ReceivedRefIngress>> {
        Ok(CODE_OPERATIONS
            .scan_from(&self.store, txn, provenance.as_bytes())?
            .into_iter()
            .map(|(_, row)| row)
            .find(|row| {
                row.candidate
                    .as_ref()
                    .is_some_and(|attached| attached.candidate == candidate)
            }))
    }

    /// The frozen resolution of `candidate`, in `txn`.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn received_candidate_resolution_in_txn(
        &self,
        txn: &RoTxn<'_>,
        provenance: EntityId,
        candidate: EntityId,
    ) -> Result<Option<ResolvedPushCandidate>> {
        Ok(self
            .received_candidate_row_in_txn(txn, provenance, candidate)?
            .and_then(|row| row.candidate)
            .and_then(|candidate| candidate.resolved))
    }

    /// The complete-push link `candidate` would earn, with the incoming
    /// tip's tree a seal must equal to earn it.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn received_push_source_link(
        &self,
        provenance: EntityId,
        candidate: EntityId,
    ) -> Result<Option<(CodePushSourceLink, String)>> {
        let txn = self.store.env.read_txn()?;
        let Some(row) = self.received_candidate_row_in_txn(&txn, provenance, candidate)? else {
            return Ok(None);
        };
        let Some(attached) = &row.candidate else {
            return Ok(None);
        };
        let Some(resolved) = &attached.resolved else {
            return Ok(None);
        };
        let (Some(old_commit), Some(new_commit)) = (&row.source.old_oid, &row.source.new_oid)
        else {
            return Ok(None);
        };
        Ok(Some((
            CodePushSourceLink {
                candidate,
                provenance,
                ref_name: row.source.ref_name.clone(),
                publication: resolved.publication,
                old_commit: old_commit.clone(),
                new_commit: new_commit.clone(),
                base_revision: resolved.base_revision,
                candidate_digest: candidate_digest(attached)?,
            },
            resolved.new_tree.clone(),
        )))
    }

    /// The owner's view of the candidate a source row carries: its hold, or
    /// a projection of its saved proposal. `None` before matching ran.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn received_candidate_view(
        &self,
        row: &ReceivedRefIngress,
    ) -> Result<Option<CodePushCandidateView>> {
        let Some(candidate) = &row.candidate else {
            return Ok(None);
        };
        let mut view = CodePushCandidateView {
            candidate: candidate.candidate,
            state: CodePushCandidateState::Pending,
            reason: None,
            base_revision: None,
            fork_session: None,
            proposal_refs: Vec::new(),
            batch_refs: Vec::new(),
            check_work_refs: Vec::new(),
            revision_refs: Vec::new(),
        };
        if let Some(held) = &candidate.hold {
            view.state = held.state;
            view.reason = Some(held.reason.clone());
        }
        let Some(resolved) = &candidate.resolved else {
            return Ok(Some(view));
        };
        view.base_revision = Some(resolved.base_revision);
        view.fork_session = Some(resolved.fork_session);
        view.proposal_refs = vec![resolved.proposal_id];
        view.state = match self.repo_proposal(resolved.proposal_id)? {
            None => CodePushCandidateState::Pending,
            Some(proposal) => match proposal.status {
                _ if proposal.merge_stack.is_some()
                    && proposal.status != RepoProposalStatus::Applied =>
                {
                    if let Some(batch) = &proposal.merge_stack {
                        view.batch_refs.push(batch.clone());
                    }
                    CodePushCandidateState::Queued
                }
                RepoProposalStatus::Proposed | RepoProposalStatus::Approved => {
                    // A queue batch lists it before its stack binds it (FIX 8268).
                    let batches =
                        self.queue_batches_listing(&row.source.object_store, proposal.id)?;
                    if batches.is_empty() {
                        CodePushCandidateState::Proposed
                    } else {
                        view.batch_refs.extend(batches);
                        CodePushCandidateState::Queued
                    }
                }
                RepoProposalStatus::Applied => {
                    if let Some(batch) = &proposal.merge_stack {
                        view.batch_refs.push(batch.clone());
                    }
                    CodePushCandidateState::Landed
                }
                RepoProposalStatus::Failed => CodePushCandidateState::RolledBack,
                RepoProposalStatus::Rejected => CodePushCandidateState::Rejected,
            },
        };
        Ok(Some(view))
    }
}
