//! The candidate leaf's pure reads (G4 PR2): retained received refs, their
//! admitting publication, a candidate's frozen resolution and its
//! complete-push link, and the owner's projection of its progress, a
//! queue batch listing its proposal included.
use heed::RoTxn;

use super::super::document_candidate_types::{
    CodePushCandidateState, CodePushCandidateView, ReceivedRefIngress, ResolvedPushCandidate,
};
use super::super::document_ingress::{
    CODE_OPERATIONS, ProvenanceRefKey, RECEIVED_UPDATES, received_update_hash,
};
use super::super::publication::OriginPublicationStatus;
use super::candidate_digest;
use crate::error::{Error, Result};
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

    /// The retained received refs of the object store `store` that moved
    /// `ref_name` from exactly `old` to exactly `new`, with their push
    /// provenance, in key order: one keyed read of the update index, never
    /// a walk of the store's receipts (FIX 7595). A pure read.
    ///
    /// # Errors
    /// A store failure, or an index row whose receipt is gone.
    pub(crate) fn received_code_ingress_rows_for_update(
        &self,
        store: &str,
        ref_name: &str,
        old: Option<&str>,
        new: &str,
    ) -> Result<Vec<(EntityId, ReceivedRefIngress)>> {
        let txn = self.store.env.read_txn()?;
        let update = received_update_hash(store, ref_name, old, Some(new));
        let mut rows = Vec::new();
        for row in RECEIVED_UPDATES.iter_from(&self.store, &txn, &update)? {
            let ((_, provenance), ()) = row?;
            let row = CODE_OPERATIONS
                .get(
                    &self.store,
                    &txn,
                    &ProvenanceRefKey::of(provenance, ref_name),
                )?
                .ok_or(Error::CorruptedIndex(
                    "received update index names no receipt",
                ))?;
            rows.push((provenance, row));
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
    pub(super) fn received_candidate_row_in_txn(
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
        // A masked copy's candidate links its canonical translation, proved
        // again here; its seal compares the canonical target tree, never the
        // submitted one (FIX 7608 2b-ii-B2, P8).
        let projection = match &attached.projected {
            None => None,
            Some(pins) => {
                let Some(link) = projected_source_link(self, &txn, provenance, candidate, pins)?
                else {
                    return Ok(None);
                };
                Some(link)
            }
        };
        let target_tree = projection.as_ref().map_or_else(
            || resolved.new_tree.clone(),
            |link| link.canonical_target_tree.clone(),
        );
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
                projection,
            },
            target_tree,
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
            detail: None,
        };
        if let Some(held) = &candidate.hold {
            view.state = held.state;
            view.reason = Some(held.reason.clone());
        }
        // A masked copy's typed hold names its ruled status text (FIX 9237).
        view.detail = super::projected_clearance::projection_hold_detail(candidate);
        let Some(resolved) = &candidate.resolved else {
            return Ok(Some(view));
        };
        view.base_revision = Some(resolved.base_revision);
        view.fork_session = Some(resolved.fork_session);
        view.proposal_refs = vec![resolved.proposal_id];
        let proposal = self.repo_proposal(resolved.proposal_id)?;
        let stack = proposal
            .as_ref()
            .and_then(|proposal| proposal.merge_stack.clone());
        view.state = match proposal {
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
        // A quarantine that names its proposal, with no live batch carrying
        // it on, is where it stands; every check work of its batches is
        // named (FIX 7536).
        let (quarantined, checks) = self.queue_proposal_quarantine_and_checks(
            &row.source.object_store,
            resolved.proposal_id,
            &view.batch_refs,
        )?;
        let carried_on = match view.state {
            CodePushCandidateState::Queued => {
                stack.is_none_or(|stack| !quarantined.contains(&stack))
            }
            CodePushCandidateState::Proposed => false,
            _ => true,
        };
        if !quarantined.is_empty() && !carried_on {
            view.state = CodePushCandidateState::Quarantined;
        }
        for batch in quarantined {
            if !view.batch_refs.contains(&batch) {
                view.batch_refs.push(batch);
            }
        }
        view.check_work_refs = checks;
        // An active projection hold wins over the proposal's progress, its
        // links kept (FIX 7608 2b-ii-B2).
        if let (Some(_), Some(held)) = (&view.detail, &candidate.hold) {
            view.state = held.state;
        }
        Ok(Some(view))
    }
}

/// The projection link of a masked copy's candidate: its source proved
/// again (the ingress proof of its operation and its translation record),
/// with its canonical base and target. `None` when either no longer stands
/// or no canonical target resolved: no complete link is earned.
fn projected_source_link(
    vault: &Vault,
    txn: &RoTxn<'_>,
    provenance: EntityId,
    candidate: EntityId,
    pins: &super::projected::RepoProjectedCandidatePins,
) -> Result<Option<crate::merge_queue::CodePushProjectionSourceLink>> {
    let Some(operation) = super::projected_join::receive_operation_in_txn(vault, txn, provenance)?
    else {
        return Ok(None);
    };
    if !super::projected_source::require_projected_candidate_source_in_txn(
        vault, txn, pins, candidate, operation,
    )? {
        return Ok(None);
    }
    let (Some(base), Some(target)) = (&pins.canonical_base, &pins.canonical_target_tree) else {
        return Ok(None);
    };
    Ok(Some(crate::merge_queue::CodePushProjectionSourceLink {
        graph: pins.graph,
        ingress: pins.ingress,
        submitted_old: pins.submitted_old.clone(),
        submitted_new: pins.submitted_new.clone(),
        canonical_base: base.clone(),
        canonical_target_tree: target.clone(),
        pins_digest: pins.digest(),
    }))
}
