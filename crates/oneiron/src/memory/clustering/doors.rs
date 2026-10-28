//! Scoped clustering and authenticated judgments through the existing topology gate.

use super::operation::{id, references, subject_ref};
use super::*;
use crate::authority::{ActAuthority, OwnerActKind};
use crate::claim::{
    ClaimApprovalStatus, ClaimReadStatus, ClaimSource, PointRead, ScopedRead, ScopedReadResult,
};
use crate::cluster::{ClusterClaim, ClusterOptions, cluster_claims};
use crate::consent::AuthenticatedOwner;
use crate::identity_topology::{
    IdentityOpOutcome, IdentityOpWrite, IdentityTopologyAction, IdentityTopologyOp,
    ProposalOutcome, ProposalRuling, TopologySeal, fold_identity_topology_log,
};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, caps};
use crate::{EdgeActorClass, EntityId, WriteActor};

fn outcome(value: ProposalOutcome) -> ClusterTopologyOutcome {
    match value {
        ProposalOutcome::ApprovedUntouched => ClusterTopologyOutcome::ApprovedUntouched,
        ProposalOutcome::ApprovedAmended => ClusterTopologyOutcome::ApprovedAmended,
        ProposalOutcome::Rejected => ClusterTopologyOutcome::Rejected,
    }
}

fn readable(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    op: &IdentityTopologyOp,
) -> MemoryResult<()> {
    let (refs, edges) = references(op);
    if lane
        .entities_readable_in_txn(txn, &refs)?
        .into_iter()
        .any(|allowed| !allowed)
    {
        return Err(MemoryError::not_found(
            "a topology judgment reference is not readable",
        ));
    }
    for edge in edges {
        if !lane.claim_edge_subject_admitted_in_txn(txn, &edge)? {
            return Err(MemoryError::not_found(
                "a topology reassignment edge is not readable",
            ));
        }
    }
    Ok(())
}

impl Memory<'_> {
    /// Exact stored partitions plus caller-supplied vectors; no semantic write.
    pub fn cluster(
        &self,
        input: &ClusterRequest,
    ) -> MemoryResult<ScopedReadResult<ClusterProposal>> {
        caps::check_batch_len("cluster claims", input.claims.len())?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let ids = input
            .claims
            .iter()
            .map(|claim| self.resolve_ref_in_lane(&lane, &claim.claim_ref))
            .collect::<MemoryResult<Vec<_>>>()?;
        let reads = ids.iter().map(|id| PointRead::id(*id)).collect::<Vec<_>>();
        let result = lane.read_projected(&reads, None, |txn, rows| {
            let mut claims = Vec::with_capacity(rows.len());
            for (row, input) in rows.into_iter().zip(&input.claims) {
                let row = row
                    .filter(|row| row.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
                    .ok_or_else(|| {
                        MemoryError::not_found("cluster member is not a readable claim")
                    })?;
                let bytes = row
                    .body
                    .ok_or_else(|| MemoryError::not_found("cluster member has no readable body"))?;
                let body = crate::claim::decode_claim_body(&bytes, true)?;
                let facets = lane.claim_facet_refs_in(txn, &row.id)?;
                if facets.len() > 1 {
                    return Err(MemoryError::bad_request(
                        "cluster member has more than one facet",
                    ));
                }
                claims.push(ClusterClaim {
                    claim_id: row.id,
                    subject: body.subject,
                    predicate: body.predicate,
                    world: body.world,
                    facet: facets.first().copied(),
                    embedding: input.embedding.clone(),
                });
            }
            let options = ClusterOptions {
                cohesion_threshold: input
                    .cohesion_threshold
                    .unwrap_or(ClusterOptions::default().cohesion_threshold),
            };
            let assignments = cluster_claims(&claims, options)?;
            // FIX 9937: every ref goes out short where the vault keeps one,
            // in this read's snapshot.
            let project = |id: &EntityId| self.cluster_ref_in_txn(txn, id);
            let mut cohorts = Vec::with_capacity(assignments.cohorts.len());
            for cohort in assignments.cohorts {
                cohorts.push(ClusterCohort {
                    cohort_id: *cohort.cohort_id.as_bytes(),
                    partition: ClusterPartition {
                        subject_ref: subject_ref(&cohort.partition.subject, &project)?,
                        predicate_root: cohort.partition.predicate_root,
                        world_ref: cohort.partition.world.as_ref().map(project).transpose()?,
                        facet_ref: cohort.partition.facet.as_ref().map(project).transpose()?,
                    },
                    member_refs: cohort
                        .member_ids
                        .iter()
                        .map(project)
                        .collect::<MemoryResult<_>>()?,
                    cohesion: cohort.cohesion,
                });
            }
            Ok::<_, MemoryError>(ClusterProposal { cohorts })
        })?;
        self.produced_from(ids);
        Ok(result)
    }

    /// `id` as the short ref the vault keeps for it in `txn`'s snapshot, else
    /// its hex (FIX 9937).
    fn cluster_ref_in_txn(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> MemoryResult<String> {
        Ok(self
            .short_ref_of_in_txn(txn, id)?
            .unwrap_or_else(|| id.to_hex()))
    }

    /// The caller's own proof or its own named Grant. No engine-seal fallback.
    /// The owner's act records where his request reached this install, as
    /// the host bound it (FIX 4650): audit only.
    fn cluster_authority(
        &self,
        owner: Option<&AuthenticatedOwner>,
        grant: Option<&str>,
    ) -> MemoryResult<ActAuthority> {
        match (owner, grant) {
            (Some(owner), None) => Ok(ActAuthority::Owner(owner.clone(), self.owner_surface())),
            (None, Some(grant)) if self.actor_class() == EdgeActorClass::Agent => {
                Ok(ActAuthority::Agent(self.vault().granted_act(
                    self.actor(),
                    id(grant)?,
                    OwnerActKind::TopologySeal,
                )?))
            }
            _ => Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "topology judgments require the caller's owner proof or an agent's own topology_seal Grant",
                &[
                    "Use your own full owner credential, or name your agent's live topology_seal Grant.",
                ],
            )),
        }
    }

    fn cluster_writer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authority: &ActAuthority,
        approval: ClaimApprovalStatus,
    ) -> MemoryResult<IdentityOpWrite> {
        let source = match authority {
            ActAuthority::Owner(owner, _) => {
                if owner.revalidate_in_txn(self.vault(), txn)? != self.actor()
                    || self.actor_class() != EdgeActorClass::Human
                {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "topology owner proof must belong to this caller",
                        &[],
                    ));
                }
                ClaimSource::UserStated
            }
            ActAuthority::Agent(granted) => {
                if granted.agent() != self.actor() || self.actor_class() != EdgeActorClass::Agent {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "topology Grant must belong to this agent",
                        &[],
                    ));
                }
                self.vault()
                    .granted_act_owner_in_txn(txn, granted, OwnerActKind::TopologySeal)?;
                ClaimSource::Generated
            }
        };
        Ok(IdentityOpWrite {
            source,
            approval,
            confidence: 1.0,
            actor: Some(WriteActor::new(self.actor(), self.actor_class())),
        })
    }

    fn cluster_apply(
        &self,
        owner: Option<&AuthenticatedOwner>,
        operation: &ClusterOperation,
        grant: Option<&str>,
        approval: ClaimApprovalStatus,
    ) -> MemoryResult<ClusterTopologyReceipt> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let resolve = |reference: &str| self.resolve_ref_in_lane(&lane, reference);
        let op = operation.into_engine(&resolve)?;
        let authority = self.cluster_authority(owner, grant)?;
        let seal = TopologySeal::decision(authority.clone());
        self.with_verified_actor_write_txn(|txn| {
            let write = self.cluster_writer_in_txn(txn, &authority, approval)?;
            readable(&lane, txn, &op)?;
            let result = self.vault().apply_identity_topology_op_as_in_txn(
                txn,
                &op,
                &write,
                &seal,
                self.vault().now_recorded_at(),
            )?;
            match result {
                IdentityOpOutcome::Applied { event, .. } => Ok(ClusterTopologyReceipt {
                    receipt_ref: self.cluster_ref_in_txn(txn, &event)?,
                    proposal_ref: None,
                    outcome: ClusterTopologyOutcome::Applied,
                }),
                IdentityOpOutcome::Parked { event } => Ok(ClusterTopologyReceipt {
                    receipt_ref: self.cluster_ref_in_txn(txn, &event)?,
                    proposal_ref: Some(self.cluster_ref_in_txn(txn, &event)?),
                    outcome: ClusterTopologyOutcome::Proposed,
                }),
                IdentityOpOutcome::Noop => Err(MemoryError::bad_request(
                    "cluster judgment did not write an event",
                )),
            }
        })
    }

    pub fn cluster_propose(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &ClusterProposeRequest,
    ) -> MemoryResult<ClusterTopologyReceipt> {
        self.cluster_apply(
            owner,
            &input.operation,
            input.grant_ref.as_deref(),
            ClaimApprovalStatus::Proposed,
        )
    }

    pub fn cluster_merge(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &ClusterMergeRequest,
    ) -> MemoryResult<ClusterTopologyReceipt> {
        self.cluster_apply(
            owner,
            &ClusterOperation::Merge(input.merge.clone()),
            input.grant_ref.as_deref(),
            ClaimApprovalStatus::Auto,
        )
    }

    pub fn cluster_split(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &ClusterSplitRequest,
    ) -> MemoryResult<ClusterTopologyReceipt> {
        self.cluster_apply(
            owner,
            &ClusterOperation::Split(input.split.clone()),
            input.grant_ref.as_deref(),
            ClaimApprovalStatus::Auto,
        )
    }

    pub fn cluster_resolve_proposal(
        &self,
        owner: Option<&AuthenticatedOwner>,
        input: &ClusterResolveRequest,
    ) -> MemoryResult<ClusterTopologyReceipt> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let resolve = |reference: &str| self.resolve_ref_in_lane(&lane, reference);
        let proposal = resolve(input.proposal_ref.as_str())?;
        let authority = self.cluster_authority(owner, input.grant_ref.as_deref())?;
        let seal = TopologySeal::decision(authority.clone()).with_seen(Some(input.seen));
        let amended = match &input.ruling {
            ClusterRuling::AmendThenApprove { operation } => Some(operation.into_engine(&resolve)?),
            _ => None,
        };
        let encoded = amended
            .as_ref()
            .map(crate::identity_topology::encode_identity_op_amendment)
            .transpose()?;
        let ruling = match &input.ruling {
            ClusterRuling::Approve => ProposalRuling::Approve,
            ClusterRuling::Reject => ProposalRuling::Reject,
            ClusterRuling::AmendThenApprove { .. } => ProposalRuling::AmendThenApprove(
                encoded
                    .as_deref()
                    .ok_or_else(|| MemoryError::bad_request("missing amendment"))?,
            ),
        };
        self.with_verified_actor_write_txn(|txn| {
            let write =
                self.cluster_writer_in_txn(txn, &authority, ClaimApprovalStatus::Approved)?;
            let proposed = self.cluster_proposed_op_in_txn(&lane, txn, proposal)?;
            readable(&lane, txn, &proposed)?;
            if let Some(amended) = &amended {
                readable(&lane, txn, amended)?;
            }
            let (verdict, receipt) = self.vault().resolve_identity_proposal_in_txn(
                txn,
                &proposal,
                ruling,
                &write,
                &seal,
                self.vault().now_recorded_at(),
            )?;
            Ok(ClusterTopologyReceipt {
                receipt_ref: self.cluster_ref_in_txn(txn, &receipt)?,
                proposal_ref: Some(self.cluster_ref_in_txn(txn, &proposal)?),
                outcome: outcome(verdict),
            })
        })
    }

    fn cluster_proposed_op_in_txn(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        proposal: EntityId,
    ) -> MemoryResult<IdentityTopologyOp> {
        if lane.entities_readable_in_txn(txn, &[proposal])? != [true] {
            return Err(MemoryError::not_found("no readable topology proposal"));
        }
        let record = self
            .vault()
            .identity_topology_event_in_txn(txn, &proposal)?
            .filter(|record| record.approval == ClaimApprovalStatus::Proposed)
            .ok_or_else(|| MemoryError::not_found("no such topology proposal"))?;
        let IdentityTopologyAction::Apply(mut op) = record.action.to_fold_action() else {
            return Err(MemoryError::bad_request(
                "proposal must be a merge or split",
            ));
        };
        // The action codec deliberately excludes envelope evidence. Keep the
        // original judgment attached when inspecting and admitting its refs.
        match &mut op {
            IdentityTopologyOp::Merge(merge) => {
                merge.evidence = record.evidence.unwrap_or_default()
            }
            IdentityTopologyOp::Split(split) => {
                split.evidence = record.evidence.unwrap_or_default()
            }
            _ => {
                return Err(MemoryError::bad_request(
                    "proposal must be a merge or split",
                ));
            }
        }
        Ok(op)
    }

    pub fn cluster_proposal(
        &self,
        input: &ClusterProposalRequest,
    ) -> MemoryResult<ScopedReadResult<ClusterProposalView>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let proposal = self.resolve_ref_in_lane(&lane, &input.proposal_ref)?;
        let result = lane.read_projected(&[PointRead::id(proposal)], None, |txn, rows| {
            if rows.into_iter().flatten().all(|row| row.body.is_none()) {
                return Err(MemoryError::not_found("no readable topology proposal"));
            }
            let op = self.cluster_proposed_op_in_txn(&lane, txn, proposal)?;
            readable(&lane, txn, &op)?;
            let fold = fold_identity_topology_log(
                &self
                    .vault()
                    .fold_effective_identity_topology_events_in_txn(txn)?,
            );
            let project = |id: &EntityId| self.cluster_ref_in_txn(txn, id);
            Ok::<_, MemoryError>(ClusterProposalView {
                proposal_ref: project(&proposal)?,
                operation: ClusterOperation::from_engine(&op, &project)?,
                seen: crate::identity_topology::topology_seal_revision_for_store_in_txn(
                    &self.vault().store,
                    txn,
                    &proposal,
                )?,
                resolution: fold.resolved_proposals.get(&proposal).copied().map(outcome),
                moot: fold.moot_proposals.contains(&proposal),
            })
        })?;
        self.produced_from([proposal]);
        Ok(result)
    }
}
