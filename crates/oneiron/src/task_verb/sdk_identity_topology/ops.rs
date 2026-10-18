//! Owner authority and DTO projection; topology effects stay in the owning engine doors.
use crate::authority::{ActAuthority, ActSurface};
use crate::consent::AuthenticatedOwner;
use crate::identity_topology::{
    self as topology, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp,
    StoredIdentityOpAction, TopologySeal,
};
use crate::memory::{MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId, Error, Vault, WriteActor};

use super::*;

fn owner_write(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
    approval: ClaimApprovalStatus,
) -> MemoryResult<IdentityOpWrite> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    Ok(IdentityOpWrite {
        source: ClaimSource::UserStated,
        approval,
        confidence: 1.0,
        actor: Some(WriteActor::new(actor, EdgeActorClass::Human)),
    })
}

fn owner_seal(owner: &AuthenticatedOwner) -> TopologySeal {
    TopologySeal::decision(ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall))
}

fn event_receipt(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> MemoryResult<IdentityTopologyReceipt> {
    let record = vault
        .identity_topology_event_in_txn(txn, &event)?
        .ok_or(Error::EntityNotFound)?;
    let action = match record.action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            IdentityEventAction::Merge { sources, survivor }
        }
        StoredIdentityOpAction::Split {
            entity,
            heads,
            reassignment,
            applied_assigned,
            applied_residue,
        } => IdentityEventAction::Split {
            entity,
            heads,
            reassignment_map: reassignment.entries.into_iter().map(Into::into).collect(),
            applied_assigned,
            applied_residue,
        },
        StoredIdentityOpAction::Facet {
            entity,
            facets,
            reassignment,
            applied_assigned,
            applied_residue,
            forked,
        } => IdentityEventAction::Facet {
            entity,
            facets,
            reassignment_map: reassignment.entries.into_iter().map(Into::into).collect(),
            applied_assigned,
            applied_residue,
            forked,
        },
        StoredIdentityOpAction::AssertDistinct { a, b, claim } => {
            IdentityEventAction::AssertDistinct { a, b, claim }
        }
        StoredIdentityOpAction::Undo { target } => IdentityEventAction::Undo { target },
        StoredIdentityOpAction::ProposalCancellation {
            proposal,
            participant,
        } => IdentityEventAction::ProposalCancellation {
            proposal,
            participant,
        },
        StoredIdentityOpAction::ProposalResolution {
            proposal,
            outcome,
            scope,
            amended_body,
        } => IdentityEventAction::ProposalResolution {
            proposal,
            outcome: outcome.into(),
            op_kind: scope.op_kind.to_owned(),
            target_class: scope.target_class,
            proposer: scope.actor,
            amendment: amended_body
                .as_deref()
                .map(topology::decode_identity_op_amendment)
                .transpose()?
                .map(amendment_op)
                .transpose()?,
        },
        StoredIdentityOpAction::AdmissionDisposition(_)
        | StoredIdentityOpAction::AuthorAttribution { .. }
        | StoredIdentityOpAction::AuthorRedaction { .. } => {
            return Err(MemoryError::bad_request(
                "event must name a topology decision, not an admission or attribution sidecar",
            ));
        }
    };
    Ok(IdentityTopologyReceipt {
        event,
        seq: record.seq,
        at: record.at,
        actor: topology::effective_author_in_txn(&vault.store, txn, event)?
            .map(WriteActor::entity_ref),
        source: record.source,
        approval: record.approval,
        confidence: record.confidence,
        evidence: record.evidence.map(Into::into),
        action,
        seen: topology::topology_seal_revision_for_store_in_txn(&vault.store, txn, &event)?,
    })
}

/// The amendment codec carries structural data; evidence lives on the proposal.
fn amendment_op(op: IdentityTopologyOp) -> MemoryResult<IdentityAmendment> {
    match op {
        IdentityTopologyOp::Merge(op) => Ok(IdentityAmendment::Merge {
            sources: op.sources,
            survivor: op.survivor,
            survivorship_plan: IdentitySurvivorshipPlan::ReadThrough,
        }),
        IdentityTopologyOp::Split(op) => Ok(IdentityAmendment::Split {
            entity: op.entity,
            heads: op.heads,
            reassignment_map: op
                .reassignment
                .entries
                .into_iter()
                .map(Into::into)
                .collect(),
        }),
        IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => Err(
            MemoryError::bad_request("only merge and split may be amended"),
        ),
    }
}

fn result_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    outcome: IdentityOpOutcome,
) -> MemoryResult<IdentityTopologyResult> {
    Ok(match outcome {
        IdentityOpOutcome::Applied { event, transitions } => IdentityTopologyResult::Applied {
            receipt: event_receipt(vault, txn, event)?,
            transitions: transitions
                .into_iter()
                .map(|(entity, state)| IdentityTransition {
                    entity,
                    state: state.into(),
                })
                .collect(),
        },
        IdentityOpOutcome::Parked { event } => IdentityTopologyResult::Parked {
            receipt: event_receipt(vault, txn, event)?,
        },
        IdentityOpOutcome::Noop => IdentityTopologyResult::Noop,
    })
}

fn apply_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    op: IdentityTopologyOp,
    approval: ClaimApprovalStatus,
) -> MemoryResult<IdentityTopologyResult> {
    let mut txn = vault.store.env.write_txn().map_err(Error::from)?;
    let write = owner_write(vault, &txn, owner, approval)?;
    let outcome = vault.apply_identity_topology_op_as_in_txn(
        &mut txn,
        &op,
        &write,
        &owner_seal(owner),
        vault.now_recorded_at(),
    )?;
    let result = result_in_txn(vault, &txn, outcome)?;
    txn.commit().map_err(Error::from)?;
    Ok(result)
}

pub fn merge_identity_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityMergeRequest,
) -> MemoryResult<IdentityTopologyResult> {
    apply_as_owner(
        vault,
        owner,
        IdentityTopologyOp::Merge(input.into_engine()),
        ClaimApprovalStatus::Auto,
    )
}

pub fn split_identity_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentitySplitRequest,
) -> MemoryResult<IdentityTopologyResult> {
    apply_as_owner(
        vault,
        owner,
        IdentityTopologyOp::Split(input.into_engine()?),
        ClaimApprovalStatus::Auto,
    )
}

pub fn facet_identity_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityFacetRequest,
) -> MemoryResult<IdentityTopologyResult> {
    apply_as_owner(
        vault,
        owner,
        IdentityTopologyOp::Facet(input.into_engine()?),
        ClaimApprovalStatus::Auto,
    )
}

pub fn assert_distinct_identity_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityAssertDistinctRequest,
) -> MemoryResult<IdentityTopologyResult> {
    apply_as_owner(
        vault,
        owner,
        IdentityTopologyOp::AssertDistinct(topology::AssertDistinctOp {
            a: input.a,
            b: input.b,
            reason: input.reason,
        }),
        ClaimApprovalStatus::Auto,
    )
}

pub fn propose_identity_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityProposeRequest,
) -> MemoryResult<IdentityTopologyResult> {
    apply_as_owner(
        vault,
        owner,
        input.operation.into_engine()?,
        ClaimApprovalStatus::Proposed,
    )
}

pub fn undo_identity_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityUndoRequest,
) -> MemoryResult<IdentityTopologyResult> {
    let mut txn = vault.store.env.write_txn().map_err(Error::from)?;
    let write = owner_write(vault, &txn, owner, ClaimApprovalStatus::Auto)?;
    let seal = owner_seal(owner).with_seen(Some(input.seen));
    let outcome = vault.undo_identity_topology_event_in_txn(
        &mut txn,
        &input.event,
        &write,
        &seal,
        vault.now_recorded_at(),
    )?;
    let result = result_in_txn(vault, &txn, outcome)?;
    txn.commit().map_err(Error::from)?;
    Ok(result)
}

pub fn resolve_identity_proposal_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityProposalResolveRequest,
) -> MemoryResult<IdentityProposalResolutionResult> {
    let amendment = match &input.decision {
        IdentityProposalRuling::AmendThenApprove { operation } => Some(
            topology::encode_identity_op_amendment(&operation.clone().into_engine()?)?,
        ),
        IdentityProposalRuling::Approve | IdentityProposalRuling::Reject => None,
    };
    let ruling = match &input.decision {
        IdentityProposalRuling::Approve => topology::ProposalRuling::Approve,
        IdentityProposalRuling::Reject => topology::ProposalRuling::Reject,
        IdentityProposalRuling::AmendThenApprove { .. } => {
            topology::ProposalRuling::AmendThenApprove(
                amendment
                    .as_deref()
                    .ok_or(Error::InvariantViolation("identity amendment missing"))?,
            )
        }
    };
    let mut txn = vault.store.env.write_txn().map_err(Error::from)?;
    let write = owner_write(vault, &txn, owner, ClaimApprovalStatus::Approved)?;
    let seal = owner_seal(owner).with_seen(Some(input.seen));
    let (_, event, applied) = vault.resolve_identity_proposal_with_applied_in_txn(
        &mut txn,
        &input.proposal,
        ruling,
        &write,
        &seal,
        vault.now_recorded_at(),
    )?;
    let result = IdentityProposalResolutionResult {
        receipt: event_receipt(vault, &txn, event)?,
        applied: applied
            .map(|event| event_receipt(vault, &txn, event))
            .transpose()?,
    };
    txn.commit().map_err(Error::from)?;
    Ok(result)
}

pub fn identity_event_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityEventRequest,
) -> MemoryResult<IdentityTopologyReceipt> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    event_receipt(vault, &txn, input.event)
}

pub fn resolve_identity_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityEntityRequest,
) -> MemoryResult<IdentityResolution> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    if vault.get_entity_type_in_txn(&txn, &input.entity)?.is_none() {
        return Err(Error::EntityNotFound.into());
    }
    let peers = |kind| {
        vault.filtered_edge_peers(
            &txn,
            crate::ports::EdgeDirection::Out,
            &input.entity,
            kind,
            None,
        )
    };
    Ok(IdentityResolution {
        entity: input.entity,
        state: vault
            .entity_lifecycle_state_in_txn(&txn, &input.entity)?
            .into(),
        heads: vault.resolve_entity_in_txn(&txn, &input.entity)?,
        merged_into: peers(EdgeKind::MergedInto)?,
        split_into: peers(EdgeKind::SplitInto)?,
        facets: peers(EdgeKind::HasFacet)?,
        assigned_claims: vault.claims_assigned_to_in_txn(&txn, &input.entity)?,
        ambiguous_residue: vault.ambiguous_residue_claims_in_txn(&txn, &input.entity)?,
        remaining_claims: vault.claims_remaining_on_origin_in_txn(&txn, &input.entity)?,
    })
}

pub fn identity_pair_proposals_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: IdentityPairRequest,
) -> MemoryResult<IdentityPairProposals> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    Ok(IdentityPairProposals {
        a: input.a,
        b: input.b,
        proposals: vault.open_merge_proposals_for_pair_in_txn(&txn, &input.a, &input.b)?,
        distinct_claims: vault.distinct_claims_for_pair_in_txn(&txn, &input.a, &input.b)?,
    })
}
