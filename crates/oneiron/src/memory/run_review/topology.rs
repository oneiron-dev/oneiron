//! A reviewed topology event's effective state (FIX 9966): its verdict from
//! the effective ledger's resolution and cancellation, never the immutable
//! `Proposed` flag alone, and the event an approved proposal's undo names.
//! `topology_outcome_in_txn` is its call surface.

use super::*;
use crate::claim::ClaimApprovalStatus;
use crate::identity_topology::{
    IdentityTopologyAction, IdentityTopologyEvent, IdentityTopologyOp, ProposalOutcome,
    StoredIdentityOpAction, StoredIdentityOpEvent, decode_identity_op_amendment,
    fold_identity_topology_log,
};

/// What the effective ledger says of one reviewed topology event.
pub(super) struct TopologyOutcome {
    pub(super) verdict: RunChangeVerdict,
    /// The ledger event an undo reverts: a directly applied event itself,
    /// or the op event an approving ruling applied for a proposal. None for
    /// a proposal still open, rejected, cancelled, or whose applied event
    /// this ledger does not hold.
    pub(super) applied: Option<EntityId>,
}

/// `event` (stored under `id`) as the effective fold reads it now. A direct
/// event keeps today's answer: it landed when it was written. A proposal
/// waits until the fold retires it: an approving ruling landed it, a
/// rejection or a participant-delete cancellation did not.
pub(super) fn topology_outcome_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    event: &StoredIdentityOpEvent,
) -> MemoryResult<TopologyOutcome> {
    if event.approval != ClaimApprovalStatus::Proposed {
        return Ok(TopologyOutcome {
            verdict: RunChangeVerdict::Landed,
            applied: Some(id),
        });
    }
    let effective = vault.fold_effective_identity_topology_events_in_txn(txn)?;
    let fold = fold_identity_topology_log(&effective);
    Ok(match fold.resolved_proposals.get(&id) {
        Some(ProposalOutcome::ApprovedUntouched | ProposalOutcome::ApprovedAmended) => {
            TopologyOutcome {
                verdict: RunChangeVerdict::Landed,
                applied: applied_by_ruling(vault, txn, &effective, id, event)?,
            }
        }
        Some(ProposalOutcome::Rejected) => TopologyOutcome {
            verdict: RunChangeVerdict::Rejected,
            applied: None,
        },
        None if fold.moot_proposals.contains(&id) => TopologyOutcome {
            verdict: RunChangeVerdict::Rejected,
            applied: None,
        },
        None => TopologyOutcome {
            verdict: RunChangeVerdict::Waiting,
            applied: None,
        },
    })
}

/// The op event the ruling that approved `proposal` applied. The ruling
/// writes that event and then its resolution in one transaction, so it is
/// the effective op event of the approved op's kind and participants
/// nearest before the proposal's first effective resolution, in the fold's
/// `(seq, event_id)` order. The approved op is the proposal's own, or the
/// amendment its resolution carries.
fn applied_by_ruling(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    effective: &[IdentityTopologyEvent],
    proposal: EntityId,
    proposed: &StoredIdentityOpEvent,
) -> MemoryResult<Option<EntityId>> {
    let mut ordered: Vec<&IdentityTopologyEvent> = effective
        .iter()
        .filter(|event| {
            matches!(
                event.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
        })
        .collect();
    ordered.sort_by_key(|event| (event.seq, event.event_id));
    let Some(at) = ordered.iter().position(|event| {
        matches!(
            &event.action,
            IdentityTopologyAction::ResolveProposal { proposal: resolved, .. } if *resolved == proposal
        )
    }) else {
        return Ok(None);
    };
    let resolution = vault
        .identity_topology_event_in_txn(txn, &ordered[at].event_id)?
        .ok_or_else(|| MemoryError::not_found("topology resolution is absent"))?;
    let approved = match &resolution.action {
        StoredIdentityOpAction::ProposalResolution {
            amended_body: Some(body),
            ..
        } => decode_identity_op_amendment(body).ok(),
        _ => match proposed.action.to_fold_action() {
            IdentityTopologyAction::Apply(op) => Some(op),
            _ => None,
        },
    };
    let Some(approved) = approved else {
        return Ok(None);
    };
    let shape = op_shape(&approved);
    Ok(ordered[..at]
        .iter()
        .rev()
        .find(|event| {
            matches!(&event.action, IdentityTopologyAction::Apply(op) if op_shape(op) == shape)
        })
        .map(|event| event.event_id))
}

/// An op's kind and its participants as a set: what an applied event and
/// the ruling that applied it both name.
fn op_shape(op: &IdentityTopologyOp) -> (std::mem::Discriminant<IdentityTopologyOp>, Vec<EntityId>) {
    let mut participants = op.participants();
    participants.sort_unstable();
    (std::mem::discriminant(op), participants)
}
