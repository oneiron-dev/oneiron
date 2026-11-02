//! A reviewed topology event's effective state (FIX 9966): its verdict from
//! the effective ledger's resolution and cancellation, never the immutable
//! `Proposed` flag alone, and the event an approved proposal's undo names.
//! `topology_outcome_in_txn` is its call surface.

use super::*;
use crate::claim::ClaimApprovalStatus;
use crate::identity_topology::{
    IdentityTopologyAction, IdentityTopologyEvent, IdentityTopologyFold, ProposalOutcome,
    StoredIdentityOpAction, StoredIdentityOpEvent, fold_identity_topology_log,
};

/// What the effective ledger says of one reviewed topology event.
pub(super) struct TopologyOutcome {
    pub(super) verdict: RunChangeVerdict,
    /// The ledger event an undo reverts: a directly applied event itself,
    /// or the op event an approving ruling applied for a proposal, as its
    /// resolution records it. None for a proposal still open, rejected or
    /// cancelled, or whose resolution names no applied event.
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
                applied: applied_by_ruling(vault, txn, (&effective, &fold), id)?,
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

/// The op event the ruling that approved `proposal` applied, as that
/// ruling's resolution records it (FIX 9966): the proposal's first effective
/// resolution in the fold's `(seq, event_id)` order, which is the one the
/// fold kept. `None` when that resolution names no applied event.
fn applied_by_ruling(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    (effective, fold): (&[IdentityTopologyEvent], &IdentityTopologyFold),
    proposal: EntityId,
) -> MemoryResult<Option<EntityId>> {
    let rejected: std::collections::BTreeSet<EntityId> =
        fold.rejections.iter().map(|(event, _)| *event).collect();
    let Some(resolution) = effective
        .iter()
        .filter(|event| {
            matches!(
                event.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            ) && !rejected.contains(&event.event_id)
                && matches!(
                    &event.action,
                    IdentityTopologyAction::ResolveProposal { proposal: resolved, .. }
                        if *resolved == proposal
                )
        })
        .min_by_key(|event| (event.seq, event.event_id))
    else {
        return Ok(None);
    };
    let record = vault
        .identity_topology_event_in_txn(txn, &resolution.event_id)?
        .ok_or_else(|| MemoryError::not_found("topology resolution is absent"))?;
    Ok(match record.action {
        StoredIdentityOpAction::ProposalResolution { applied, .. } => applied,
        _ => None,
    })
}
