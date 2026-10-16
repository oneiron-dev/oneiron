//! Which puts hand an agent definition back authority it gave up.
//!
//! Three switches on a stored definition decide whether its agent runs:
//! `enabled`, `approval_status` and `lifecycle_status` (the dispatcher and the
//! gate's live ceiling read all three). Turning a definition off, rejecting it
//! or retracting it is open to any writer. Turning it back on is the owner's:
//! a writer below owner grade, or a federation peer, may not re-enable,
//! re-approve or reactivate a definition, nor bring a deleted one back on.

use super::codec::decode_agent_definition;
use super::id_pin::is_agent_id_in_txn;
use super::types::AgentDefinition;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Approval from least to most authority: rejected, proposed, approved, auto.
const fn approval_rank(status: ClaimApprovalStatus) -> u8 {
    match status {
        ClaimApprovalStatus::Rejected => 0,
        ClaimApprovalStatus::Proposed => 1,
        ClaimApprovalStatus::Approved => 2,
        ClaimApprovalStatus::Auto => 3,
    }
}

/// Whether `updated` gives back authority `prior` does not hold: it turns the
/// definition on, moves its approval up, or makes it active again. `None` is
/// an agent id whose row was deleted, which holds none.
fn widens(prior: Option<&AgentDefinition>, updated: &AgentDefinition) -> bool {
    let (enabled, approval, active) = prior.map_or(
        (false, approval_rank(ClaimApprovalStatus::Rejected), false),
        |prior| {
            (
                prior.enabled,
                approval_rank(prior.approval_status),
                prior.lifecycle_status == ClaimLifecycleStatus::Active,
            )
        },
    );
    (updated.enabled && !enabled)
        || approval_rank(updated.approval_status) > approval
        || (updated.lifecycle_status == ClaimLifecycleStatus::Active && !active)
}

/// Whether a put of `body` at `id` widens the definition stored there, read
/// in `txn`. A put at an id that was never an agent's is a create, not a
/// widening; a put over another entity type is the put arm's to refuse.
pub(crate) fn agent_definition_put_widens_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    let updated = decode_agent_definition(body)?;
    match live_entity_row_in_txn(store, txn, id)? {
        LiveEntityRow::Live { entity_type, body } if entity_type == ENTITY_TYPE_AGENT_DEF => {
            Ok(widens(Some(&decode_agent_definition(&body)?), &updated))
        }
        LiveEntityRow::Live { .. } => Ok(false),
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            Ok(is_agent_id_in_txn(store, txn, id)? && widens(None, &updated))
        }
    }
}
