//! Which puts hand an agent definition back authority it gave up.
//!
//! Three switches on a stored definition decide whether its agent runs:
//! `enabled`, `approval_status` and `lifecycle_status` (the dispatcher and the
//! gate's live ceiling read all three). Turning a definition off, rejecting it
//! or retracting it is open to any writer. Turning it back on is the owner's:
//! a writer below owner grade, or a federation peer, may not re-enable,
//! re-approve or reactivate a definition, nor bring a deleted one back on.
//!
//! The models a definition runs on are the owner's too (FIX 4472): its
//! `models` list, `compaction_model`, `model_tier` and `dreaming_model`. A
//! model choice decides which provider reads the agent's context, so a change
//! that leaves the grant the definition holds, clearing a choice included, is
//! the owner's. A change within it is any writer's (FIX 9558): the list
//! narrowed to models it already names, or the compaction model moved to one
//! of them.

use super::codec::decode_agent_definition;
use super::id_pin::is_agent_id_in_txn;
use super::types::AgentDefinition;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::ModelId;
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
/// definition on, moves its approval up, makes it active again, or takes a
/// model choice outside the grant `prior` holds. `None` is an agent id whose
/// row was deleted, which holds none.
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
        || prior.map_or(has_model_choice(updated), |prior| {
            !models_within_grant(prior, updated)
        })
}

/// Whether `updated`'s model choices stay within the grant `prior` holds
/// (FIX 9558): its list the same, or a non-empty list of models `prior`
/// lists (each entry's `when` reworded or not); its compaction model the
/// same, or one `prior` lists; its tier and dreaming model the same. A
/// cleared choice falls back to the house route, outside the grant.
fn models_within_grant(prior: &AgentDefinition, updated: &AgentDefinition) -> bool {
    let listed = |model: &ModelId| prior.models.iter().any(|entry| entry.model_ref == *model);
    let models = updated.models == prior.models
        || (!updated.models.is_empty()
            && updated.models.iter().all(|entry| listed(&entry.model_ref)));
    let compaction = match (&updated.compaction_model, &prior.compaction_model) {
        (None, None) => true,
        (Some(model), held) => held.as_ref() == Some(model) || listed(model),
        (None, Some(_)) => false,
    };
    models
        && compaction
        && updated.model_tier == prior.model_tier
        && updated.dreaming_model == prior.dreaming_model
}

/// Whether a definition names any model choice of its own.
fn has_model_choice(def: &AgentDefinition) -> bool {
    !def.models.is_empty()
        || def.compaction_model.is_some()
        || def.model_tier.is_some()
        || def.dreaming_model.is_some()
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
