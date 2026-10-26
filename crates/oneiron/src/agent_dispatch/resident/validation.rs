//! A resident binding's validation: the rows it names, its inbox's actor,
//! its home message's conversation and each goal reference. A goal keeps
//! every axis, however many (rule 5): past its row (the count of 32 it once
//! refused past) the binding raises one check, and validates on.

use super::{ResidentAgentSpec, invalid};
use crate::Vault;
use crate::error::Result;
use crate::scan_check::{EngineScan, ScanCount};
use crate::task_verb::ConsultPayloadRef;

/// The goal axes past which a binding asks when its threshold row does not
/// read: the count it once refused past.
const RESIDENT_GOAL_AXES_CHECK: u64 = 32;

pub(super) fn validate(vault: &Vault, spec: &ResidentAgentSpec) -> Result<()> {
    if vault.get_entity_type(&spec.agent_def_ref)? != Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
        || vault.get_entity_type(&spec.home_conversation_ref)?
            != Some(crate::registry::ENTITY_TYPE_CONVERSATION)
        || vault.get_entity_type(&spec.home_message_ref)?
            != Some(crate::registry::ENTITY_TYPE_MESSAGE)
    {
        return Err(invalid());
    }
    observe_goal_axes(vault, spec);
    let facts = vault
        .channel_identity_facts(&spec.inbox_identity_ref)?
        .ok_or_else(invalid)?;
    if facts.binding.actor_ref() != Some(spec.agent_def_ref) {
        return Err(invalid());
    }
    let parents: Vec<_> = vault
        .edges_out(&spec.home_message_ref)?
        .into_iter()
        .filter(|edge| edge.kind == crate::edge::EdgeKind::BelongsTo)
        .collect();
    if parents.len() != 1 || parents[0].target != spec.home_conversation_ref {
        return Err(invalid());
    }
    for reference in std::iter::once(spec.goal.goal)
        .chain(std::iter::once(spec.goal.why))
        .chain(spec.goal.axes.iter().copied())
    {
        ConsultPayloadRef::parse(vault, &reference.short_ref())?;
    }
    Ok(())
}

/// Counts `spec`'s goal axes against the resident row, scoped to its agent
/// (FIX 9120). Evidence only: the threshold is read in a short snapshot of
/// its own, dropped before any other read, and nothing here fails the
/// binding.
fn observe_goal_axes(vault: &Vault, spec: &ResidentAgentSpec) {
    let scope = spec.agent_def_ref.as_bytes();
    let mut count = vault
        .store
        .env
        .read_txn()
        .ok()
        .and_then(|txn| {
            ScanCount::start(&vault.store, &txn, EngineScan::ResidentGoalAxes, scope).ok()
        })
        .unwrap_or_else(|| {
            ScanCount::start_at(
                EngineScan::ResidentGoalAxes,
                scope,
                RESIDENT_GOAL_AXES_CHECK,
            )
        });
    count.rows(spec.goal.axes.len());
    count.defer(&vault.store);
}
