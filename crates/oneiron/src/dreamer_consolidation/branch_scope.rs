//! Durable branch restriction alongside a partition payload, not a partition
//! or consolidation identity axis. Trusted callers supply exact resource rights.

use super::partition::{ConsolidationPartitionPlan, encode_partition_payload};
use super::support::invalid_consolidation;
use crate::Result;
use crate::llm::Scope;
use rmpv::Value;

pub(super) const KEY_BRANCH_SCOPE: &str = "branch_scope";

impl ConsolidationPartitionPlan {
    /// Exact output resource for this ordered, queued TURN slice.
    pub fn output_resource(&self) -> crate::llm::ScopeResource {
        let turns: Vec<_> = self.turns.iter().map(|turn| turn.turn_id).collect();
        super::resources::output_projection(&self.key, &turns)
    }

    /// Exact graph/vector signals projection for this TURN slice. Reading it
    /// still requires actor authority and the accompanying four-axis scope.
    pub fn signals_resource(&self) -> crate::llm::ScopeResource {
        let turns: Vec<_> = self.turns.iter().map(|turn| turn.turn_id).collect();
        super::resources::signals_projection(&self.key, &turns)
    }

    /// Exact stored gap projection for this partition and branch slice.
    pub fn gap_resource(&self, scope: &Scope) -> crate::llm::ScopeResource {
        super::gap::branch_gap_projection(&self.key, scope)
    }

    /// Bind a queued branch to the caller's exact scope. Project and relationship
    /// slice its resources; project never changes the consolidation identity.
    pub fn scoped_input(&self, scope: &Scope) -> Result<Value> {
        if scope.world != self.key.world_ref || scope.facet != self.key.facet_ref {
            return Err(invalid_consolidation(
                "queued scope does not match partition",
            ));
        }
        let Value::Map(mut entries) = encode_partition_payload(self) else {
            unreachable!("partition payload is a map");
        };
        let json = serde_json::to_string(scope)
            .map_err(|_| invalid_consolidation("cannot encode branch scope"))?;
        entries.push((Value::from(KEY_BRANCH_SCOPE), Value::from(json)));
        Ok(Value::Map(entries))
    }
}

pub(crate) fn decode_branch_scope(value: &Value) -> Result<Option<Scope>> {
    // Queue routing also carries non-partition jobs. Their opaque input cannot
    // carry this map key and grants no branch scope; partition decoding remains
    // strict at its own door.
    let Value::Map(entries) = value else {
        return Ok(None);
    };
    let mut scope = None;
    for (key, value) in entries {
        if key.as_str() == Some(KEY_BRANCH_SCOPE) {
            if scope.is_some() {
                return Err(invalid_consolidation("duplicate branch scope"));
            }
            let json = value
                .as_str()
                .ok_or_else(|| invalid_consolidation("invalid branch scope"))?;
            scope = Some(
                serde_json::from_str(json)
                    .map_err(|_| invalid_consolidation("invalid branch scope"))?,
            );
        }
    }
    Ok(scope)
}

pub(super) fn effective_scope(
    queued: Option<Scope>,
    caller: Option<&Scope>,
) -> Result<Option<Scope>> {
    match (queued, caller) {
        (Some(parent), Some(child)) => parent.attenuate(child.clone()).map(Some),
        (Some(parent), None) => Ok(Some(parent)),
        (None, caller) => Ok(caller.cloned()),
    }
}

/// The real queue parent is an upper bound too. Missing scope on a parent is
/// deny-all, never permission to regenerate a broader grant from a child model's
/// partition payload. Non-branch maintenance parents grant no branch rights.
pub(super) fn resolve_scope(
    vault: &crate::Vault,
    parent: Option<crate::attempt_queue::AttemptId>,
    queued: Option<Scope>,
    caller: Option<&Scope>,
) -> Result<Option<Scope>> {
    let inherited = if let Some(parent) = parent {
        effective_scope(Some(stored_parent_scope(vault, parent)?), queued.as_ref())?
    } else {
        queued
    };
    effective_scope(inherited, caller)
}

fn stored_parent_scope(
    vault: &crate::Vault,
    parent: crate::attempt_queue::AttemptId,
) -> Result<Scope> {
    let mut seen = std::collections::BTreeSet::new();
    let mut chain = Vec::new();
    let mut cursor = Some(parent);
    while let Some(id) = cursor {
        if !seen.insert(*id.as_bytes()) {
            return Err(invalid_consolidation("cyclic branch scope lineage"));
        }
        let record = crate::attempt_queue::AttemptQueue::new(vault)
            .get(id)?
            .ok_or_else(|| invalid_consolidation("branch parent is missing"))?;
        let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload)?;
        let own_scope = if payload.attempt_type
            == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
        {
            crate::agent_dispatch::decode_agent_dispatch_input(&payload.input)?.scope
        } else if [
            crate::dreamer_runner::DreamerConsolidationScope::Micro,
            crate::dreamer_runner::DreamerConsolidationScope::Meso,
            crate::dreamer_runner::DreamerConsolidationScope::Macro,
        ]
        .into_iter()
        .any(|scope| record.kind == scope.attempt_kind() && payload.attempt_type == scope.as_str())
        {
            decode_branch_scope(&payload.input)?
        } else {
            // A non-branch job does not relay resource authority from elsewhere.
            chain.push(Some(Scope::default()));
            break;
        };
        chain.push(own_scope);
        cursor = payload.parent_attempt;
    }
    let mut bound = chain.pop().flatten().unwrap_or_default();
    for child in chain.into_iter().rev().flatten() {
        bound = bound.attenuate(child)?;
    }
    Ok(bound)
}
