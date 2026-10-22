//! Durable branch restriction alongside a partition payload, not a partition
//! or consolidation identity axis. Trusted callers supply exact resource rights.

use super::partition::{ConsolidationPartitionPlan, encode_partition_payload};
use super::support::invalid_consolidation;
use crate::Result;
use crate::llm::Scope;
use crate::side_table::{self, LegacyJson, SideTable};
use rmpv::Value;

/// Pinned effective scope attenuation bound to one Dreamer attempt, inherited by retry
/// successors. Key: id16 (the attempt id).
const SELECTION_SCOPE: SideTable<[u8; 16], Option<Scope>, LegacyJson> =
    SideTable::new(&side_table::DREAMER_SELECTION_SCOPE);

pub(super) const KEY_BRANCH_SCOPE: &str = "branch_scope";

impl ConsolidationPartitionPlan {
    /// Exact output resource for this ordered, queued TURN slice: its
    /// one-part branch's.
    pub fn output_resource(&self) -> crate::llm::ScopeResource {
        self.branch().output_resource()
    }

    /// Exact graph/vector signals projection for this TURN slice. Reading it
    /// still requires actor authority and the accompanying four-axis scope.
    pub fn signals_resource(&self) -> crate::llm::ScopeResource {
        self.branch().signals_resource()
    }

    /// Exact stored gap projection for this partition and branch slice.
    pub fn gap_resource(&self, scope: &Scope) -> crate::llm::ScopeResource {
        super::gap::branch_gap_projection(&self.branch(), scope)
    }

    /// Bind a queued branch to the caller's exact scope. Project and relationship
    /// slice its resources; project never changes the partition identity. Each
    /// candidate still carries its sources' project in its claim identity.
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
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    queued: Option<Scope>,
    caller: Option<&Scope>,
) -> Result<Option<Scope>> {
    match (queued, caller) {
        (Some(parent), Some(child)) => attenuate(vault, txn, &parent, child.clone()).map(Some),
        (Some(parent), None) => Ok(Some(parent)),
        (None, caller) => Ok(caller.cloned()),
    }
}

/// `child` under `parent`: a child project proven in `txn` to descend from
/// the parent's narrows it too, as agent dispatch admits it (FIX 8999). A
/// project that does not read is no proof, so nothing admitted before
/// changes.
fn attenuate(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    parent: &Scope,
    child: Scope,
) -> Result<Scope> {
    parent.attenuate_with(child, |project, ancestor| {
        crate::agent_dispatch::project_descends_from_in_txn(vault, txn, project, ancestor)
    })
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
    let txn = vault.store.env.read_txn()?;
    let inherited = if let Some(parent) = parent {
        let bound = stored_parent_scope(vault, &txn, parent)?;
        effective_scope(vault, &txn, Some(bound), queued.as_ref())?
    } else {
        queued
    };
    effective_scope(vault, &txn, inherited, caller)
}

fn stored_parent_scope(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
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
            .get_in_txn(txn, id)?
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
        bound = attenuate(vault, txn, &bound, child)?;
    }
    Ok(bound)
}

/// Reconstruct exact durable scope at the wake's one read revision. A saved
/// caller attenuation and parent chain supply rights only by narrowing.
pub(super) fn execution_scope_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    attempt: crate::attempt_queue::AttemptId,
    parent: Option<crate::attempt_queue::AttemptId>,
    queued: Option<Scope>,
    caller: Option<&Scope>,
) -> Result<Option<Scope>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut chain = Vec::new();
    let mut cursor = parent;
    let mut recipe_root = false;
    while let Some(id) = cursor {
        if !seen.insert(*id.as_bytes()) {
            return Err(invalid_consolidation("cyclic branch scope lineage"));
        }
        let row = crate::attempt_queue::AttemptQueue::new(vault)
            .get_in_txn(txn, id)?
            .ok_or_else(|| invalid_consolidation("branch parent is missing"))?;
        let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&row.payload)?;
        if row.kind == crate::dreamer_runner::DreamerConsolidationScope::Macro.attempt_kind()
            && payload.attempt_type == crate::dreamer_wake::nightly::CONTINUE_ATTEMPT
            && payload.parent_attempt.is_some()
            && vault.dreamer_attempt_authority_in_txn(txn, id)?.is_some()
        {
            cursor = payload.parent_attempt;
            continue;
        }
        // A Timer wake's plan parent (FIX 336) only groups the children it
        // planned: they take what its own parent bounds, and with none, no
        // inherited bound, as under a recipe receipt.
        if row.kind == crate::dreamer_runner::DreamerConsolidationScope::Macro.attempt_kind()
            && payload.attempt_type == crate::dreamer_wake::nightly::PLAN_ATTEMPT
            && vault.dreamer_attempt_authority_in_txn(txn, id)?.is_some()
        {
            if payload.parent_attempt.is_none() {
                recipe_root = true;
                break;
            }
            cursor = payload.parent_attempt;
            continue;
        }
        if row.kind == crate::dreamer_runner::DREAMER_RECIPE_WAKE_ATTEMPT_KIND
            && payload.attempt_type == crate::dreamer_runner::DREAMER_RECIPE_WAKE_ATTEMPT_KIND
            && payload.parent_attempt.is_none()
            && vault.dreamer_attempt_authority_in_txn(txn, id)?.is_some()
        {
            // This engine-owned root only groups independently admitted work.
            // It is not an agent branch supplying inherited resource rights.
            recipe_root = true;
            break;
        }
        let bound = if payload.attempt_type == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
            crate::agent_dispatch::decode_agent_dispatch_input(&payload.input)?.scope
        } else if [
            crate::dreamer_runner::DreamerConsolidationScope::Micro,
            crate::dreamer_runner::DreamerConsolidationScope::Meso,
            crate::dreamer_runner::DreamerConsolidationScope::Macro,
        ]
        .into_iter()
        .any(|scope| row.kind == scope.attempt_kind() && payload.attempt_type == scope.as_str())
        {
            decode_branch_scope(&payload.input)?
        } else {
            chain.push(Some(Scope::default()));
            break;
        };
        chain.push(bound);
        cursor = payload.parent_attempt;
    }
    let inherited = if recipe_root {
        let mut bound = None;
        for child in chain.into_iter().rev() {
            bound = effective_scope(vault, txn, bound, child.as_ref())?;
        }
        effective_scope(vault, txn, bound, queued.as_ref())?
    } else if parent.is_some() {
        let mut bound = chain.pop().flatten().unwrap_or_default();
        for child in chain.into_iter().rev().flatten() {
            bound = attenuate(vault, txn, &bound, child)?;
        }
        effective_scope(vault, txn, Some(bound), queued.as_ref())?
    } else {
        queued
    };
    let stored = SELECTION_SCOPE
        .get(&vault.store, txn, attempt.as_bytes())?
        .flatten();
    let bound = effective_scope(vault, txn, inherited, caller)?;
    effective_scope(vault, txn, stored, bound.as_ref())
}

/// Persist a caller's attenuation before work can produce a scheduled retry.
/// Queue payloads stay immutable; this private bound follows the retry chain.
pub(super) fn pin_execution_scope(
    vault: &crate::Vault,
    attempt: crate::attempt_queue::AttemptId,
    requested: Option<&Scope>,
) -> Result<Option<Scope>> {
    vault.with_write_txn_grouped(|txn| {
        let stored = SELECTION_SCOPE
            .get(&vault.store, txn, attempt.as_bytes())?
            .flatten();
        let effective = effective_scope(vault, txn, stored, requested)?;
        SELECTION_SCOPE.put(&vault.store, txn, attempt.as_bytes(), &effective)?;
        Ok(effective)
    })
}

pub(crate) fn inherit_retry_scope_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    source: crate::attempt_queue::AttemptId,
    successor: crate::attempt_queue::AttemptId,
) -> Result<()> {
    if let Some(scope) = SELECTION_SCOPE.get(&vault.store, txn, source.as_bytes())? {
        SELECTION_SCOPE.put(&vault.store, txn, successor.as_bytes(), &scope)?;
    }
    Ok(())
}
