//! Native's open-conflict marker for parity tests.
//!
//! Rebuilds the bound inputs as the routing door does, opens the same branch
//! and assembles with real `assemble_extracted`. The one judge set is then
//! parked open through the branch's own `park_open_conflict` under its write
//! fence, as native parks a set its ladder leaves open. No model is asked, so
//! the marker carries its members' own decisions and no verdict's.

use serde_json::{Value, json};

use super::super::BranchResources;
use super::extraction_routing_door::{bound_inputs, door_request};
use crate::dreamer_consolidation as consolidation;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Parks the one native conflict `operands_json` form on the bound attempt
/// at `now_ms`, and returns the marker with its set as JSON.
///
/// Output holds the marker id, the member claims in set order, and the
/// set's prior heads. Operands that form no conflict, or more than one, are
/// refused before any write.
pub(crate) fn park_open_conflict_json(
    vault: &Vault,
    attempt_hex: &str,
    now_ms: u64,
    operands_json: &[Value],
) -> Result<Value> {
    let (attempt_id, operands) = door_request(attempt_hex, operands_json)?;
    let actor = vault.dreamer_actor_for_attempt(attempt_id)?;
    let inputs = bound_inputs(vault, &actor, attempt_id, &operands, now_ms)?;
    let resources = BranchResources::open_branch(
        vault,
        actor,
        &inputs.branch,
        attempt_id,
        Some(&inputs.scope),
        None,
        Some(&inputs.known),
    )?;
    let assembled =
        consolidation::assembly::assemble_extracted(vault, &resources, inputs.extracted, now_ms)?;
    let [conflict] = assembled.conflicts.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "the operands form {} native conflicts, not one",
            assembled.conflicts.len()
        )));
    };
    let mut members = Vec::with_capacity(conflict.candidate_indexes.len());
    for index in &conflict.candidate_indexes {
        let member = assembled.candidates.get(*index).ok_or_else(|| {
            Error::InvalidConfig("a native conflict names a missing candidate".to_owned())
        })?;
        members.push(member);
    }
    let mut decisions = Vec::new();
    for member in &members {
        consolidation::provenance::join_decisions(&mut decisions, &member.decisions);
    }
    resources.require_output(resources.scope())?;
    resources.park_open_conflict(
        vault, actor, attempt_id, conflict, &members, &decisions, now_ms,
    )?;
    let marker = consolidation::conflict_open_marker_id(conflict, attempt_id)?;
    Ok(json!({
        "marker": marker.to_hex(),
        "members": members
            .iter()
            .map(|member| member.claim_id.to_hex())
            .collect::<Vec<_>>(),
        "prior_heads": conflict
            .prior_heads
            .iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>(),
        "prior_head": conflict.prior_head.as_ref().map(EntityId::to_hex),
    }))
}
