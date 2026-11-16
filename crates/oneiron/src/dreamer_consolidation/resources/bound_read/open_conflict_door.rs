//! Native's open-conflict marker for parity tests.
//!
//! Rebuilds the bound inputs as the routing door does, opens the same branch
//! and assembles with real `assemble_extracted`. The one judge set is then
//! parked open through the branch's own `park_open_conflict` under its write
//! fence, as native parks a set its ladder leaves open, or built without
//! writing so a test can compare the marker another path wrote. No model is
//! asked, so the marker carries its members' own decisions and no verdict's.

use serde_json::{Value, json};

use super::super::BranchResources;
use super::extraction_routing_door::{bound_inputs, door_request};
use crate::WriteActor;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation as consolidation;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// One native conflict assembled for a door: the branch, the attempt, the
/// set, its members, their joined decisions, and the operands' claim ids in
/// operand order (to align member order for byte comparison).
struct AssembledConflict<'a> {
    /// The branch the set assembled on, for the parking write's fence.
    resources: &'a BranchResources<'a>,
    /// The attempt's Dreamer actor.
    actor: WriteActor,
    /// The bound attempt.
    attempt: AttemptId,
    /// The one assembled set.
    conflict: &'a consolidation::ConflictSet,
    /// The set's members in native assembly order.
    members: Vec<&'a consolidation::evidence::VerifiedCandidate>,
    /// The members' joined decisions.
    decisions: Vec<consolidation::KeptDecision>,
    /// The operands' claim ids in operand order.
    operand_order: Vec<EntityId>,
}

/// Runs `finish` over the one native conflict `operands_json` form on the
/// bound attempt at `now_ms`: the bound inputs, the branch, the real
/// assembly, the set's members and their joined decisions. Both doors share
/// this body; only their finish differs. Operands that form no conflict, or
/// more than one, are refused before `finish` runs.
///
/// # Errors
///
/// The vault's, operands the bound read refuses, and operands that form no
/// native conflict or more than one.
fn with_assembled_conflict<R>(
    vault: &Vault,
    attempt_hex: &str,
    now_ms: u64,
    operands_json: &[Value],
    finish: impl FnOnce(AssembledConflict<'_>) -> Result<R>,
) -> Result<R> {
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
    finish(AssembledConflict {
        resources: &resources,
        actor,
        attempt: attempt_id,
        conflict,
        members,
        decisions,
        operand_order: inputs.claims,
    })
}

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
    with_assembled_conflict(vault, attempt_hex, now_ms, operands_json, |assembled| {
        let AssembledConflict {
            resources,
            actor,
            attempt,
            conflict,
            members,
            decisions,
            ..
        } = assembled;
        resources.require_output(resources.scope())?;
        resources.park_open_conflict(
            vault, actor, attempt, conflict, &members, &decisions, now_ms,
        )?;
        let marker = consolidation::conflict_open_marker_id(conflict, attempt)?;
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
    })
}

/// Builds, without writing, the marker the one native conflict
/// `operands_json` form on the bound attempt at `now_ms` would park, and
/// returns it with its set as JSON.
///
/// Output holds the marker id, the member claims in operand order, the set's
/// prior heads, and the marker claim's predicate, subject, value and
/// evidence envelope: the value and the envelope as lowercase hex of their
/// encoded bytes. A test commits the same operands through another path and
/// compares byte for byte. Member choice is native's. Member order follows
/// the operands, not native's selection rank: a path that orders members by
/// pack position stores native's bytes only when its pack lists them in
/// selection order, and this door re-sorts native's members so that a test
/// compares the two under one order (native's own marker test sorts members
/// before it compares them).
/// Operands that form no conflict, or more than one, are refused.
///
/// # Errors
///
/// As `park_open_conflict_json`, and a marker claim that does not encode.
pub(crate) fn build_open_conflict_json(
    vault: &Vault,
    attempt_hex: &str,
    now_ms: u64,
    operands_json: &[Value],
) -> Result<Value> {
    with_assembled_conflict(vault, attempt_hex, now_ms, operands_json, |assembled| {
        let AssembledConflict {
            actor,
            attempt,
            conflict,
            decisions,
            operand_order,
            mut members,
            ..
        } = assembled;
        members.sort_by_key(|member| {
            operand_order
                .iter()
                .position(|id| *id == member.claim_id)
                .unwrap_or(usize::MAX)
        });
        let provenance =
            consolidation::open_conflict::native_marker_provenance(attempt, &decisions)?;
        let parts = consolidation::open_conflict::open_marker_parts(
            actor, attempt, conflict, &members, provenance, now_ms,
        )?;
        let body = consolidation::candidate_probe_body(&parts.candidate)?;
        let crate::ClaimSubject::Entity(subject) = body.subject else {
            return Err(Error::InvalidConfig(
                "a native conflict marker names no entity subject".to_owned(),
            ));
        };
        let mut value_bytes = Vec::new();
        rmpv::encode::write_value(&mut value_bytes, &body.value).map_err(|_| {
            Error::InvalidConfig("a native conflict marker value does not encode".to_owned())
        })?;
        let evidence = parts
            .candidate
            .evidence()
            .cloned()
            .unwrap_or(rmpv::Value::Nil);
        let mut evidence_bytes = Vec::new();
        rmpv::encode::write_value(&mut evidence_bytes, &evidence).map_err(|_| {
            Error::InvalidConfig(
                "a native conflict marker evidence envelope does not encode".to_owned(),
            )
        })?;
        Ok(json!({
            "marker": parts.id.to_hex(),
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
            "predicate": body.predicate,
            "subject": subject.to_hex(),
            "value_hex": crate::entity_id::bytes_to_hex_lower(&value_bytes),
            "evidence_hex": crate::entity_id::bytes_to_hex_lower(&evidence_bytes),
        }))
    })
}
