//! Native's open-conflict marker and resolution builds for parity tests.
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

/// Runs `finish` over native assembly of `operands_json` on the bound
/// attempt at `now_ms`: the bound inputs, the branch, the real assembly,
/// and the operands' claim ids in operand order. The conflict doors and
/// the candidate door share this body; only their finish differs.
///
/// # Errors
///
/// The vault's, and operands the bound read refuses.
pub(super) fn with_native_assembly<R>(
    vault: &Vault,
    attempt_hex: &str,
    now_ms: u64,
    operands_json: &[Value],
    finish: impl FnOnce(
        AttemptId,
        WriteActor,
        &BranchResources<'_>,
        consolidation::assembly::AssembledCandidates,
        Vec<EntityId>,
    ) -> Result<R>,
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
    finish(attempt_id, actor, &resources, assembled, inputs.claims)
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
    with_native_assembly(
        vault,
        attempt_hex,
        now_ms,
        operands_json,
        |attempt_id, actor, resources, assembled, claims| {
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
                resources,
                actor,
                attempt: attempt_id,
                conflict,
                members,
                decisions,
                operand_order: claims,
            })
        },
    )
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

/// Seals the one resolution `output` as native would, prepares it with
/// native provenance without writing, and returns the prepared claim as
/// JSON: the fields the candidate door answers plus the replaced head.
///
/// The seal must hold exactly one write and no attachment; anything else
/// is refused before any preparation.
fn prepare_one_resolution_json(
    vault: &Vault,
    attempt_id: AttemptId,
    actor: WriteActor,
    resources: &BranchResources<'_>,
    output: consolidation::evidence::VerifiedCandidate,
    now_ms: u64,
) -> Result<Value> {
    let write = resources.prepare_write_verified(resources.scope(), vec![output])?;
    if write.candidates.len() != 1 || !write.attachments.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "the resolution seals to {} writes and {} attachments, not one write",
            write.candidates.len(),
            write.attachments.len()
        )));
    }
    let mut writes = write.candidates.into_iter();
    let candidate = writes
        .next()
        .ok_or_else(|| Error::InvalidConfig("the sealed write names no candidate".to_owned()))?;
    let supersedes = candidate.supersedes;
    let mut evidences = write.candidate_evidence.into_iter();
    let evidence = evidences
        .next()
        .ok_or_else(|| Error::InvalidConfig("the sealed write names no evidence".to_owned()))?;
    let run = crate::dreamer_promotion::DreamerRunContext {
        run_id: crate::entity_id::bytes_to_hex_lower(attempt_id.as_bytes()),
        attempt_id,
        agent_actor: actor,
        now_ms,
    };
    let txn = vault.store.env.read_txn()?;
    let (prepared, claim_candidate) = crate::dreamer_promotion::prepare_promotion(
        vault,
        &txn,
        &run,
        candidate,
        Some(&evidence),
        &[],
        None,
    )
    .map_err(|rejection| {
        Error::InvalidConfig(format!(
            "native promotion refused with kind {:?}",
            rejection.kind
        ))
    })?;
    let default_facet = vault.default_facet_in_txn(&txn)?;
    let candidate_evidence = claim_candidate
        .evidence()
        .cloned()
        .unwrap_or(rmpv::Value::Nil);
    let mut evidence_bytes = Vec::new();
    rmpv::encode::write_value(&mut evidence_bytes, &candidate_evidence).map_err(|_| {
        Error::InvalidConfig("a native resolution evidence envelope does not encode".to_owned())
    })?;
    let body = claim_candidate.into_claim_body(&prepared.envelope, default_facet)?;
    let crate::ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidConfig(
            "a native resolution names no entity subject".to_owned(),
        ));
    };
    let mut value_bytes = Vec::new();
    rmpv::encode::write_value(&mut value_bytes, &body.value).map_err(|_| {
        Error::InvalidConfig("a native resolution value does not encode".to_owned())
    })?;
    let scope_hex = body
        .scope
        .as_ref()
        .map(|scope| -> Result<String> {
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, scope).map_err(|_| {
                Error::InvalidConfig("a native resolution scope does not encode".to_owned())
            })?;
            Ok(crate::entity_id::bytes_to_hex_lower(&bytes))
        })
        .transpose()?;
    Ok(json!({
        "claim": prepared.claim_id.to_hex(),
        "predicate": body.predicate,
        "subject": subject.to_hex(),
        "value_hex": crate::entity_id::bytes_to_hex_lower(&value_bytes),
        "scope_hex": scope_hex,
        "source": body.source.map(|source| source.as_str().to_owned()),
        "confidence": body.confidence,
        "world": body.world.map(|world| world.to_hex()),
        "relationship": body.rel.as_ref().map(|rel| {
            rel.iter().map(EntityId::to_hex).collect::<Vec<_>>()
        }),
        "facet": body.scope_facet.to_hex(),
        "project": body.scope_project.to_hex(),
        "candidate_evidence_hex": crate::entity_id::bytes_to_hex_lower(&evidence_bytes),
        "occurred": {"start": prepared.occurred.start, "end": prepared.occurred.end},
        "learned_at": prepared.learned_at,
        "approval": body.approval.as_str(),
        "supersedes": supersedes.map(|head| head.to_hex()),
    }))
}

/// Builds, without writing, the claim native's merge of the one native
/// conflict `operands_json` form on the bound attempt at `now_ms` would
/// land with kept member `kept` and merged value `value`, and returns it
/// as JSON.
///
/// `kept` names the kept member as an index into `operands_json` in
/// operand order; it must name a member of the one set. `value` is the
/// merged value as JSON and must not be null; it converts as the stager's
/// does. The set is rebuilt as the routing door rebuilds it, the kept
/// selection is recomputed with native's matching priors, and the merged
/// candidate is built with no decisions, sealed with real
/// `prepare_write_verified` for that one output, and prepared with real
/// `prepare_promotion` under native provenance, without writing, so a test
/// can compare the claim another path wrote. No model is asked.
///
/// Output holds what the candidate door answers plus the replaced head:
/// the claim id, the predicate, subject, value, scope, source, confidence,
/// world, relationship, facet and project from the prepared claim body,
/// the candidate evidence, the validity window, the learned time, the
/// approval the envelope asks, and `supersedes` as the replaced head's hex
/// or null when the merge replaces no head. Provenance is native's and is
/// not compared: the other path stamps its own.
///
/// Operands that form anything but exactly one native conflict, a `kept`
/// outside the operands or outside the one set, a null `value`, or an
/// output that seals to anything but exactly one plain write, are refused
/// before any preparation.
///
/// # Errors
///
/// The vault's, operands the bound read refuses, operands that form
/// anything but one native conflict, a kept member the set does not name,
/// a null value, an output that seals to anything but one write, a native
/// promotion refusal, and a claim that does not encode.
pub(crate) fn build_native_merge_json(
    vault: &Vault,
    attempt_hex: &str,
    now_ms: u64,
    operands_json: &[Value],
    kept: usize,
    value: &Value,
) -> Result<Value> {
    if value.is_null() {
        return Err(Error::InvalidConfig(
            "a merge needs a value that is not null".to_owned(),
        ));
    }
    let merged_value = consolidation::json_to_rmpv(value);
    with_native_assembly(
        vault,
        attempt_hex,
        now_ms,
        operands_json,
        |attempt_id, actor, resources, assembled, claims| {
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
            let kept_claim = claims.get(kept).ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "kept names operand {kept} of {} operands, not one",
                    claims.len()
                ))
            })?;
            let selected = consolidation::recompute_kept_selection(
                conflict,
                &members,
                *kept_claim,
                resources.key_rules(),
                |member| resources.matching_priors(member, resources.key_rules()),
            )?;
            let mut priors = Vec::with_capacity(selected.prior_heads.len());
            for head in &selected.prior_heads {
                priors.push(resources.prior(*head)?.clone());
            }
            let merged = consolidation::merged_candidate(
                &selected,
                &members,
                &priors,
                merged_value,
                Vec::new(),
                attempt_id,
                now_ms,
            )?;
            prepare_one_resolution_json(vault, attempt_id, actor, resources, merged, now_ms)
        },
    )
}

/// Builds, without writing, the claim native's skip of the one native
/// conflict `operands_json` form on the bound attempt at `now_ms` would
/// land, and returns it as JSON.
///
/// The set is rebuilt as the routing door rebuilds it, and native's skip
/// rule is checked on that set: `fast_path` on the vault policy, or
/// `bound_correction` on native's own correction map. The one member is
/// stamped with the supplied `confidence` by the shared member builder.
/// With the set's prior head as its `supersedes`, it is sealed with real
/// `prepare_write_verified` for that one output and prepared with real
/// `prepare_promotion` under native provenance, without writing, so a test
/// can compare the claim another path wrote. No model is asked.
///
/// Output holds what the candidate door answers plus the replaced head,
/// as the merge build does; `supersedes` is always the prior head's hex.
/// Provenance is native's and is not compared: the other path stamps its
/// own.
///
/// Operands that form anything but exactly one native conflict, a set
/// native's skip rule refuses, or an output that seals to anything but
/// exactly one plain write, are refused before any preparation.
///
/// # Errors
///
/// The vault's, operands the bound read refuses, operands that form
/// anything but one native conflict, a set native's skip rule refuses, an
/// output that seals to anything but one write, a native promotion
/// refusal, and a claim that does not encode.
pub(crate) fn build_native_skip_json(
    vault: &Vault,
    attempt_hex: &str,
    now_ms: u64,
    operands_json: &[Value],
    confidence: f32,
) -> Result<Value> {
    with_native_assembly(
        vault,
        attempt_hex,
        now_ms,
        operands_json,
        |attempt_id, actor, resources, assembled, _claims| {
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
            let prior = conflict
                .prior_head
                .map(|head| resources.prior(head))
                .transpose()?;
            let member_data: Vec<&consolidation::PromotionCandidate> =
                members.iter().map(|member| &member.proposal).collect();
            // The read ends with the policy: the seal and the preparation
            // below open their own, and this store allows one a thread.
            let policy = {
                let policy_txn = vault.store.env.read_txn()?;
                crate::gate::resolve_policy_manifest(&vault.store, &policy_txn)?
            };
            let allowed = consolidation::fast_path(&policy, conflict, &member_data, prior)
                || consolidation::bound_correction(
                    &assembled.corrections,
                    conflict,
                    &member_data,
                    prior,
                );
            if !allowed {
                return Err(Error::InvalidConfig(
                    "native's skip rule refuses this set: neither fast_path nor bound_correction holds"
                        .to_owned(),
                ));
            }
            let mut output = (*members[0]).clone();
            output.proposal.candidate =
                crate::derive::member_candidate(&output.proposal.candidate, confidence, &[])?;
            output.proposal.supersedes = conflict.prior_head;
            prepare_one_resolution_json(vault, attempt_id, actor, resources, output, now_ms)
        },
    )
}
