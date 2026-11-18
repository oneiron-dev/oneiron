//! Native extraction routing choices for parity tests.
//!
//! Read-only: rebuilds the bound projection, verifies operands through the
//! bound stored mapping, opens the same branch with the bound scope and
//! listing, assembles with real `assemble_extracted`, then seals outside-set
//! writes with real `prepare_write_verified`. Held and judged members never
//! enter the sealed write. Scope is assembly corrections, judge queue,
//! prior routing and outside writes only; no executor decisions.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::super::BranchResources;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation as consolidation;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;
use crate::verbs::CandidateOperand;

fn bad(message: String) -> Error {
    Error::InvalidConfig(message)
}

/// Holds the bound branch, scope, listing and verified rows for native assembly.
pub(super) struct BoundRoutingInputs {
    pub(super) branch: consolidation::branch::QueuedBranch,
    pub(super) scope: oneiron_model::llm::Scope,
    pub(super) known: consolidation::neighbourhood::Neighbourhood,
    pub(super) claims: Vec<EntityId>,
    pub(super) extracted: Vec<consolidation::evidence::ExtractedCandidate>,
}

/// Decodes a door call: the attempt as 32 lowercase hex digits and each
/// operand as the bound verdict's candidate operand.
pub(super) fn door_request(
    attempt_hex: &str,
    operands_json: &[Value],
) -> Result<(AttemptId, Vec<CandidateOperand>)> {
    let attempt_entity =
        EntityId::from_hex(attempt_hex).map_err(|error| bad(format!("bad attempt: {error:?}")))?;
    if attempt_entity.to_hex() != attempt_hex {
        return Err(bad("attempt must be 32 lowercase hex digits".to_owned()));
    }
    let attempt_id = AttemptId::from_bytes(attempt_entity.as_bytes())
        .map_err(|error| bad(format!("bad attempt: {error:?}")))?;
    let mut operands = Vec::with_capacity(operands_json.len());
    for operand in operands_json {
        let decoded: CandidateOperand = serde_json::from_value(operand.clone())
            .map_err(|error| bad(format!("bad operand: {error}")))?;
        operands.push(decoded);
    }
    Ok((attempt_id, operands))
}

/// Returns native routing for `operands` on the bound attempt at `now_ms` as JSON.
///
/// Output holds the original operands, the clock, pack-order claims, native
/// ready and held claims, judge sets with prior heads, every correction
/// including held ones, and outside-set write choices only.
pub(crate) fn routing_choices_json(
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
    let mut grouped_ids = BTreeMap::new();
    for row in &inputs.extracted {
        let proposal = row.proposal();
        let key = (
            consolidation::routing::candidate_keys(proposal, resources.key_rules())?,
            proposal.supersedes,
        );
        grouped_ids.entry(key).or_insert(proposal.claim_id);
    }
    let all_grouped: BTreeSet<EntityId> = grouped_ids.into_values().collect();
    let assembled =
        consolidation::assembly::assemble_extracted(vault, &resources, inputs.extracted, now_ms)?;
    let corrections: Vec<Value> = assembled
        .corrections
        .iter()
        .map(|(claim, head)| json!({"claim": claim.to_hex(), "head": head.to_hex()}))
        .collect();
    let ready_claims: Vec<EntityId> = assembled
        .candidates
        .iter()
        .map(|row| row.claim_id)
        .collect();
    let ready_set: BTreeSet<EntityId> = ready_claims.iter().copied().collect();
    let held: Vec<String> = all_grouped
        .difference(&ready_set)
        .map(|id| id.to_hex())
        .collect();
    let mut judged: BTreeSet<usize> = BTreeSet::new();
    let mut judge_sets = Vec::new();
    for conflict in &assembled.conflicts {
        for index in &conflict.candidate_indexes {
            judged.insert(*index);
        }
        judge_sets.push(json!({
            "candidate_claims": conflict.candidate_indexes.iter()
                .map(|index| assembled.candidates[*index].claim_id.to_hex())
                .collect::<Vec<_>>(),
            "prior_heads": conflict.prior_heads.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
            "prior_head": conflict.prior_head.map(|id| id.to_hex()),
        }));
    }
    let mut outside = Vec::new();
    for (index, verified) in assembled.candidates.into_iter().enumerate() {
        if judged.contains(&index) {
            continue;
        }
        outside.push(verified);
    }
    let choices = write_choices(&resources, outside)?;
    Ok(json!({
        "operands": operands_json,
        "now_ms": now_ms,
        "candidates": inputs.claims.iter().enumerate().map(|(index, id)| {
            json!({"index": index, "claim": id.to_hex()})
        }).collect::<Vec<_>>(),
        "ready": ready_claims.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
        "held": held,
        "judge_sets": judge_sets,
        "corrections": corrections,
        "choices": choices,
    }))
}

/// Projects the real sealed handoff into ordered outside-set write choices.
fn write_choices(
    resources: &BranchResources<'_>,
    outside: Vec<consolidation::evidence::VerifiedCandidate>,
) -> Result<Vec<Value>> {
    let outside_ids: Vec<EntityId> = outside.iter().map(|candidate| candidate.claim_id).collect();
    let write = resources.prepare_write_verified(resources.scope(), outside)?;
    let mut by_claim: BTreeMap<EntityId, Value> = BTreeMap::new();
    for candidate in &write.candidates {
        by_claim.insert(
            candidate.claim_id,
            json!({
                "claim": candidate.claim_id.to_hex(),
                "kind": "new",
                "head": null,
                "supersedes": candidate.supersedes.map(|id| id.to_hex()),
            }),
        );
    }
    for (head, candidate, _) in &write.attachments {
        by_claim.insert(
            candidate.claim_id,
            json!({
                "claim": candidate.claim_id.to_hex(),
                "kind": "attach",
                "head": head.to_hex(),
                "supersedes": null,
            }),
        );
    }
    for id in &outside_ids {
        by_claim.entry(*id).or_insert_with(|| {
            json!({
                "claim": id.to_hex(),
                "kind": "already_represented",
                "head": null,
                "supersedes": null,
            })
        });
    }
    let choices: Vec<Value> = outside_ids
        .iter()
        .filter_map(|id| by_claim.get(id).cloned())
        .collect();
    Ok(choices)
}

/// Reads the bound branch, scope, listing and stored-locator rows.
///
/// Each operand is checked and bound-verified in one read snapshot, so masked
/// spans map to stored bytes exactly; the verified locators then back native
/// rows without any served-coordinate shortcut. The scope and listing are the
/// bound projection's own, so branch opening admits the same priors.
pub(super) fn bound_inputs(
    vault: &Vault,
    actor: &crate::write_envelope::WriteActor,
    attempt_id: AttemptId,
    operands: &[CandidateOperand],
    now_ms: u64,
) -> Result<BoundRoutingInputs> {
    use consolidation::evidence::{EvidenceLocator, ExtractedCandidate};
    let memory = vault.memory(actor.entity_ref(), EdgeActorClass::System);
    let read = consolidation::turn_text::dreamer_read(vault)?;
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let (branch, bound) = consolidation::extraction_pack::check_extraction_operands_in_txn(
        &memory, &read, &txn, None, attempt_id, operands, None,
    )
    .map_err(|error| bad(format!("routing door refused: {error:?}")))?;
    let checked = consolidation::extraction_pack::check_pack_candidates(
        operands, &bound, attempt_id, &branch,
    )?;
    let scope = bound.scope().clone();
    let known = bound.neighbourhood.clone();
    let mut claims = Vec::with_capacity(checked.rows.len());
    let mut extracted = Vec::with_capacity(checked.rows.len());
    for (operand, row) in operands.iter().zip(&checked.rows) {
        claims.push(row.proposal.claim_id);
        let verified = bound
            .verify_observation_candidate_in_txn(
                &memory,
                &read,
                &txn,
                operand,
                &row.proposal,
                now_ms,
            )
            .map_err(|error| bad(format!("routing door refused: {error:?}")))?;
        let mut locators = Vec::with_capacity(verified.evidence.locators().len());
        for reference in verified.evidence.locators() {
            if let Some(claim) = reference.claim_id {
                locators.push(EvidenceLocator::claim(reference.source_id, claim)?);
            } else if let Some((start, end)) = reference.byte_range {
                locators.push(EvidenceLocator::turn_range(
                    reference.source_id,
                    start,
                    end,
                )?);
            } else {
                return Err(bad("whole turn locator needs stored length".to_owned()));
            }
        }
        let mut row = ExtractedCandidate::new(verified.proposal, locators)?;
        if let Some(corrects) = operand.corrects.as_ref() {
            let head = consolidation::extraction_pack::parse_reference(corrects)?;
            row = row.correcting(head);
        }
        extracted.push(row);
    }
    Ok(BoundRoutingInputs {
        branch,
        scope,
        known,
        claims,
        extracted,
    })
}
