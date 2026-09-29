//! A judge outage is an open question, persisted through the shared write gate.
use super::evidence::{VerifiedCandidate, VerifiedEvidenceSet};
use super::{ConflictSet, conflict_open_marker_id};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EntityId, Result,
    SourceLineage, TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

pub(super) fn park_open_conflict(
    vault: &Vault,
    actor: WriteActor,
    attempt: crate::attempt_queue::AttemptId,
    conflict: &ConflictSet,
    members: &[&VerifiedCandidate],
    fence: &super::resources::ConsolidationFence,
    now: u64,
) -> Result<EntityId> {
    let id = conflict_open_marker_id(conflict, attempt)?;
    let mut verified: Option<VerifiedEvidenceSet> = None;
    for member in members {
        verified = Some(verified.map_or_else(
            || member.evidence.clone(),
            |old| old.union(&member.evidence),
        ));
    }
    let verified = verified
        .ok_or_else(|| super::support::invalid_consolidation("open conflict has no evidence"))?;
    let meet = verified.meet();
    let evidence = verified.envelope(Vec::new());
    let envelope = WriteEnvelope::with_lineage(
        actor,
        meet,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("dreamer")),
            (
                Value::from("run"),
                Value::from(crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())),
            ),
        ]))?,
        ClaimApprovalStatus::Proposed,
        SourceLineage::of(ClaimSource::Generated).with(meet),
    );
    let mut candidate = ClaimCandidate::new(
        crate::claim::PREDICATE_CONFLICT_OPEN,
        ClaimSubject::Entity(conflict.identity.subject),
        Value::Map(vec![
            (
                Value::from("predicate"),
                if members.iter().all(|member| {
                    super::conflict::candidate_facts(&member.candidate)
                        .is_ok_and(|facts| facts.predicate == conflict.identity.predicate)
                }) {
                    Value::from(conflict.identity.predicate.clone())
                } else {
                    Value::Nil
                },
            ),
            (
                Value::from("predicates"),
                Value::Array(
                    members
                        .iter()
                        .map(|member| {
                            super::conflict::candidate_facts(&member.candidate)
                                .map(|facts| Value::from(facts.predicate))
                        })
                        .collect::<Result<Vec<_>>>()?,
                ),
            ),
            (
                Value::from("prior_head"),
                conflict
                    .prior_head
                    .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
            ),
            (
                Value::from("prior_heads"),
                Value::Array(
                    conflict
                        .prior_heads
                        .iter()
                        .map(|id| Value::Binary(id.as_bytes().to_vec()))
                        .collect(),
                ),
            ),
            (
                Value::from("candidates"),
                Value::Array(
                    members
                        .iter()
                        .map(|c| Value::Binary(c.claim_id.as_bytes().to_vec()))
                        .collect(),
                ),
            ),
        ]),
        1.0,
    )
    .with_evidence(evidence);
    if let Some(world) = conflict.identity.world {
        candidate = candidate.with_world(world);
    }
    if let Some(rel) = conflict.identity.rel {
        candidate = candidate.with_relationship(rel);
    }
    candidate = candidate
        .with_scope(super::persistence::identity_scope(&conflict.identity)?)
        .with_evidence_taint(meet)?;
    vault.with_write_txn(|txn| {
        fence.validate_in_txn(vault, txn)?;
        let mut envelope = envelope.clone();
        vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(id)
}
