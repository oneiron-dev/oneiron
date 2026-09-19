//! A judge outage is an open question, persisted through the shared write gate.
use super::{ConflictSet, PromotionCandidate, conflict_open_marker_id};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EntityId, Result, TimeRange,
    Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

pub(super) fn park_open_conflict(
    vault: &Vault,
    actor: WriteActor,
    attempt: crate::attempt_queue::AttemptId,
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    fence: &super::resources::ConsolidationFence,
    now: u64,
) -> Result<EntityId> {
    let id = conflict_open_marker_id(conflict, attempt);
    let refs: std::collections::BTreeSet<_> = members
        .iter()
        .flat_map(|c| c.evidence_turn_refs.iter().copied())
        .collect();
    for member in members {
        fence.evidence_source(member)?;
    }
    let evidence = super::encode_consolidation_evidence(&super::ConsolidationEvidenceEnvelope {
        refs: refs.into_iter().collect(),
        chain: Vec::new(),
        source_meet: ClaimSource::Generated,
    });
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("dreamer")),
            (
                Value::from("run"),
                Value::from(crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())),
            ),
        ]))?,
        ClaimApprovalStatus::Proposed,
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
    if let Some(facet) = conflict.identity.facet {
        candidate = candidate.with_scope(Value::Map(vec![(
            Value::from("facet_ref"),
            Value::Binary(facet.as_bytes().to_vec()),
        )]));
    }
    vault.with_write_txn(|txn| {
        fence.validate_in_txn(vault, txn)?;
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
