//! Persistent contradiction markers and prior-head context for consolidation.
use super::conflict::deterministic_claim_id;
#[cfg(test)]
use super::conflict::{ConflictSet, PriorHead, conflict_open_marker_id};
use super::provenance::{PromotionCandidate, source_meet};
use super::support::{TURN_BODY_FACET_REF_KEY, invalid_consolidation};
use crate::claim::{
    ClaimSource, ClaimSubject, PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED,
    claim_evidence_taint,
};
use crate::error::Result;
use crate::write_envelope::ClaimCandidate;
use crate::{EntityId, Vault};
use rmpv::Value;

pub(super) fn identity_scope(identity: &super::conflict::ConflictIdentity) -> Result<Value> {
    let mut fields = Vec::new();
    if let Some(facet) = identity.facet {
        fields.push((
            Value::from(TURN_BODY_FACET_REF_KEY),
            Value::Binary(facet.as_bytes().to_vec()),
        ));
    }
    if let Some(topic) = &identity.topic {
        let value = rmpv::decode::read_value(&mut topic.as_slice())
            .map_err(|_| invalid_consolidation("conflict topic key"))?;
        fields.push((Value::from("topic_key"), value));
    }
    Ok(Value::Map(fields))
}

#[cfg(test)]
pub(super) fn open_marker(
    conflict: &ConflictSet,
    members: &[&PromotionCandidate],
    priors: &[PriorHead],
    attempt: crate::attempt_queue::AttemptId,
    now: u64,
) -> Result<PromotionCandidate> {
    let mut evidence = std::collections::BTreeSet::new();
    let mut meet = ClaimSource::Generated;
    let mut chain = Vec::new();
    for member in members {
        evidence.extend(member.evidence_turn_refs.iter().copied());
        meet = source_meet(meet, member.evidence_meet);
        for hop in &member.provenance_chain {
            if !chain.contains(hop) {
                chain.push(*hop);
            }
        }
    }
    for prior in priors
        .iter()
        .filter(|p| conflict.prior_heads.contains(&p.claim_id))
    {
        meet = source_meet(
            meet,
            claim_evidence_taint(&prior.body)
                .or(prior.body.source)
                .unwrap_or(ClaimSource::Generated),
        );
    }
    let value = Value::Map(vec![
        (
            Value::from("predicate"),
            Value::from(conflict.identity.predicate.as_str()),
        ),
        (
            Value::from("topic_key"),
            conflict
                .identity
                .topic
                .as_ref()
                .map_or(Value::Nil, |v| Value::Binary(v.clone())),
        ),
        (
            Value::from("members"),
            Value::Array(
                members
                    .iter()
                    .map(|c| Value::Binary(c.claim_id.as_bytes().to_vec()))
                    .collect(),
            ),
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
    ]);
    let mut candidate = ClaimCandidate::new(
        PREDICATE_CONFLICT_OPEN,
        ClaimSubject::Entity(conflict.identity.subject),
        value,
        1.0,
    )
    .with_scope(identity_scope(&conflict.identity)?);
    if let Some(rel) = conflict.identity.rel {
        candidate = candidate.with_relationship(rel);
    }
    if let Some(world) = conflict.identity.world {
        candidate = candidate.with_world(world);
    }
    Ok(PromotionCandidate {
        claim_id: conflict_open_marker_id(conflict, attempt)?,
        candidate,
        evidence_turn_refs: evidence.into_iter().collect(),
        provenance_chain: chain,
        supersedes: None,
        evidence_meet: meet,
        occurred: crate::TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
    })
}

/// Records an explicit close as an ordinary gated promotion claim. The open
/// marker remains as audit evidence; replays of this run use the same id.
pub fn close_persistent_conflict(
    vault: &Vault,
    run: &crate::dreamer_promotion::DreamerRunContext,
    open: EntityId,
    resolution: Value,
    evidence_refs: Vec<EntityId>,
) -> Result<crate::dreamer_promotion::PromotionOutcome> {
    let body = vault
        .get_claim(&open)?
        .ok_or(invalid_consolidation("conflict marker not found"))?;
    if body.predicate != PREDICATE_CONFLICT_OPEN {
        return Err(invalid_consolidation("not an open conflict marker"));
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid_consolidation("conflict subject"));
    };
    let value = Value::Map(vec![
        (
            Value::from("open_marker"),
            Value::Binary(open.as_bytes().to_vec()),
        ),
        (Value::from("resolution"), resolution),
    ]);
    let claim_id = deterministic_claim_id(
        run.attempt_id,
        subject,
        PREDICATE_CONFLICT_RESOLVED,
        &Value::Binary(open.as_bytes().to_vec()),
        body.world,
        None,
        body.rel,
        super::conflict::topic_key(body.scope.as_ref())?.as_deref(),
    )?;
    let meet = source_meet(
        ClaimSource::Generated,
        claim_evidence_taint(&body)
            .or(body.source)
            .unwrap_or(ClaimSource::Generated),
    );
    let mut candidate = ClaimCandidate::new(PREDICATE_CONFLICT_RESOLVED, body.subject, value, 1.0);
    if let Some(scope) = body.scope {
        candidate = candidate.with_scope(scope);
    }
    if let Some(rel) = body.rel {
        candidate = candidate.with_relationship(rel);
    }
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    crate::dreamer_promotion::promote_consolidated_claims(
        vault,
        run,
        vec![PromotionCandidate {
            claim_id,
            candidate,
            evidence_turn_refs: evidence_refs,
            provenance_chain: Vec::new(),
            supersedes: None,
            evidence_meet: meet,
            occurred: crate::TimeRange {
                start: run.now_ms,
                end: run.now_ms,
            },
            learned_at: run.now_ms,
        }],
    )
}
