//! Explicit graph-unit backfill for a standing question. The host supplies a typed
//! judgment; the engine pins its receipt and lands the kept claim atomically.

use super::super::types::invalid;
use super::{records::*, store::*};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::llm::decision::{DecisionAnswer, DecisionReceipt, ProviderPin, TypedDecision};
use crate::{
    ClaimCandidate, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};

/// One explicit backfill result over a graph unit. Model execution and artifact
/// landing belong to their adapters; this door never runs a model or grants access.
#[derive(Debug, Clone)]
pub struct StandingAnswer {
    pub unit: EntityId,
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    pub evidence: Vec<EntityId>,
    pub providers: Vec<ProviderPin>,
}

/// Keep one backfilled answer for an immutable question version. A retry at
/// the same source frontier returns the first receipt; a changed unit may be
/// refreshed without editing the question. Explicit backfill is allowed while
/// automatic refresh is paused.
pub fn backfill_standing_answer(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    expected_version: u32,
    actor: WriteActor,
    input: StandingAnswer,
    now: u64,
) -> Result<AnswerRecord> {
    vault.with_write_txn(|txn| {
        let mut head = owned_head(vault, txn, principal, question)?;
        if head.version != expected_version {
            return Err(Error::ConcurrentWrite("standing question changed"));
        }
        let record: QuestionRecord = load(
            vault,
            txn,
            &key(question, b"version", &expected_version.to_be_bytes()),
        )?
        .ok_or(Error::EntityNotFound)?;
        if record.schema_version != 1 {
            return Err(invalid("unsupported question schema"));
        }
        record.definition.validate()?;
        if !record.definition.units.contains(&input.unit)
            || !record.definition.question.contract.accepts(&input.answer)
            || matches!(input.answer, DecisionAnswer::Abstain)
            || input
                .probability
                .is_some_and(|p| !p.is_finite() || !(0.0..=1.0).contains(&p))
            || input.evidence.len() > 4096
            || input.providers.len() > 64
            || input.providers.iter().any(|pin| {
                pin.model.is_empty()
                    || pin.version.is_empty()
                    || pin.rung < record.definition.dial.first
                    || pin.rung > record.definition.dial.ceiling
            })
        {
            return Err(invalid("invalid standing answer"));
        }
        let (source_kind, source) = super::task_ask::validate_task_answer_unit(
            vault,
            txn,
            principal,
            actor.entity_ref(),
            input.unit,
        )?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        let reader = crate::claim::ScopedReadActorKey::new(principal.to_hex())
            .ok_or(Error::InvariantViolation("canonical question principal"))?;
        let holder = crate::claim::ScopedReadActorKey::new(actor.entity_ref().to_hex())
            .ok_or(Error::InvariantViolation("canonical question actor"))?;
        for evidence in &input.evidence {
            if !super::arrival::readable(&vault.store, txn, &policy, &reader, evidence)?
                || !super::arrival::readable(&vault.store, txn, &policy, &holder, evidence)?
            {
                return Err(Error::EntityNotFound);
            }
        }
        let frontier = *blake3::hash(&source).as_bytes();
        let dedup = key(
            question,
            b"backfill",
            &[
                expected_version.to_be_bytes().as_slice(),
                input.unit.as_bytes(),
                &[source_kind],
                &frontier,
            ]
            .concat(),
        );
        if let Some(claim) = load::<EntityIdBytes>(vault, txn, &dedup)? {
            return load(vault, txn, &key(question, b"answer", &claim.0))?
                .ok_or(Error::CorruptedIndex("standing backfill answer"));
        }
        let answer = AnswerRecord {
            claim: EntityId::now(),
            unit: input.unit,
            decision: TypedDecision {
                in_band: input
                    .probability
                    .is_some_and(|p| record.definition.dial.band.contains(p)),
                answer: input.answer,
                probability: input.probability,
                evidence: input.evidence,
                receipt: DecisionReceipt {
                    question,
                    question_version: expected_version,
                    principal,
                    providers: input.providers,
                    band: record.definition.dial.band,
                },
                human_ask: None,
            },
            frontier,
            source_kind,
            answered_at: now,
        };
        let encoded = encode(&answer)?;
        let value = rmpv::decode::read_value(&mut encoded.as_slice())
            .map_err(|_| Error::CorruptedIndex("standing answer encoding"))?;
        let mut candidate = ClaimCandidate::new(
            "judgment.answer",
            ClaimSubject::Entity(input.unit),
            value.clone(),
            1.0,
        );
        let mut taint = ClaimSource::Imported;
        if source_kind == crate::registry::ENTITY_TYPE_CLAIM {
            let body = crate::claim::decode_claim_body(&source, true)?;
            taint = body.source.unwrap_or(ClaimSource::Imported);
            if let Some(inherited) = crate::claim::claim_evidence_taint(&body) {
                taint = crate::dreamer_consolidation::source_meet(taint, inherited);
            }
            if let Some(scope) = body.scope {
                candidate = candidate.with_scope(scope);
            }
            if let Some(world) = body.world {
                candidate = candidate.with_world(world);
            }
        }
        candidate = candidate
            .with_evidence_taint(taint)?
            .with_private_reader(principal)?
            .with_evidence(rmpv::Value::Array(vec![rmpv::Value::from(
                input.unit.to_hex(),
            )]));
        let envelope = WriteEnvelope::new(
            actor,
            crate::dreamer_consolidation::source_meet(ClaimSource::Generated, taint),
            WriteProvenance::new(value)?,
            ClaimApprovalStatus::Proposed,
        );
        vault
            .batch_in()
            .claim_candidate(
                &answer.claim,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply(txn)?;
        put(
            vault,
            txn,
            &key(question, b"answer", answer.claim.as_bytes()),
            &answer,
        )?;
        put(vault, txn, &dedup, &EntityIdBytes(*answer.claim.as_bytes()))?;
        head.last_refresh = Some(now);
        put(vault, txn, &key(question, b"head", &[]), &head)?;
        Ok(answer)
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EntityIdBytes([u8; 16]);
