//! Transactional tasks.ask adapter to the shared versioned question substrate.

use super::{arrival, records::*, store::*};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject, ScopedReadActorKey};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionReceipt, DecisionRung, TypedDecision,
};
use crate::{
    ClaimCandidate, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};

pub(crate) struct TaskAnswerBinding<'a> {
    pub(crate) task: EntityId,
    pub(crate) principal: EntityId,
    pub(crate) unit: EntityId,
    pub(crate) question: &'a serde_json::Value,
    pub(crate) binding: &'a OutcomeBinding,
    pub(crate) now: u64,
}

/// The caller holds the first-answer CAS transaction. An ask has exactly one
/// immutable version, keyed by its TASK id, and one receipt-bearing claim.
/// Its prediction is the submitted result reference, not a model probability:
/// probability=1 records a definite selection by the winning holder.
pub(crate) fn bind_task_answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    input: TaskAnswerBinding<'_>,
) -> Result<AnswerRecord> {
    if load::<QuestionHead>(vault, txn, &key(input.task, b"head", &[]))?.is_some() {
        return Err(Error::ConcurrentWrite("ask question already bound"));
    }
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    for principal in [input.principal, actor.entity_ref()] {
        let reader = ScopedReadActorKey::new(principal.to_hex()).expect("canonical principal");
        if !arrival::readable(&vault.store, txn, &policy, &reader, &input.unit)? {
            return Err(Error::EntityNotFound);
        }
    }
    let raw = vault
        .store
        .entities
        .get(txn, input.unit.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("ask result header"))?;
    // Custody records are not decision evidence even in a default-open vault.
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
        return Err(Error::EntityNotFound);
    }
    let source = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    let choice = input.unit.to_hex();
    let band = DecisionBand::default();
    let record = QuestionRecord {
        schema_version: 1,
        principal: input.principal,
        definition: QuestionDefinition {
            question: DecisionQuestion {
                id: input.task,
                version: 1,
                text: input.question.to_string(),
                class: DecisionClass::Judgment,
                contract: AnswerContract::Choice {
                    options: vec![choice.clone()],
                },
                accept_type: false,
            },
            adapter: "tasks.ask".into(),
            units: vec![input.unit],
            recipe: "tasks.ask.v1".into(),
            profile: "holder-selection".into(),
            dial: DecisionDial {
                first: DecisionRung::Human,
                ceiling: DecisionRung::Human,
                band,
            },
            refresh: RefreshPolicy {
                on_arrival: true,
                every_seconds: None,
            },
            delivery: "tasks.wait".into(),
            learning: true,
            binding: Some(input.binding.clone()),
        },
        created_at: input.now,
    };
    record.definition.validate()?;
    let answer = AnswerRecord {
        claim: EntityId::now(),
        unit: input.unit,
        decision: TypedDecision {
            answer: DecisionAnswer::Choice(choice),
            probability: Some(1.0),
            evidence: vec![input.unit],
            in_band: false,
            receipt: DecisionReceipt {
                question: input.task,
                question_version: 1,
                principal: input.principal,
                providers: Vec::new(),
                band,
            },
            human_ask: None,
        },
        frontier: *blake3::hash(&source).as_bytes(),
        source_kind: header.entity_type,
        answered_at: input.now,
    };
    let encoded = encode(&answer)?;
    let value = rmpv::decode::read_value(&mut encoded.as_slice())
        .map_err(|_| Error::CorruptedIndex("ask answer encoding"))?;
    let mut candidate = ClaimCandidate::new(
        "judgment.answer",
        ClaimSubject::Entity(input.unit),
        value.clone(),
        1.0,
    );
    let mut taint = ClaimSource::Imported;
    if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
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
        .with_private_reader(input.principal)?;
    candidate = candidate.with_evidence(rmpv::Value::Array(vec![rmpv::Value::from(
        input.unit.to_hex(),
    )]));
    let envelope = WriteEnvelope::new(
        actor,
        crate::dreamer_consolidation::source_meet(ClaimSource::Generated, taint),
        WriteProvenance::new(value)?,
        ClaimApprovalStatus::Proposed,
    );
    let at = TimeRange {
        start: input.now,
        end: input.now,
    };
    vault
        .batch_in()
        .claim_candidate(&answer.claim, candidate, &envelope, at, input.now)
        .apply(txn)?;
    put(
        vault,
        txn,
        &key(input.task, b"version", &1_u32.to_be_bytes()),
        &record,
    )?;
    put(
        vault,
        txn,
        &key(input.task, b"head", &[]),
        &QuestionHead {
            version: 1,
            paused: false,
            last_refresh: Some(input.now),
        },
    )?;
    put(
        vault,
        txn,
        &key(input.task, b"answer", answer.claim.as_bytes()),
        &answer,
    )?;
    arrival::watch(&vault.store, txn, &record)?;
    Ok(answer)
}
