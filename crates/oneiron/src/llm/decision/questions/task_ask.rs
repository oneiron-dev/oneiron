//! Transactional tasks.ask adapter to the shared versioned question substrate.

use super::{
    arrival,
    records::*,
    store::{
        AnswerKey, HeadKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_VERSION, VersionKey, encode,
        secret_scan_before_put,
    },
};
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
    pub(crate) question: &'a str,
    pub(crate) binding: &'a OutcomeBinding,
    pub(crate) now: u64,
    pub(crate) choice: &'a str,
    pub(crate) revision: u32,
}

/// The caller holds the answer admission transaction. An ask has exactly one
/// immutable version, keyed by its group id, and one receipt-bearing claim.
/// Its prediction is a settled human selection, never a companion estimate.
/// The cutoff owns quorum resolution before this learning path may run.
pub(crate) fn bind_task_answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    input: TaskAnswerBinding<'_>,
) -> Result<AnswerRecord> {
    if QUESTION_HEAD.contains(&vault.store, txn, &HeadKey(input.task))? {
        return Err(Error::ConcurrentWrite("ask question already bound"));
    }
    let (source_kind, source) =
        validate_task_answer_unit(vault, txn, input.principal, actor.entity_ref(), input.unit)?;
    let choice = input.choice.to_owned();
    let band = DecisionBand::default();
    let record = QuestionRecord {
        schema_version: 1,
        principal: input.principal,
        definition: QuestionDefinition {
            question: DecisionQuestion {
                id: input.task,
                version: input.revision,
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
            profile: "responder-selection".into(),
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
                question_version: input.revision,
                principal: input.principal,
                providers: Vec::new(),
                band,
            },
            human_ask: None,
        },
        frontier: *blake3::hash(&source).as_bytes(),
        source_kind,
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
    secret_scan_before_put(&record)?;
    QUESTION_VERSION.put(
        &vault.store,
        txn,
        &VersionKey {
            id: input.task,
            version: input.revision,
        },
        &record,
    )?;
    let head = QuestionHead {
        version: input.revision,
        paused: false,
        last_refresh: Some(input.now),
    };
    secret_scan_before_put(&head)?;
    QUESTION_HEAD.put(&vault.store, txn, &HeadKey(input.task), &head)?;
    secret_scan_before_put(&answer)?;
    QUESTION_ANSWER.put(
        &vault.store,
        txn,
        &AnswerKey {
            question: input.task,
            claim: answer.claim,
        },
        &answer,
    )?;
    arrival::watch(&vault.store, txn, &record)?;
    Ok(answer)
}

/// Shared current visibility and secret-custody admission before first-answer CAS.
pub(crate) fn validate_task_answer_unit(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    holder: EntityId,
    unit: EntityId,
) -> Result<(u8, Vec<u8>)> {
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    for principal in [principal, holder] {
        let reader = ScopedReadActorKey::new(principal.to_hex())
            .ok_or(Error::InvariantViolation("canonical ask principal"))?;
        if !arrival::readable(&vault.store, txn, &policy, &reader, &unit)? {
            return Err(Error::EntityNotFound);
        }
    }
    let raw = vault
        .store
        .entities
        .get(txn, unit.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("ask result header"))?;
    // Custody records are not decision evidence even in a default-open vault.
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
        return Err(Error::EntityNotFound);
    }
    Ok((
        header.entity_type,
        raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
    ))
}
