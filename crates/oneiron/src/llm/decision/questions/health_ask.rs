//! Wire health checks (OF-520) on the shared versioned question substrate. A crossing's
//! typed decision ("is everything okay: a bot, or a valid burst?") is one one-off question
//! over one unit, the crossing as the server kept it. A later outcome fact on that unit
//! labels the decision for the loop, through the question's binding.

use super::{
    arrival,
    records::*,
    store::{
        AnswerKey, HeadKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_VERSION, VersionKey, encode,
        family_prefix, secret_scan_before_put,
    },
};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::llm::decision::types::invalid;
use crate::llm::decision::{DecisionDial, DecisionQuestion, TypedDecision};
use crate::{
    ClaimCandidate, EdgeActorClass, EntityId, Error, Result, TimeRange, Vault, WriteActor,
    WriteEnvelope, WriteProvenance,
};

/// A crossing's unit: what crossed, as the server kept it, about the vault owner.
pub const HEALTH_CROSSING_PREDICATE: &str = "wire.health.crossing";
/// What happened next: a later fact on a crossing's unit. Its value is an answer option,
/// which the question's binding maps to a label.
pub const HEALTH_OUTCOME_PREDICATE: &str = "wire.health.outcome";

/// One health decision to bind.
pub struct HealthAnswer<'a> {
    /// The vault owner role the question was asked for.
    pub principal: EntityId,
    pub question: &'a DecisionQuestion,
    pub dial: DecisionDial,
    pub decision: &'a TypedDecision,
    /// The crossing as the server kept it, the unit's value.
    pub crossing: &'a serde_json::Value,
    pub binding: &'a OutcomeBinding,
    pub now: u64,
}

/// A bound health decision: the crossing's unit and the answer receipt.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthBound {
    pub unit: EntityId,
    pub answer: AnswerRecord,
}

impl Vault {
    /// Keeps one health decision in one write: the crossing's unit, the question's one
    /// version, its answer receipt and `judgment.answer` claim, and the binding's watch. A
    /// question binds once; binding it again returns the first binding.
    pub fn bind_health_answer(&self, input: &HealthAnswer<'_>) -> Result<HealthBound> {
        self.with_write_txn_grouped(|txn| bind_health_answer_in_txn(self, txn, input))
    }

    /// Records what happened next to the crossing `unit`: the owner's `outcome`, an answer
    /// option. Its arrival labels the bound decision.
    pub fn record_health_outcome(
        &self,
        principal: EntityId,
        unit: EntityId,
        outcome: &str,
        now: u64,
    ) -> Result<EntityId> {
        if outcome.is_empty() || outcome.len() > 4096 {
            return Err(invalid("invalid health outcome"));
        }
        let value = rmpv::Value::from(outcome);
        let candidate = ClaimCandidate::new(
            HEALTH_OUTCOME_PREDICATE,
            ClaimSubject::Entity(unit),
            value.clone(),
            1.0,
        )
        .with_private_reader(principal)?;
        let envelope = WriteEnvelope::new(
            WriteActor::new(principal, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(value)?,
            ClaimApprovalStatus::Approved,
        );
        let fact = EntityId::now();
        self.with_write_txn_grouped(|txn| {
            self.batch_in()
                .claim_candidate(&fact, candidate, &envelope, at(now), now)
                .apply(txn)
        })?;
        Ok(fact)
    }
}

fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}

fn bind_health_answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &HealthAnswer<'_>,
) -> Result<HealthBound> {
    let question = input.question;
    let receipt = &input.decision.receipt;
    if receipt.question != question.id
        || receipt.question_version != question.version
        || receipt.principal != input.principal
    {
        return Err(invalid("a health decision answers its own question"));
    }
    if QUESTION_HEAD.contains(&vault.store, txn, &HeadKey(question.id))? {
        // Bound by an earlier pass that stopped before its host kept the unit.
        let (_, answer) = QUESTION_ANSWER
            .scan_from(&vault.store, txn, &family_prefix(question.id, b"answer"))?
            .into_iter()
            .next()
            .ok_or(Error::CorruptedIndex("health question without its answer"))?;
        return Ok(HealthBound {
            unit: answer.unit,
            answer,
        });
    }
    let actor = WriteActor::new(input.principal, EdgeActorClass::Human);
    let encoded = rmp_serde::to_vec_named(input.crossing)
        .map_err(|_| invalid("health crossing encoding failed"))?;
    let crossing = rmpv::decode::read_value(&mut encoded.as_slice())
        .map_err(|_| Error::CorruptedIndex("health crossing encoding"))?;
    let unit = EntityId::now();
    let candidate = ClaimCandidate::new(
        HEALTH_CROSSING_PREDICATE,
        ClaimSubject::Entity(input.principal),
        crossing.clone(),
        1.0,
    )
    .with_private_reader(input.principal)?;
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Observed,
        WriteProvenance::new(crossing)?,
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch_in()
        .claim_candidate(&unit, candidate, &envelope, at(input.now), input.now)
        .apply(txn)?;
    let record = QuestionRecord {
        schema_version: 1,
        principal: input.principal,
        definition: QuestionDefinition {
            question: question.clone(),
            adapter: "wire.health".into(),
            units: vec![unit],
            recipe: "wire.health.v1".into(),
            profile: "fleet-burst".into(),
            dial: input.dial,
            activation: QuestionActivation::OneOff,
            refresh: RefreshPolicy {
                on_arrival: false,
                every_seconds: None,
            },
            delivery: "owner.decisions".into(),
            learning: true,
            binding: Some(input.binding.clone()),
            criteria: QuestionCriteria::default(),
            audience: QuestionAudience::Asker,
            posture: None,
            media: QuestionMedia::default(),
            deadline_ms: None,
            artifacts: Vec::new(),
        },
        created_at: input.now,
    };
    record.definition.validate()?;
    let answer = AnswerRecord {
        claim: EntityId::now(),
        unit,
        decision: input.decision.clone(),
        frontier: *blake3::hash(&encoded).as_bytes(),
        source_kind: crate::registry::ENTITY_TYPE_CLAIM,
        answered_at: input.now,
    };
    let answer_bytes = encode(&answer)?;
    let value = rmpv::decode::read_value(&mut answer_bytes.as_slice())
        .map_err(|_| Error::CorruptedIndex("health answer encoding"))?;
    let candidate = ClaimCandidate::new(
        "judgment.answer",
        ClaimSubject::Entity(unit),
        value.clone(),
        1.0,
    )
    .with_evidence_taint(ClaimSource::Observed)?
    .with_private_reader(input.principal)?
    .with_evidence(rmpv::Value::Array(vec![rmpv::Value::from(unit.to_hex())]));
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(value)?,
        ClaimApprovalStatus::Proposed,
    );
    vault
        .batch_in()
        .claim_candidate(
            &answer.claim,
            candidate,
            &envelope,
            at(input.now),
            input.now,
        )
        .apply(txn)?;
    secret_scan_before_put(&record)?;
    QUESTION_VERSION.put(
        &vault.store,
        txn,
        &VersionKey {
            id: question.id,
            version: question.version,
        },
        &record,
    )?;
    let head = QuestionHead {
        version: question.version,
        paused: false,
        last_refresh: Some(input.now),
        retry_at: None,
    };
    secret_scan_before_put(&head)?;
    QUESTION_HEAD.put(&vault.store, txn, &HeadKey(question.id), &head)?;
    secret_scan_before_put(&answer)?;
    QUESTION_ANSWER.put(
        &vault.store,
        txn,
        &AnswerKey {
            question: question.id,
            claim: answer.claim,
        },
        &answer,
    )?;
    arrival::watch(&vault.store, txn, &record)?;
    Ok(HealthBound { unit, answer })
}
