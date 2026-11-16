//! Wire health checks (OF-520) on the shared versioned question substrate. A crossing's
//! typed decision ("is everything okay: a bot, or a valid burst?") is one one-off question
//! over one unit, the crossing as the server kept it. A later outcome fact on that unit
//! labels the decision for the loop, through the question's binding. The
//! owner stamps that fact as his own act, under the proof of the door that
//! admitted him (ARCH-0044 C5; WIRE-HEALTH-OUTCOME-STAMPER = A).

use super::{
    arrival,
    records::*,
    store::{
        HeadKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_VERSION, VersionKey, encode,
        family_prefix, secret_scan_before_put,
    },
};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::llm::decision::types::invalid;
use crate::llm::decision::{
    DecisionAnswer, DecisionAsk, DecisionDial, DecisionQuestion, TypedDecision,
};
use crate::{
    ClaimCandidate, EdgeActorClass, EntityId, Error, Result, TimeRange, Vault, WriteActor,
    WriteEnvelope, WriteProvenance,
};

/// A crossing's unit: what crossed, as the server kept it, about the vault owner.
pub const HEALTH_CROSSING_PREDICATE: &str = "wire.health.crossing";
/// What happened next: a later fact on a crossing's unit. Its value is an answer option,
/// which the question's binding maps to a label.
pub const HEALTH_OUTCOME_PREDICATE: &str = "wire.health.outcome";
/// The adapter a health question's record names.
const HEALTH_ADAPTER: &str = "wire.health";

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
    /// option, as his own act under `owner`'s proof, revalidated in the write. Its arrival
    /// labels the bound decision. A proof that is not the owner's own full, undelegated
    /// credential refuses the write.
    pub fn record_health_outcome(
        &self,
        owner: &AuthenticatedOwner,
        unit: EntityId,
        outcome: &str,
        now: u64,
    ) -> Result<EntityId> {
        self.with_write_txn_grouped(|txn| {
            let authored = owner.owner_authored_write_in_txn(self, txn)?;
            owner_outcome_in_txn(self, txn, authored, unit, outcome, now)
        })
    }
}

/// The owner's answer to `ask`, when it asks a health check, as that check's outcome: one
/// `wire.health.outcome` fact on the crossing's unit, in the writer that keeps the answer,
/// as the owner's own act under `owner`'s proof. The sweep that settles the check holds no
/// proof, so the label lands here or not at all. An ask of another question, an answer
/// that is no choice, a question not yet bound to its unit, and a proof that is not the
/// owner's own full, undelegated credential land nothing; the answer stands either way.
pub(crate) fn land_owner_health_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    ask: &DecisionAsk,
) -> Result<Option<EntityId>> {
    let Some(DecisionAnswer::Choice(outcome)) = ask.answer.as_ref().map(|held| &held.answer) else {
        return Ok(None);
    };
    let key = VersionKey {
        id: ask.question.id,
        version: ask.question.version,
    };
    let Some(record) = QUESTION_VERSION.get(&vault.store, &*txn, &key)? else {
        return Ok(None);
    };
    if record.definition.adapter != HEALTH_ADAPTER {
        return Ok(None);
    }
    let [unit] = record.definition.units.as_slice() else {
        return Err(Error::CorruptedIndex(
            "health question without its one unit",
        ));
    };
    if !ask.principal.is(record.principal) {
        return Err(invalid("a health ask answers its own question"));
    }
    let Some(authored) = owner.owner_answer_in_txn(vault, txn)? else {
        return Ok(None);
    };
    let answered_at = ask.answer.as_ref().map_or(0, |held| held.answered_at);
    owner_outcome_in_txn(vault, txn, authored, *unit, outcome, answered_at).map(Some)
}

/// One `wire.health.outcome` fact on `unit`, the owner's `outcome`: Human, UserStated and
/// Approved, private to him, landed under `authored`, the proof revalidated in `txn`.
fn owner_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    authored: crate::consent::OwnerAuthoredWrite,
    unit: EntityId,
    outcome: &str,
    now: u64,
) -> Result<EntityId> {
    if outcome.is_empty() || outcome.len() > 4096 {
        return Err(invalid("invalid health outcome"));
    }
    let principal = authored.actor();
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
    vault
        .batch_in()
        .with_owner_authored(Some(authored))
        .claim_candidate(&fact, candidate, &envelope, at(now), now)
        .apply(txn)?;
    Ok(fact)
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
            adapter: HEALTH_ADAPTER.into(),
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
        // A one-off health check keeps no authenticated asker: the engine
        // writes it for its principal, under the principal's own lane.
        asker_class: None,
        read_lane: crate::claim::FrozenReadLane::principal(),
    };
    record.definition.validate()?;
    let answer = AnswerRecord {
        claim: EntityId::now(),
        unit,
        decision: input.decision.clone(),
        frontier: *blake3::hash(&encoded).as_bytes(),
        source_kind: crate::registry::ENTITY_TYPE_CLAIM,
        answered_at: input.now,
        omitted: Vec::new(),
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
    super::ask_history::put_graph_answer_in_txn(vault, txn, question.id, input.principal, &answer)?;
    arrival::watch(&vault.store, txn, &record)?;
    Ok(HealthBound { unit, answer })
}
