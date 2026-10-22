//! The candidates an escalated consolidation round dropped, retained on its
//! `conflict.open` marker (OF-023, FIX 496).
//!
//! An escalation leaves the contradiction for a responder, and its round
//! drops the candidates it could not settle. The marker keeps each of them
//! whole beside its id: the proposal as the round made it (predicate,
//! subject, value, confidence, window, axes and scope), the parent-verified
//! evidence it cited, its lineage and the decisions that shaped it. None of
//! it is a stored claim or active truth. A responder sees the values, and a
//! Keep of one lands it as the round proposed it, in the settlement's own
//! transaction, under the current Gate: its evidence is bound again in that
//! transaction, since decoded bytes are never a witness by themselves. Each
//! cited TURN's projection, the MESSAGE ids its branch read and nothing of
//! their words, rides beside the citations, so that binding compares against
//! the words the round read (FIX 5755).

use rmpv::Value;

use super::evidence::{VerifiedCandidate, VerifiedEvidenceSet};
use super::provenance::{
    KeptDecision, PromotionCandidate, decode_consolidation_evidence, decode_verified_citations,
};
use super::settle::keep_approval::KeepAs;
use super::support::invalid_consolidation;
use crate::attempt_queue::AttemptId;
use crate::claim::{ClaimSource, ClaimSubject};
use crate::dreamer_promotion::{KeptConflictLink, KeptLanding};
use crate::edge::EdgeActorClass;
use crate::write_envelope::{ClaimCandidate, WriteActor};
use crate::{EntityId, Result, TimeRange, Vault};

/// The marker-value key the retained candidates ride under.
const ALTERNATIVES_KEY: &str = "alternatives";
/// The entry key each cited TURN's projection rides under (FIX 5755).
const PROJECTIONS_KEY: &str = "projections";

/// One candidate an escalated round dropped, as its marker retains it.
#[derive(Debug, Clone, PartialEq)]
pub struct RetainedAlternative {
    /// The id the round minted for it; a Keep lands it at this id.
    pub id: EntityId,
    pub predicate: String,
    pub value: Value,
    pub confidence: f32,
    /// The trust meet of the evidence its round verified for it.
    pub source: ClaimSource,
    /// The consolidation attempt that proposed it.
    pub attempt: AttemptId,
    /// The landings reverted settlements of its conflict made of it, each
    /// retracted (FIX 5752): a Keep after them lands it at a fresh id.
    pub(super) landings: Vec<EntityId>,
    /// The Keeps of it staged in their import's review that the owner
    /// declined there (FIX 7072): a Keep after them stages it at a fresh id,
    /// and the Dreamer's own ruling never offers it again.
    pub(super) declined: Vec<EntityId>,
    /// The whole retained entry, read in full only when it is kept.
    entry: Value,
}

/// The marker-value entry retaining `members`, the candidates the escalating
/// `attempt` drops: each whole, with its verified evidence. No member is left
/// out, however many the conflict holds.
pub(super) fn alternatives_entry(
    members: &[&VerifiedCandidate],
    attempt: AttemptId,
) -> Result<(Value, Value)> {
    let entries = members
        .iter()
        .map(|member| encode(member, attempt))
        .collect::<Result<Vec<_>>>()?;
    Ok((Value::from(ALTERNATIVES_KEY), Value::Array(entries)))
}

fn binary(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn encode(member: &VerifiedCandidate, attempt: AttemptId) -> Result<Value> {
    let body = super::conflict::candidate_probe_body(&member.candidate)?;
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid_consolidation(
            "a retained alternative names no entity subject",
        ));
    };
    let fields = vec![
        ("id", binary(member.claim_id)),
        ("attempt", Value::Binary(attempt.as_bytes().to_vec())),
        ("predicate", Value::from(body.predicate)),
        ("subject", binary(subject)),
        ("value", body.value),
        ("confidence", Value::F64(f64::from(body.confidence))),
        (
            "salience",
            body.salience
                .map_or(Value::Nil, |salience| Value::F64(f64::from(salience))),
        ),
        (
            "valid_from",
            body.valid_from.map_or(Value::Nil, Value::from),
        ),
        ("valid_to", body.valid_to.map_or(Value::Nil, Value::from)),
        ("world", body.world.map_or(Value::Nil, binary)),
        ("rel", body.rel.map_or(Value::Nil, binary)),
        ("scope", body.scope.unwrap_or(Value::Nil)),
        (
            "hints",
            Value::Array(
                member
                    .candidate
                    .lexical_hints()
                    .iter()
                    .map(|hint| Value::from(hint.as_str()))
                    .collect(),
            ),
        ),
        (
            "candidate_evidence",
            member.candidate.evidence().cloned().unwrap_or(Value::Nil),
        ),
        (
            "evidence",
            member.evidence.envelope(member.provenance_chain.clone()),
        ),
        (
            PROJECTIONS_KEY,
            Value::Array(
                member
                    .evidence
                    .projections()
                    .into_iter()
                    .map(|(source, messages)| {
                        Value::Array(vec![
                            binary(source),
                            Value::Array(messages.into_iter().map(binary).collect()),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "occurred",
            Value::Array(vec![
                Value::from(member.occurred.start),
                Value::from(member.occurred.end),
            ]),
        ),
        (
            "decisions",
            super::provenance::kept_decisions_value(&member.decisions)?,
        ),
    ];
    Ok(Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    ))
}

fn field<'v>(entry: &'v Value, key: &str) -> Result<&'v Value> {
    match entry {
        Value::Map(rows) => rows
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value)
            .ok_or_else(|| invalid_consolidation("a retained alternative lacks a field")),
        _ => Err(invalid_consolidation("a retained alternative is not a map")),
    }
}

fn bytes_at<'v>(entry: &'v Value, key: &str) -> Result<&'v [u8]> {
    match field(entry, key)? {
        Value::Binary(bytes) => Ok(bytes.as_slice()),
        _ => Err(invalid_consolidation(
            "a retained alternative's id is not binary",
        )),
    }
}

fn id_at(entry: &Value, key: &str) -> Result<EntityId> {
    entity(bytes_at(entry, key)?)
}

fn entity(bytes: &[u8]) -> Result<EntityId> {
    let bytes = <[u8; 16]>::try_from(bytes)
        .map_err(|_| invalid_consolidation("a retained alternative's id has the wrong length"))?;
    Ok(EntityId::from_bytes(bytes)?)
}

/// The projections an entry keeps beside its citations, by source; none
/// when it keeps none, so its citations bind as the TURN reads now.
fn projections(entry: &Value) -> Result<Vec<(EntityId, Vec<EntityId>)>> {
    let Ok(Value::Array(rows)) = field(entry, PROJECTIONS_KEY) else {
        return Ok(Vec::new());
    };
    let malformed = || invalid_consolidation("a retained alternative's projection");
    rows.iter()
        .map(|row| {
            let Value::Array(pair) = row else {
                return Err(malformed());
            };
            let [Value::Binary(source), Value::Array(messages)] = pair.as_slice() else {
                return Err(malformed());
            };
            let messages = messages
                .iter()
                .map(|message| match message {
                    Value::Binary(bytes) => entity(bytes),
                    _ => Err(malformed()),
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((entity(source)?, messages))
        })
        .collect()
}

fn optional_id(entry: &Value, key: &str) -> Result<Option<EntityId>> {
    match field(entry, key)? {
        Value::Nil => Ok(None),
        _ => id_at(entry, key).map(Some),
    }
}

fn optional_u64(entry: &Value, key: &str) -> Result<Option<u64>> {
    match field(entry, key)? {
        Value::Nil => Ok(None),
        value => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid_consolidation("a retained alternative's time is not a number")),
    }
}

fn optional_value(entry: &Value, key: &str) -> Result<Option<Value>> {
    Ok(match field(entry, key)? {
        Value::Nil => None,
        value => Some(value.clone()),
    })
}

/// The alternatives a marker's `value` retains. An entry that does not read
/// as one is left out, so the marker itself stays answerable.
pub(super) fn retained_alternatives(value: &Value) -> Vec<RetainedAlternative> {
    let Ok(Value::Array(entries)) = field(value, ALTERNATIVES_KEY) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| summary(entry).ok())
        .collect()
}

fn summary(entry: &Value) -> Result<RetainedAlternative> {
    let evidence = decode_consolidation_evidence(field(entry, "evidence")?)?
        .ok_or_else(|| invalid_consolidation("a retained alternative has no evidence"))?;
    Ok(RetainedAlternative {
        id: id_at(entry, "id")?,
        predicate: field(entry, "predicate")?
            .as_str()
            .ok_or_else(|| invalid_consolidation("a retained alternative names no predicate"))?
            .to_owned(),
        value: field(entry, "value")?.clone(),
        confidence: field(entry, "confidence")?
            .as_f64()
            .ok_or_else(|| invalid_consolidation("a retained alternative has no confidence"))?
            as f32,
        source: evidence.source_meet,
        attempt: AttemptId::from_bytes(bytes_at(entry, "attempt")?)?,
        landings: Vec::new(),
        declined: Vec::new(),
        entry: entry.clone(),
    })
}

fn decisions(value: &Value) -> Result<Vec<KeptDecision>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid_consolidation("retained decisions do not encode"))?;
    rmp_serde::from_slice(&bytes)
        .map_err(|_| invalid_consolidation("retained decisions do not decode"))
}

impl RetainedAlternative {
    /// The alternative as its round proposed it, to land at `landing`, its
    /// evidence bound again in `txn` as the Dreamer reads it now, against
    /// the projection its branch read where the TURN has moved on: a
    /// citation whose source moved, left the Dreamer's reach or lost the
    /// words it named refuses. Its trust never rises above what its round
    /// verified. It is learned at `now_ms` in Unix seconds, as every claim's
    /// times are (FIX 8695, FIX 10356).
    fn proposal_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        landing: EntityId,
        now_ms: u64,
    ) -> Result<(PromotionCandidate, VerifiedEvidenceSet)> {
        let entry = &self.entry;
        let mut candidate = ClaimCandidate::new(
            self.predicate.clone(),
            ClaimSubject::Entity(id_at(entry, "subject")?),
            self.value.clone(),
            self.confidence,
        )
        .with_validity(
            optional_u64(entry, "valid_from")?,
            optional_u64(entry, "valid_to")?,
        );
        let Value::Array(hints) = field(entry, "hints")? else {
            return Err(invalid_consolidation("a retained alternative's hints"));
        };
        candidate = candidate.with_lexical_hints(
            hints
                .iter()
                .map(|hint| {
                    hint.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| invalid_consolidation("a retained alternative's hint"))
                })
                .collect::<Result<Vec<_>>>()?,
        );
        if let Some(salience) = field(entry, "salience")?.as_f64() {
            candidate = candidate.with_salience(salience as f32);
        }
        if let Some(scope) = optional_value(entry, "scope")? {
            candidate = candidate.with_scope(scope);
        }
        if let Some(world) = optional_id(entry, "world")? {
            candidate = candidate.with_world(world);
        }
        if let Some(rel) = optional_id(entry, "rel")? {
            candidate = candidate.with_relationship(rel);
        }
        if let Some(evidence) = optional_value(entry, "candidate_evidence")? {
            candidate = candidate.with_evidence(evidence);
        }
        let stored = field(entry, "evidence")?;
        let envelope = decode_consolidation_evidence(stored)?
            .ok_or_else(|| invalid_consolidation("a retained alternative has no evidence"))?;
        let evidence = VerifiedEvidenceSet::reverify_in_txn(
            vault,
            txn,
            &decode_verified_citations(stored)?,
            &projections(entry)?,
            envelope.source_meet,
        )?;
        let Value::Array(occurred) = field(entry, "occurred")? else {
            return Err(invalid_consolidation("a retained alternative's window"));
        };
        let [start, end] = occurred.as_slice() else {
            return Err(invalid_consolidation("a retained alternative's window"));
        };
        let occurred = TimeRange {
            start: start
                .as_u64()
                .ok_or_else(|| invalid_consolidation("a retained alternative's window"))?,
            end: end
                .as_u64()
                .ok_or_else(|| invalid_consolidation("a retained alternative's window"))?,
        };
        Ok((
            PromotionCandidate {
                claim_id: landing,
                candidate,
                evidence_turn_refs: evidence.refs(),
                provenance_chain: envelope.chain,
                supersedes: None,
                evidence_meet: evidence.meet(),
                occurred,
                learned_at: now_ms / 1_000,
                decisions: decisions(field(entry, "decisions")?)?,
            },
            evidence,
        ))
    }
}

/// Lands `alternative`, the one a settlement keeps, at `landing` in the
/// settlement's transaction through the promotion writer's selected landing,
/// as the Dreamer's claim from its round: a refusal is the settlement's, and
/// its marker stays open. Words from an import are staged in that import's
/// review instead, never landed (FIX 5754), linked by `link` to the conflict
/// it was kept for (FIX 6152). `keep_as` says how it lands (FIX 5753).
/// `now_ms` is the settlement's clock: Unix milliseconds from both
/// `Memory::settle_conflict` callers.
pub(super) fn land_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    alternative: &RetainedAlternative,
    landing: EntityId,
    link: KeptConflictLink,
    keep_as: KeepAs<'_>,
    now_ms: u64,
) -> Result<KeptLanding> {
    let (proposal, evidence) = alternative.proposal_in_txn(vault, txn, landing, now_ms)?;
    let run = crate::dreamer_promotion::DreamerRunContext {
        run_id: crate::entity_id::bytes_to_hex_lower(alternative.attempt.as_bytes()),
        attempt_id: alternative.attempt,
        agent_actor: WriteActor::new(
            crate::dreamer_runner::authority::dreamer_actor_id()?,
            EdgeActorClass::System,
        ),
        now_ms,
    };
    crate::dreamer_promotion::land_kept_alternative_in_txn(
        vault, txn, &run, proposal, &evidence, link, keep_as,
    )
}
