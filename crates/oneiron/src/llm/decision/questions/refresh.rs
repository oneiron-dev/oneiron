//! Host-driven answer work: observe under principal, invoke provider outside a write transaction,
//! then atomically recheck source, authority, version and pause before settling claims.

use super::{arrival, records::*, store::*};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::llm::decision::{DecisionReceipt, TypedDecision};
use crate::{
    ClaimCandidate, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};

struct Prepared {
    unit: EntityId,
    frontier: [u8; 32],
    proposal: AnswerProposal,
}

/// The host supplies the answerer (and invokes this on arrival or on each timer tick).
/// No model work runs under the vault write lock. A stale or paused run cannot land.
pub fn refresh_question(
    vault: &Vault,
    actor: WriteActor,
    principal: EntityId,
    question: EntityId,
    trigger: RefreshTrigger,
    now: u64,
    mut answerer: impl FnMut(&QuestionRecord, EntityId, &[u8]) -> Result<AnswerProposal>,
) -> Result<Vec<AnswerRecord>> {
    let (record, head, units) = {
        let txn = vault.store.env.read_txn()?;
        let head = owned_head(vault, &txn, principal, question)?;
        let record: QuestionRecord = load(
            vault,
            &txn,
            &key(question, b"version", &head.version.to_be_bytes()),
        )?
        .ok_or(Error::EntityNotFound)?;
        record.definition.validate()?;
        if head.paused {
            return Ok(Vec::new());
        }
        let units = match trigger {
            RefreshTrigger::Manual => record.definition.units.clone(),
            RefreshTrigger::Schedule => {
                let Some(interval) = record.definition.refresh.every_seconds else {
                    return Ok(Vec::new());
                };
                if now
                    < head
                        .last_refresh
                        .unwrap_or(record.created_at)
                        .saturating_add(interval)
                {
                    return Ok(Vec::new());
                }
                record.definition.units.clone()
            }
            RefreshTrigger::Arrival(unit) => {
                if !record.definition.refresh.on_arrival
                    || !record.definition.units.contains(&unit)
                    || vault
                        .store
                        .vault_meta
                        .get(&txn, &arrival::pending_key(question, unit))?
                        .is_none()
                {
                    return Ok(Vec::new());
                }
                vec![unit]
            }
        };
        (record, head, units)
    };
    let mut prepared = Vec::new();
    for unit in units {
        let snapshot = {
            let txn = vault.store.env.read_txn()?;
            source(vault, &txn, principal, actor, unit)?
        };
        let Some((_, raw)) = snapshot else { continue };
        let proposal = answerer(&record, unit, &raw[ENTITY_METADATA_HEADER_LEN..])?;
        validate_proposal(&record, &proposal)?;
        prepared.push(Prepared {
            unit,
            frontier: *blake3::hash(&raw).as_bytes(),
            proposal,
        });
    }
    vault.with_write_txn(|txn| {
        let current = owned_head(vault, txn, principal, question)?;
        if current.version != head.version
            || current.paused
            || current.last_refresh != head.last_refresh
        {
            return Err(Error::ConcurrentWrite(
                "standing question changed during refresh",
            ));
        }
        // Every input is checked before the first write. A batch is all-or-nothing.
        let mut inputs = Vec::new();
        for p in &prepared {
            let Some((kind, raw)) = source(vault, txn, principal, actor, p.unit)? else {
                return Err(Error::ConcurrentWrite("standing question source changed"));
            };
            if *blake3::hash(&raw).as_bytes() != p.frontier {
                return Err(Error::ConcurrentWrite("standing question source changed"));
            }
            inputs.push((kind, raw));
        }
        let mut answers = Vec::new();
        for (p, (kind, raw)) in prepared.iter().zip(inputs) {
            let answer = AnswerRecord {
                claim: EntityId::now(),
                unit: p.unit,
                decision: TypedDecision {
                    answer: p.proposal.answer.clone(),
                    probability: p.proposal.probability,
                    evidence: vec![p.unit],
                    in_band: p
                        .proposal
                        .probability
                        .is_some_and(|v| record.definition.dial.band.contains(v)),
                    receipt: DecisionReceipt {
                        question,
                        question_version: head.version,
                        principal,
                        providers: p.proposal.providers.clone(),
                        band: record.definition.dial.band,
                    },
                    human_ask: None,
                },
                frontier: *blake3::hash(&raw).as_bytes(),
                source_kind: kind,
                answered_at: now,
            };
            land(vault, txn, actor, principal, &answer, &raw)?;
            put(
                vault,
                txn,
                &key(question, b"answer", answer.claim.as_bytes()),
                &answer,
            )?;
            answers.push(answer);
        }
        if matches!(trigger, RefreshTrigger::Schedule) {
            let mut updated = current;
            updated.last_refresh = Some(now);
            for p in &prepared {
                vault
                    .store
                    .vault_meta
                    .delete(txn, &arrival::pending_key(question, p.unit))?;
            }
            put(vault, txn, &key(question, b"head", &[]), &updated)?;
        }
        if let RefreshTrigger::Arrival(unit) = trigger {
            vault
                .store
                .vault_meta
                .delete(txn, &arrival::pending_key(question, unit))?;
        }
        Ok(answers)
    })
}

/// Pump due scheduled and materialized-arrival work. The host calls this on its clock
/// and after ingress; an arrival never runs a provider inside the ingress transaction.
pub fn refresh_due_questions(
    vault: &Vault,
    actor: WriteActor,
    now: u64,
    mut answerer: impl FnMut(&QuestionRecord, EntityId, &[u8]) -> Result<AnswerProposal>,
) -> Result<Vec<AnswerRecord>> {
    let work = {
        let txn = vault.store.env.read_txn()?;
        let mut work = Vec::new();
        for row in vault.store.vault_meta.prefix_iter(&txn, PREFIX)? {
            let (bytes, raw) = row?;
            if !bytes.ends_with(b":head:") {
                continue;
            }
            let Some(id_bytes) = bytes.get(PREFIX.len()..PREFIX.len() + 16) else {
                return Err(Error::CorruptedIndex("question head key"));
            };
            let id = EntityId::from_bytes(
                id_bytes
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("question head key"))?,
            )?;
            let head: QuestionHead = decode(&raw)?;
            if head.paused {
                continue;
            }
            let record: QuestionRecord = load(
                vault,
                &txn,
                &key(id, b"version", &head.version.to_be_bytes()),
            )?
            .ok_or(Error::CorruptedIndex("question version"))?;
            if let Some(interval) = record.definition.refresh.every_seconds
                && now
                    >= head
                        .last_refresh
                        .unwrap_or(record.created_at)
                        .saturating_add(interval)
            {
                work.push((record.principal, id, RefreshTrigger::Schedule));
            }
        }
        for row in vault.store.vault_meta.prefix_iter(&txn, arrival::PENDING)? {
            let (bytes, _) = row?;
            let tail = bytes
                .get(arrival::PENDING.len()..)
                .ok_or(Error::CorruptedIndex("question pending key"))?;
            if tail.len() != 32 {
                return Err(Error::CorruptedIndex("question pending key"));
            }
            let question = EntityId::from_bytes(
                tail[..16]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("question pending key"))?,
            )?;
            let unit = EntityId::from_bytes(
                tail[16..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("question pending key"))?,
            )?;
            let Some(head) = load::<QuestionHead>(vault, &txn, &key(question, b"head", &[]))?
            else {
                continue;
            };
            if head.paused {
                continue;
            }
            let Some(record) = load::<QuestionRecord>(
                vault,
                &txn,
                &key(question, b"version", &head.version.to_be_bytes()),
            )?
            else {
                continue;
            };
            if !work.iter().any(|(_, id, trigger)| {
                *id == question && matches!(trigger, RefreshTrigger::Schedule)
            }) {
                work.push((record.principal, question, RefreshTrigger::Arrival(unit)));
            }
        }
        work
    };
    let mut answers = Vec::new();
    for (principal, question, trigger) in work {
        answers.extend(refresh_question(
            vault,
            actor,
            principal,
            question,
            trigger,
            now,
            &mut answerer,
        )?);
    }
    Ok(answers)
}

/// Scoped receipt read; past versions remain available after edits and switches.
pub fn answer_records(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<AnswerRecord>> {
    let txn = vault.store.env.read_txn()?;
    owned_head(vault, &txn, principal, question)?;
    list(vault, &txn, &key(question, b"answer", &[]))
}

fn validate_proposal(record: &QuestionRecord, proposal: &AnswerProposal) -> Result<()> {
    if !record
        .definition
        .question
        .contract
        .accepts(&proposal.answer)
        || proposal
            .probability
            .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
        || (!matches!(
            proposal.answer,
            crate::llm::decision::DecisionAnswer::Abstain
        ) && proposal.probability.is_none())
        || proposal.providers.is_empty()
        || proposal.providers.iter().any(|p| {
            p.rung < record.definition.dial.first
                || p.rung > record.definition.dial.ceiling
                || p.model.is_empty()
                || p.version.is_empty()
        })
    {
        return Err(Error::InvalidConfig(
            "invalid standing question answer".into(),
        ));
    }
    Ok(())
}

fn source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    actor: WriteActor,
    unit: EntityId,
) -> Result<Option<(u8, Vec<u8>)>> {
    match super::task_ask::validate_task_answer_unit(
        vault,
        txn,
        principal,
        actor.entity_ref(),
        unit,
    ) {
        Ok((kind, _)) => {
            let raw = vault
                .store
                .entities
                .get(txn, unit.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            Ok(Some((kind, raw.to_vec())))
        }
        Err(Error::EntityNotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

fn land(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    principal: EntityId,
    answer: &AnswerRecord,
    raw: &[u8],
) -> Result<()> {
    let value = rmpv::decode::read_value(&mut encode(answer)?.as_slice())
        .map_err(|_| Error::CorruptedIndex("question answer encoding"))?;
    let mut candidate = ClaimCandidate::new(
        "judgment.answer",
        ClaimSubject::Entity(answer.unit),
        value.clone(),
        1.0,
    );
    let mut taint = ClaimSource::Imported;
    if answer.source_kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
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
            answer.unit.to_hex(),
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
                start: answer.answered_at,
                end: answer.answered_at,
            },
            answer.answered_at,
        )
        .apply(txn)
}

#[cfg(test)]
mod tests;
