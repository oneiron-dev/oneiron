//! Idempotent outcome projection over durable facts and immutable question versions.

use super::{
    records::*,
    store::{
        HeadKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_LABEL, QUESTION_VERSION, VersionKey,
        family_prefix,
    },
};
use crate::llm::decision::{DecisionAnswer, PersonChangedAnswer};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// The Coach's person-changed records, read here only: the table, its
/// writer ([`Vault::record_person_changed_answer`]) and its read marks are
/// the Coach's. Key: the source the host bound the person's answer to.
const PERSON_CHANGED: SideTable<EntityId, PersonChangedAnswer, Named> =
    SideTable::new(&side_table::COACH_PERSON_CHANGED);

pub fn project_bound_outcomes(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<usize> {
    if super::read_question(vault, principal, question, None)?.is_none() {
        return Ok(0);
    }
    let facts = {
        let txn = vault.store.env.read_txn()?;
        crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &vault.store,
            &txn,
            crate::registry::ENTITY_TYPE_CLAIM,
            None,
        )?
        .collect::<Result<std::collections::BTreeSet<_>>>()?
    };
    vault.with_write_txn_grouped(|txn| {
        super::arrival::project_question_in_txn(&vault.store, txn, &facts, question)
    })
}

/// Labels are observations of immutable answer receipts. Current facts and
/// authority are checked again within one read snapshot before returning them.
/// A window that closed in silence pairs its answer with the binding's
/// silence label; such a pair names the answer as its own fact.
/// A caller at `locality` gets no pair derived from a row a device-local
/// world keeps from it, and each pair names the rows it was derived from.
pub fn calibration_pairs(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    locality: crate::claim::CallerLocality,
) -> Result<Vec<CalibrationPair>> {
    let txn = vault.store.env.read_txn()?;
    let kept = crate::settings::device_local_worlds_at(vault, &txn, locality)?;
    let Some(head) = QUESTION_HEAD.get(&vault.store, &txn, &HeadKey(question))? else {
        return Ok(Vec::new());
    };
    let Some(current) = QUESTION_VERSION.get(
        &vault.store,
        &txn,
        &VersionKey {
            id: question,
            version: head.version,
        },
    )?
    else {
        return Ok(Vec::new());
    };
    if current.principal != principal {
        return Ok(Vec::new());
    }
    let answers: Vec<AnswerRecord> = QUESTION_ANSWER
        .scan_from(&vault.store, &txn, &family_prefix(question, b"answer"))?
        .into_iter()
        .map(|(_, answer)| answer)
        .collect();
    let labels: Vec<OutcomeLabel> = QUESTION_LABEL
        .scan_from(&vault.store, &txn, &family_prefix(question, b"label"))?
        .into_iter()
        .map(|(_, label)| label)
        .collect();
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    let mut pairs = Vec::new();
    for outcome in labels {
        let Some(answer) = answers.iter().find(|a| a.claim == outcome.answer) else {
            continue;
        };
        let Some(record) = QUESTION_VERSION.get(
            &vault.store,
            &txn,
            &VersionKey {
                id: question,
                version: answer.decision.receipt.question_version,
            },
        )?
        else {
            continue;
        };
        if record.principal != principal {
            continue;
        }
        let Some(raw) =
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &outcome.fact)?
        else {
            continue;
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(crate::Error::CorruptedIndex("outcome fact header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            true,
        )?;
        let mut derived_from = derived_rows(question, answer, outcome.fact, &body);
        derived_from.extend(crate::reaction::outcome_sources(&body)?);
        if !kept.is_empty() && kept_any(vault, &txn, &kept, &derived_from)? {
            continue;
        }
        let fact = super::arrival::Fact {
            id: outcome.fact,
            body: &body,
            occurred_at: header.occurred_start,
        };
        if super::arrival::evaluate_fact(&vault.store, &txn, &policy, &record, answer, &fact)?
            .as_ref()
            != Some(&outcome)
        {
            continue;
        }
        let Some(probability) = answer.decision.probability else {
            continue;
        };
        pairs.push(CalibrationPair {
            prediction: answer.decision.answer.clone(),
            probability,
            outcome,
            derived_from,
        });
    }
    // A window that closed in silence labels its answer by the binding's
    // silence label, unless a fact in the window has labelled it since.
    for (_, close) in super::windows::QUESTION_WINDOW.scan_from(
        &vault.store,
        &txn,
        &family_prefix(question, b"window"),
    )? {
        let WindowOutcome::Silence(label) = close.outcome else {
            continue;
        };
        let Some(answer) = answers.iter().find(|a| a.claim == close.answer) else {
            continue;
        };
        let Some(record) = QUESTION_VERSION.get(
            &vault.store,
            &txn,
            &VersionKey {
                id: question,
                version: close.question_version,
            },
        )?
        else {
            continue;
        };
        let Some(binding) = &record.definition.binding else {
            continue;
        };
        let Some(probability) = answer.decision.probability else {
            continue;
        };
        let derived_from = vec![question, answer.claim, answer.unit];
        if record.principal != principal
            || (!kept.is_empty() && kept_any(vault, &txn, &kept, &derived_from)?)
            || !super::windows::silence_stands(&vault.store, &txn, &policy, &record, answer)?
            || super::windows::fact_labelled(&vault.store, &txn, &policy, &record, answer)?
        {
            continue;
        }
        pairs.push(CalibrationPair {
            prediction: answer.decision.answer.clone(),
            probability,
            outcome: OutcomeLabel {
                answer: answer.claim,
                fact: answer.claim,
                fact_value_hash: super::windows::silence_hash()?,
                label,
                noise_weight: binding.noise_weight,
                occurred_at: close.ends_at,
            },
            derived_from,
        });
    }
    Ok(pairs)
}

/// Ask-up changed-answer labels (OF-516): each time a person changed the
/// model's answer to `question` for `principal`, the model's prior answer and
/// its probability are paired with the person's answer as the outcome. For a
/// yes/no question the label is the person's answer, as a fact's mapped value
/// is; for any other the label says the prior held, which a changed answer
/// never does. A record without a prior probability pairs nothing. A caller
/// at `locality` gets no pair from a row a device-local world keeps from it.
pub fn person_changed_pairs(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    locality: crate::claim::CallerLocality,
) -> Result<Vec<CalibrationPair>> {
    let txn = vault.store.env.read_txn()?;
    let kept = crate::settings::device_local_worlds_at(vault, &txn, locality)?;
    let mut pairs = Vec::new();
    for (source, record) in PERSON_CHANGED.scan(&vault.store, &txn)? {
        if record.question != question || record.principal != principal {
            continue;
        }
        let Some(probability) = record.prior_probability else {
            continue;
        };
        let derived_from = vec![question, source];
        if !kept.is_empty() && kept_any(vault, &txn, &kept, &derived_from)? {
            continue;
        }
        let label = match (&record.prior, &record.person) {
            (DecisionAnswer::Noul(_), DecisionAnswer::Noul(person)) => *person,
            (prior, person) => prior == person,
        };
        let person = serde_json::to_vec(&record.person)
            .map_err(|_| crate::Error::InvariantViolation("encode a person's answer"))?;
        let occurred_at =
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &source)?
                .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
                .map_or(0, |header| header.occurred_start);
        pairs.push(CalibrationPair {
            prediction: record.prior,
            probability,
            outcome: OutcomeLabel {
                answer: source,
                fact: source,
                fact_value_hash: *blake3::hash(&person).as_bytes(),
                label,
                noise_weight: 1.0,
                occurred_at,
            },
            derived_from,
        });
    }
    Ok(pairs)
}

/// The rows a pair is derived from: the question, the answer and the unit
/// it binds, the outcome fact and the fact's subject and edge endpoint.
fn derived_rows(
    question: EntityId,
    answer: &AnswerRecord,
    fact: EntityId,
    body: &crate::claim::ClaimBody,
) -> Vec<EntityId> {
    let (subject, endpoint) = match body.subject {
        crate::claim::ClaimSubject::Entity(id) => (id, None),
        crate::claim::ClaimSubject::Edge { source, target, .. } => (source, Some(target)),
    };
    [question, answer.claim, answer.unit, fact, subject]
        .into_iter()
        .chain(endpoint)
        .collect()
}

fn kept_any(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kept: &std::collections::BTreeSet<EntityId>,
    rows: &[EntityId],
) -> Result<bool> {
    for id in rows {
        if crate::settings::device_local_keeps_among(&vault.store, txn, kept, id)? {
            return Ok(true);
        }
    }
    Ok(false)
}
