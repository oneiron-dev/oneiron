//! Idempotent outcome projection over durable facts and immutable question versions.

use super::{records::*, store::*};
use crate::{EntityId, Result, Vault};

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
        vault
            .store
            .type_index
            .prefix_iter(&txn, &[crate::registry::ENTITY_TYPE_CLAIM])?
            .map(|row| {
                let (key, _) = row?;
                crate::vault::entity_id_from_type_index_key(&key)
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?
    };
    vault.with_write_txn(|txn| {
        super::arrival::project_question_in_txn(&vault.store, txn, &facts, question)
    })
}

/// Labels are observations of immutable answer receipts. Current facts and
/// authority are checked again within one read snapshot before returning them.
pub fn calibration_pairs(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<CalibrationPair>> {
    let txn = vault.store.env.read_txn()?;
    let Some(head) = load::<QuestionHead>(vault, &txn, &key(question, b"head", &[]))? else {
        return Ok(Vec::new());
    };
    let Some(current) = load::<QuestionRecord>(
        vault,
        &txn,
        &key(question, b"version", &head.version.to_be_bytes()),
    )?
    else {
        return Ok(Vec::new());
    };
    if current.principal != principal {
        return Ok(Vec::new());
    }
    let answers: Vec<AnswerRecord> = list(vault, &txn, &key(question, b"answer", &[]))?;
    let labels: Vec<OutcomeLabel> = list(vault, &txn, &key(question, b"label", &[]))?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    let mut pairs = Vec::new();
    for outcome in labels {
        let Some(answer) = answers.iter().find(|a| a.claim == outcome.answer) else {
            continue;
        };
        let Some(record) = load::<QuestionRecord>(
            vault,
            &txn,
            &key(
                question,
                b"version",
                &answer.decision.receipt.question_version.to_be_bytes(),
            ),
        )?
        else {
            continue;
        };
        if record.principal != principal {
            continue;
        }
        let Some(raw) = vault.store.entities.get(&txn, outcome.fact.as_bytes())? else {
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
        });
    }
    Ok(pairs)
}
