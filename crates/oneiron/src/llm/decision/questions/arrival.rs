//! Outcome arrival projection in the materializing transaction. No model or timer.

use super::{
    records::*,
    store::{decode, encode, key},
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject, ScopedReadActorKey};
use crate::gate::PolicyManifestResolution;
use crate::store::Store;
use crate::{EntityId, Error, Result};

const WATCH: &[u8] = b"typed_question:watch:v1:";

pub(super) fn watch(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &QuestionRecord,
) -> Result<()> {
    let Some(binding) = &record.definition.binding else {
        return Ok(());
    };
    if !record.definition.learning {
        return Ok(());
    }
    let predicate = predicate(&binding.source);
    let prefix = watch_prefix(predicate);
    let id = record.definition.question.id;
    let watch_key = [prefix.as_slice(), id.as_bytes()].concat();
    store.vault_meta.put(txn, &watch_key, id.as_bytes())?;
    Ok(())
}

fn watch_prefix(predicate: &str) -> Vec<u8> {
    [WATCH, predicate.as_bytes(), &[0]].concat()
}

fn predicate(source: &OutcomeSource) -> &str {
    match source {
        OutcomeSource::Claim { predicate } | OutcomeSource::Event { predicate } => predicate,
        OutcomeSource::Stage { .. } => "crm.stage",
        OutcomeSource::Edge { .. } => "edge.provenance",
    }
}

/// Called after the batch's final entity and edge state is installed, on both
/// ordinary writes and replicated batches. Question metadata remains local.
pub(crate) fn project_arrivals_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
) -> Result<usize> {
    project(store, txn, ids, None)
}

pub(super) fn project_question_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
    question: EntityId,
) -> Result<usize> {
    project(store, txn, ids, Some(question))
}

fn project(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
    only: Option<EntityId>,
) -> Result<usize> {
    if store.vault_meta.prefix_iter(txn, WATCH)?.next().is_none() {
        return Ok(0);
    }
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    let mut count = 0;
    for id in ids {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("outcome fact header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if !crate::claim::claim_consolidatable(&body)
            || !crate::claim::claim_evidence_admissible(&body)
        {
            continue;
        }
        let watchers = store
            .vault_meta
            .prefix_iter(txn, &watch_prefix(&body.predicate))?
            .map(|row| {
                let (_, bytes) = row?;
                EntityId::from_bytes(
                    bytes
                        .as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("outcome watcher"))?,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        for question in watchers {
            if only.is_some_and(|id| id != question) {
                continue;
            }
            count += project_fact(
                store,
                txn,
                &policy,
                question,
                *id,
                &body,
                header.occurred_start,
            )?;
        }
    }
    Ok(count)
}

fn project_fact(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    policy: &PolicyManifestResolution,
    question: EntityId,
    fact: EntityId,
    body: &ClaimBody,
    occurred_at: u64,
) -> Result<usize> {
    let answers = store
        .vault_meta
        .prefix_iter(txn, &key(question, b"answer", &[]))?
        .map(|row| {
            let (_, raw) = row?;
            decode::<AnswerRecord>(&raw)
        })
        .collect::<Result<Vec<_>>>()?;
    let fact = Fact {
        id: fact,
        body,
        occurred_at,
    };
    let mut count = 0;
    for answer in answers {
        let version = answer.decision.receipt.question_version;
        let Some(raw) = store
            .vault_meta
            .get(txn, &key(question, b"version", &version.to_be_bytes()))?
        else {
            continue;
        };
        let record: QuestionRecord = decode(&raw)?;
        let Some(label) = evaluate_fact(store, txn, policy, &record, &answer, &fact)? else {
            continue;
        };
        let suffix = [
            answer.claim.as_bytes().as_slice(),
            fact.id.as_bytes().as_slice(),
        ]
        .concat();
        let label_key = key(question, b"label", &suffix);
        if store.vault_meta.get(txn, &label_key)?.is_some() {
            continue;
        }
        store.vault_meta.put(txn, &label_key, &encode(&label)?)?;
        count += 1;
    }
    Ok(count)
}

pub(super) struct Fact<'a> {
    pub(super) id: EntityId,
    pub(super) body: &'a ClaimBody,
    pub(super) occurred_at: u64,
}

/// Admission and reads use the same predicate, subject, link, horizon and
/// privacy checks. A mutable fact cannot move an old label to another unit.
pub(super) fn evaluate_fact(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    record: &QuestionRecord,
    answer: &AnswerRecord,
    fact: &Fact<'_>,
) -> Result<Option<OutcomeLabel>> {
    record.definition.validate()?;
    let body = fact.body;
    if record.schema_version != 1
        || record.definition.question.id != answer.decision.receipt.question
        || record.definition.question.version != answer.decision.receipt.question_version
        || record.principal != answer.decision.receipt.principal
        || !record.definition.learning
        || !record.definition.units.contains(&answer.unit)
        || !crate::claim::claim_consolidatable(body)
        || !crate::claim::claim_evidence_admissible(body)
    {
        return Ok(None);
    }
    let Some(binding) = &record.definition.binding else {
        return Ok(None);
    };
    if predicate(&binding.source) != body.predicate
        || fact.occurred_at < answer.answered_at
        || fact.occurred_at.saturating_sub(answer.answered_at) > binding.horizon
    {
        return Ok(None);
    }
    let (subject, edge_kind, other_endpoint) = match body.subject {
        ClaimSubject::Entity(id) => (id, None, None),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => (source, Some(kind), Some(target)),
    };
    let actor = ScopedReadActorKey::new(record.principal.to_hex()).expect("canonical principal");
    for id in [
        Some(fact.id),
        Some(answer.unit),
        Some(subject),
        other_endpoint,
    ]
    .into_iter()
    .flatten()
    {
        if !readable(store, txn, policy, &actor, &id)? {
            return Ok(None);
        }
    }
    if subject != answer.unit
        && !linked(
            store,
            txn,
            &answer.unit,
            &subject,
            binding.linked_by.as_deref(),
        )?
    {
        return Ok(None);
    }
    let Some(raw) = store.entities.get(txn, answer.claim.as_bytes())? else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("outcome answer header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Ok(None);
    }
    let prediction = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    let encoded = encode(answer)?;
    let expected = rmpv::decode::read_value(&mut encoded.as_slice())
        .map_err(|_| Error::CorruptedIndex("outcome answer value"))?;
    let facets = crate::claim::facet_refs_in_db(&store.edges_out, txn, &answer.claim)?;
    if crate::vault_cleanup::is_archived_in_txn(store, txn, &answer.claim)?
        || !crate::gate::scoped_read_claim_allowed(policy, &actor, &prediction, &facets)
        || prediction.stale
        || prediction.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        || prediction.approval == crate::claim::ClaimApprovalStatus::Rejected
        || prediction.predicate != "judgment.answer"
        || prediction.subject != ClaimSubject::Entity(answer.unit)
        || prediction.value != expected
    {
        return Ok(None);
    }
    let value = match &binding.source {
        OutcomeSource::Stage { campaign } => {
            let stage = crate::campaign::claims::decode_crm_stage_value(&body.value)?;
            if stage.campaign_ref.to_hex() != *campaign {
                return Ok(None);
            }
            stage.stage.0
        }
        OutcomeSource::Edge { relation } => {
            if crate::edge::parse_relation(relation) != edge_kind {
                return Ok(None);
            }
            let provenance = crate::provenance::decode_edge_provenance_body(&body.value)?;
            match provenance.supersession_status {
                crate::provenance::SupersessionStatus::Confirmed => "confirmed",
                crate::provenance::SupersessionStatus::Disputed => "disputed",
                crate::provenance::SupersessionStatus::Retracted => "retracted",
                crate::provenance::SupersessionStatus::Proposed => return Ok(None),
            }
            .into()
        }
        _ if edge_kind.is_some() => return Ok(None),
        _ => body
            .value
            .as_str()
            .map_or_else(|| body.value.to_string(), str::to_owned),
    };
    let Some(label) = binding.mapping.get(&value) else {
        return Ok(None);
    };
    Ok(Some(OutcomeLabel {
        answer: answer.claim,
        fact: fact.id,
        fact_value_hash: value_hash(&body.value)?,
        label: *label,
        noise_weight: binding.noise_weight,
        occurred_at: fact.occurred_at,
    }))
}

fn linked(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    unit: &EntityId,
    subject: &EntityId,
    relation: Option<&str>,
) -> Result<bool> {
    let Some(relation) = relation else {
        return Ok(false);
    };
    for row in store.edges_out.prefix_iter(txn, unit.as_bytes())? {
        let (key, value) = row?;
        let edge = crate::vault::parse_edge_record(&key, &value)?;
        if edge.target == *subject
            && Some(edge.kind) == crate::edge::parse_relation(relation)
            && edge.provenance.is_none_or(|p| {
                p.confirmation_status != crate::edge::EdgeConfirmationStatus::Retracted
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn readable(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    actor: &ScopedReadActorKey,
    id: &EntityId,
) -> Result<bool> {
    if crate::vault_cleanup::is_archived_in_txn(store, txn, id)? {
        return Ok(false);
    }
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("outcome scope header"))?;
    if raw.len() == ENTITY_METADATA_HEADER_LEN {
        return Ok(false);
    }
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(true);
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    let facets = crate::claim::facet_refs_in_db(&store.edges_out, txn, id)?;
    Ok(crate::claim::claim_surfaceable(&body)
        && crate::gate::scoped_read_claim_allowed(policy, actor, &body, &facets))
}

pub(super) fn value_hash(value: &rmpv::Value) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("outcome value encoding"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
