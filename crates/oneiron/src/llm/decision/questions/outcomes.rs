//! Idempotent outcome projection over durable facts and immutable question versions.

use super::{
    arrival::SavedLaneJudge,
    records::*,
    store::{
        HeadKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_LABEL, QUESTION_VERSION, VersionKey,
        family_prefix, owned_head,
    },
};
use crate::llm::decision::{DecisionAnswer, DecisionAsk, PersonChangedAnswer};
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
    let Some(facts) = projectable_facts(vault, principal, question)? else {
        return Ok(0);
    };
    vault.with_write_txn_grouped(|txn| {
        super::arrival::project_question_in_txn(vault, txn, &facts, question)
    })
}

/// [`project_bound_outcomes`], answering each label the projection newly
/// bound rather than their count (FIX 11827): the labels the question held
/// before and after it, in the projection's own write.
pub(super) fn project_bound_labels(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<OutcomeLabel>> {
    let Some(facts) = projectable_facts(vault, principal, question)? else {
        return Ok(Vec::new());
    };
    let prefix = family_prefix(question, b"label");
    vault.with_write_txn_grouped(|txn| {
        let held: std::collections::BTreeSet<(EntityId, EntityId)> = QUESTION_LABEL
            .scan_from(&vault.store, txn, &prefix)?
            .into_iter()
            .map(|(_, label)| (label.answer, label.fact))
            .collect();
        if super::arrival::project_question_in_txn(vault, txn, &facts, question)? == 0 {
            return Ok(Vec::new());
        }
        Ok(QUESTION_LABEL
            .scan_from(&vault.store, txn, &prefix)?
            .into_iter()
            .map(|(_, label)| label)
            .filter(|label| !held.contains(&(label.answer, label.fact)))
            .collect())
    })
}

/// Every claim a projection of `principal`'s standing question judges as a
/// fact; `None` when the question is not theirs.
fn projectable_facts(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<Option<std::collections::BTreeSet<EntityId>>> {
    if super::read_question(vault, principal, question, None)?.is_none() {
        return Ok(None);
    }
    let txn = vault.store.env.read_txn()?;
    let facts = crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        &txn,
        crate::registry::ENTITY_TYPE_CLAIM,
        None,
    )?
    .collect::<Result<std::collections::BTreeSet<_>>>()?;
    Ok(Some(facts))
}

/// The stored outcome labels of the caller's standing question that still
/// stand, in label order: each fact is judged again as a calibration pair's
/// is ([`standing_labels_in_txn`]), no probability required. So a label
/// stored past the lane its question was saved under (an old build's own-lane
/// shortcut), or before its principal lost a read of a row it rests on,
/// reads no more (FIX STORED-OUTCOME-READS-SKIP-SAVED-LANE). Another
/// principal's question is not found, as its answers are not. A caller toward
/// `destination` gets no label derived from a row a world withheld from its
/// machine keeps (mesh PR2b), as [`calibration_pairs`] pairs none.
pub fn outcome_labels(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<crate::settings::ReadDestination>,
) -> Result<Vec<OutcomeLabel>> {
    Ok(
        outcome_labels_with_rows(vault, principal, question, destination)?
            .into_iter()
            .map(|(label, _)| label)
            .collect(),
    )
}

/// [`outcome_labels`], each label beside every row it was derived from, as a
/// calibration pair names them.
pub(super) fn outcome_labels_with_rows(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<crate::settings::ReadDestination>,
) -> Result<Vec<(OutcomeLabel, Vec<EntityId>)>> {
    let txn = vault.store.env.read_txn()?;
    owned_head(vault, &txn, principal, question)?;
    let kept = crate::settings::device_local_worlds_for(vault, &txn, &destination.into())?;
    let answers = stored_answers(vault, &txn, question)?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    Ok(
        standing_labels_in_txn(vault, &txn, &policy, principal, question, &answers, &kept)?
            .into_iter()
            .map(|standing| (standing.label, standing.derived_from))
            .collect(),
    )
}

/// The answers stored for `question`, across its versions.
pub(super) fn stored_answers(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    question: EntityId,
) -> Result<Vec<AnswerRecord>> {
    Ok(QUESTION_ANSWER
        .scan_from(&vault.store, txn, &family_prefix(question, b"answer"))?
        .into_iter()
        .map(|(_, answer)| answer)
        .collect())
}

/// One stored outcome label that still stands, beside the answer it labels
/// and every row it was derived from.
pub(super) struct StandingLabel<'a> {
    pub(super) answer: &'a AnswerRecord,
    pub(super) label: OutcomeLabel,
    pub(super) derived_from: Vec<EntityId>,
}

/// The stored labels of `question` that still stand in `txn`, in label order
/// (FIX STORED-OUTCOME-READS-SKIP-SAVED-LANE). A label stands when it labels
/// one of `answers`, the question's stored answers, the version that answer
/// was given under is `principal`'s, and its fact, evaluated again as at its
/// arrival under the lane that version was saved under
/// ([`SavedLaneJudge::Vault`]: a live owner's own lane, else the lane rebuilt
/// over the principal's live key, its relationship access gate included),
/// gives the very label the store holds. A caller toward `kept` worlds gets
/// none derived from a row they withhold.
pub(super) fn standing_labels_in_txn<'a>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    principal: EntityId,
    question: EntityId,
    answers: &'a [AnswerRecord],
    kept: &std::collections::BTreeSet<EntityId>,
) -> Result<Vec<StandingLabel<'a>>> {
    let mut standing = Vec::new();
    for (_, outcome) in
        QUESTION_LABEL.scan_from(&vault.store, txn, &family_prefix(question, b"label"))?
    {
        let Some(answer) = answers.iter().find(|a| a.claim == outcome.answer) else {
            continue;
        };
        let Some(record) = QUESTION_VERSION.get(
            &vault.store,
            txn,
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
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &outcome.fact)?
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
        if !kept.is_empty() && kept_any(vault, txn, kept, &derived_from)? {
            continue;
        }
        let fact = super::arrival::Fact {
            id: outcome.fact,
            body: &body,
            occurred_at: header.occurred_start,
        };
        if super::arrival::evaluate_fact(
            &vault.store,
            txn,
            policy,
            SavedLaneJudge::Vault(vault),
            &record,
            answer,
            &fact,
        )?
        .as_ref()
            != Some(&outcome)
        {
            continue;
        }
        standing.push(StandingLabel {
            answer,
            label: outcome,
            derived_from,
        });
    }
    Ok(standing)
}

/// Labels are observations of immutable answer receipts. Current facts and
/// authority are checked again within one read snapshot before returning them.
/// Each pair names the question version, route, routing policy revision and
/// answering pins its answer's receipt holds, beside its original probability.
/// A window that closed in silence pairs its answer with the binding's
/// silence label; such a pair names the answer as its own fact. Each answer a
/// person changed pairs too ([`person_changed_pairs`]).
/// A caller toward `destination` gets no pair derived from a row a world
/// withheld from its machine keeps, and each pair names the rows it was
/// derived from.
pub fn calibration_pairs(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<crate::settings::ReadDestination>,
) -> Result<Vec<CalibrationPair>> {
    let txn = vault.store.env.read_txn()?;
    calibration_pairs_in_txn(vault, &txn, principal, question, destination)
}

pub(crate) fn calibration_pairs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<crate::settings::ReadDestination>,
) -> Result<Vec<CalibrationPair>> {
    let kept = crate::settings::device_local_worlds_for(vault, txn, &destination.into())?;
    let Some(head) = QUESTION_HEAD.get(&vault.store, txn, &HeadKey(question))? else {
        return Ok(Vec::new());
    };
    let Some(current) = QUESTION_VERSION.get(
        &vault.store,
        txn,
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
    let answers = stored_answers(vault, txn, question)?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let mut pairs = Vec::new();
    for standing in
        standing_labels_in_txn(vault, txn, &policy, principal, question, &answers, &kept)?
    {
        let Some(probability) = standing.answer.decision.probability else {
            continue;
        };
        pairs.push(super::route_calibration::answer_pair(
            standing.answer,
            probability,
            standing.label,
            standing.derived_from,
        ));
    }
    // A window that closed in silence labels its answer by the binding's
    // silence label, unless a fact in the window has labelled it since.
    for (_, close) in super::windows::QUESTION_WINDOW.scan_from(
        &vault.store,
        txn,
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
            txn,
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
            || (!kept.is_empty() && kept_any(vault, txn, &kept, &derived_from)?)
            || !super::windows::silence_stands(
                &vault.store,
                txn,
                &policy,
                SavedLaneJudge::Vault(vault),
                &record,
                answer,
            )?
            || super::windows::fact_labelled(
                &vault.store,
                txn,
                &policy,
                SavedLaneJudge::Vault(vault),
                &record,
                answer,
            )?
        {
            continue;
        }
        pairs.push(super::route_calibration::answer_pair(
            answer,
            probability,
            OutcomeLabel {
                answer: answer.claim,
                fact: answer.claim,
                fact_value_hash: super::windows::silence_hash()?,
                label,
                noise_weight: binding.noise_weight,
                occurred_at: close.ends_at,
            },
            derived_from,
        ));
    }
    // A person who changed the model's answer labels it too (OF-516).
    pairs.extend(person_changed_pairs_in_txn(
        vault, txn, principal, question, &kept,
    )?);
    Ok(pairs)
}

/// Ask-up changed-answer labels (OF-516): each time a person changed the
/// model's answer to `question` for `principal`, the model's prior answer and
/// its probability are paired with the person's answer as the outcome. For a
/// yes/no question the label is the person's answer, as a fact's mapped value
/// is; for any other the label says the prior held, which a changed answer
/// never does. A record without a prior probability pairs nothing. The
/// Coach's threshold run marks the records it read and keeps them, so a pair
/// stays readable after it (FIX 566). A saved question's record pairs only
/// as the answered change of the ask it is bound to, and only when the lane
/// its version was saved under reads the rows the person answered over. A
/// caller toward `destination` gets no pair from a row a world withheld from
/// its machine keeps. [`calibration_pairs`] carries these pairs beside the
/// outcome pairs.
pub fn person_changed_pairs(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<crate::settings::ReadDestination>,
) -> Result<Vec<CalibrationPair>> {
    let txn = vault.store.env.read_txn()?;
    let kept = crate::settings::device_local_worlds_for(vault, &txn, &destination.into())?;
    person_changed_pairs_in_txn(vault, &txn, principal, question, &kept)
}

/// [`person_changed_pairs`] in the caller's snapshot, past the rows `kept`
/// worlds withhold. A saved question's record pairs only when the lane its
/// version was saved under reads the rows the person answered over
/// ([`person_change_in_saved_lane`], FIX PERSON-CHANGED-PAIRS-SKIP-SAVED-LANE).
/// A question no one saved (a catalogue question) has no such lane, and its
/// records pair as they are.
fn person_changed_pairs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    question: EntityId,
    kept: &std::collections::BTreeSet<EntityId>,
) -> Result<Vec<CalibrationPair>> {
    let records: Vec<(EntityId, PersonChangedAnswer)> = PERSON_CHANGED
        .scan(&vault.store, txn)?
        .into_iter()
        .filter(|(_, record)| record.question == question && record.principal == principal)
        .collect();
    // A saved question's asks, each by its id: the source its person-changed
    // record is bound to.
    let saved = !records.is_empty()
        && QUESTION_HEAD
            .get(&vault.store, txn, &HeadKey(question))?
            .is_some();
    let asks: std::collections::BTreeMap<EntityId, DecisionAsk> = if saved {
        vault
            .question_decision_asks_in_txn(txn, question)?
            .into_iter()
            .map(|ask| (ask.id, ask))
            .collect()
    } else {
        std::collections::BTreeMap::new()
    };
    let mut pairs = Vec::new();
    for (source, record) in records {
        let Some(probability) = record.prior_probability else {
            continue;
        };
        if saved && !person_change_in_saved_lane(vault, txn, &record, asks.get(&source))? {
            continue;
        }
        let derived_from = vec![question, source];
        if !kept.is_empty() && kept_any(vault, txn, kept, &derived_from)? {
            continue;
        }
        let label = match (&record.prior, &record.person) {
            (DecisionAnswer::Noul(_), DecisionAnswer::Noul(person)) => *person,
            (prior, person) => prior == person,
        };
        let person = serde_json::to_vec(&record.person)
            .map_err(|_| crate::Error::InvariantViolation("encode a person's answer"))?;
        let occurred_at =
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &source)?
                .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
                .map_or(0, |header| header.occurred_start);
        // The prior went up to the person rung; its record keeps the pin that read it, and no
        // receipt.
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
            question_version: record.question_version,
            route: DecisionRoute::Person,
            policy: None,
            providers: vec![record.prior_provider],
            derived_from,
        });
    }
    Ok(pairs)
}

/// Whether `record` is its `ask`'s answered change and the lane its question
/// version was saved under reads every row the person answered over (FIX
/// PERSON-CHANGED-PAIRS-SKIP-SAVED-LANE): the evidence the ask was put over,
/// or the version's units for an ask put over none (a health ask). The ask
/// must be the record's: of its version and principal, answered with its
/// person's answer as a change, as both answer writers keep them in one
/// write. A record a host put under an open ask, or under an ask of another
/// version, borrows a lane that never judged that ask. Neither the ask's id
/// nor the question's names a row, so neither is judged. The lane is rebuilt
/// as an outcome label's is ([`super::arrival::saved_lane_reads_in_txn`]): a
/// live owner's own lane reads them, any other is held to its frozen bounds
/// and its principal's relationship access gate in this snapshot. An ask or a
/// version the vault no longer holds, or a version another principal saved,
/// reads nothing.
fn person_change_in_saved_lane(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &PersonChangedAnswer,
    ask: Option<&DecisionAsk>,
) -> Result<bool> {
    let Some(ask) = ask else {
        return Ok(false);
    };
    let answered_change = ask
        .answer
        .as_ref()
        .is_some_and(|answer| answer.changed && answer.answer == record.person);
    if !answered_change
        || ask.question.version != record.question_version
        || !ask.principal.is(record.principal)
    {
        return Ok(false);
    }
    let evidence = ask.evidence.as_slice();
    let Some(version) = QUESTION_VERSION.get(
        &vault.store,
        txn,
        &VersionKey {
            id: record.question,
            version: record.question_version,
        },
    )?
    else {
        return Ok(false);
    };
    if version.principal != record.principal {
        return Ok(false);
    }
    let rows: &[EntityId] = if evidence.is_empty() {
        &version.definition.units
    } else {
        evidence
    };
    super::arrival::saved_lane_reads_in_txn(
        &vault.store,
        SavedLaneJudge::Vault(vault),
        txn,
        &version,
        rows,
    )
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
