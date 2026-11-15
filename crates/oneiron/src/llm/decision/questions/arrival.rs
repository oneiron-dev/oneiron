//! Outcome arrival projection in the materializing transaction. No model or timer.

use super::{
    reader_authority::{Reader, store_home},
    records::*,
    store::{
        LabelKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_LABEL, QUESTION_VERSION, VersionKey,
        decode_family, encode, family_prefix,
    },
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject, ScopedReadActorKey};
use crate::gate::PolicyManifestResolution;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::side_table::{self, Named, Raw, SideKey, SideTable};
use crate::store::Store;
pub(super) use crate::store::decision_question_watches::{RESTS_ON, UNIT_WATCH};
use crate::{EntityId, Error, Result, Vault};

/// Key of one predicate watcher registration. Not fixed-width: a variable-length predicate,
/// then a NUL separator, then the watching question's id16. `OutcomeBinding::validate` refuses a
/// predicate containing `\0`, so the separator is unambiguous.
struct WatchKey {
    predicate: String,
    id: EntityId,
}

impl SideKey for WatchKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.predicate.as_bytes());
        out.push(0);
        out.extend_from_slice(self.id.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let split = bytes.len().checked_sub(16)?;
        let (rest, id_bytes) = bytes.split_at(split);
        let (&zero, predicate_bytes) = rest.split_last()?;
        if zero != 0 {
            return None;
        }
        Some(Self {
            predicate: std::str::from_utf8(predicate_bytes).ok()?.to_owned(),
            id: EntityId::from_bytes(id_bytes.try_into().ok()?).ok()?,
        })
    }
}

/// Key of one outcome fact a materializing batch could not judge under its
/// question's saved lane ([`SavedLaneJudge::Deferred`]). Family:
/// `deferred`, suffix: id16(fact). It goes with its question's rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeferredOutcomeKey {
    pub(super) question: EntityId,
    pub(super) fact: EntityId,
}

impl SideKey for DeferredOutcomeKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.question, b"deferred"));
        out.extend_from_slice(self.fact.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (question, suffix) = decode_family(bytes, b"deferred")?;
        Some(Self {
            question,
            fact: EntityId::from_bytes(suffix.try_into().ok()?).ok()?,
        })
    }
}

pub(super) const QUESTION_DEFERRED_OUTCOME: SideTable<DeferredOutcomeKey, (), Named> =
    SideTable::new(&side_table::TYPED_QUESTION);

const QUESTION_WATCH: SideTable<WatchKey, EntityId, Raw> =
    SideTable::new(&side_table::TYPED_QUESTION_WATCH);
pub(super) const PENDING: SideTable<(EntityId, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::TYPED_QUESTION_PENDING);
pub(super) const ROOT_SOURCES: SideTable<(EntityId, EntityId), Vec<EntityId>, Named> =
    SideTable::new(&side_table::TYPED_QUESTION_ROOT_SOURCES);

/// Records what `root`'s newest standing answer rests on besides `root`
/// itself (its neighbours, the sources it names as evidence), so an edit to
/// any of them queues `root`'s arrival. It replaces what the answer before
/// it rested on.
pub(super) fn watch_sources(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    question: EntityId,
    root: EntityId,
    sources: &[EntityId],
) -> Result<()> {
    unwatch_sources(store, txn, question, root)?;
    let sources: std::collections::BTreeSet<EntityId> = sources
        .iter()
        .copied()
        .filter(|source| *source != root)
        .collect();
    if sources.is_empty() {
        return Ok(());
    }
    for source in &sources {
        RESTS_ON.put(store, txn, &(*source, question, root), &())?;
    }
    ROOT_SOURCES.put(
        store,
        txn,
        &(question, root),
        &sources.into_iter().collect::<Vec<_>>(),
    )
}

/// Drops the source watchers `root`'s standing answer registered.
pub(super) fn unwatch_sources(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    question: EntityId,
    root: EntityId,
) -> Result<()> {
    if let Some(old) = ROOT_SOURCES.get(store, txn, &(question, root))? {
        for source in old {
            RESTS_ON.delete(store, txn, &(source, question, root))?;
        }
        ROOT_SOURCES.delete(store, txn, &(question, root))?;
    }
    Ok(())
}
pub(super) fn unwatch_units(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &QuestionRecord,
) -> Result<()> {
    for unit in &record.definition.units {
        UNIT_WATCH.delete(store, txn, &(*unit, record.definition.question.id))?;
        // A queued arrival for a still-covered unit survives the edit; all
        // others are retired by the caller once the new definition is known.
    }
    Ok(())
}

pub(super) fn watch(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &QuestionRecord,
) -> Result<()> {
    if record.definition.refresh.on_arrival {
        for unit in &record.definition.units {
            UNIT_WATCH.put(store, txn, &(*unit, record.definition.question.id), &())?;
        }
    }
    let Some(binding) = &record.definition.binding else {
        return Ok(());
    };
    if !record.definition.learning {
        return Ok(());
    }
    let predicate = predicate(&binding.source).to_owned();
    let id = record.definition.question.id;
    QUESTION_WATCH.put(store, txn, &WatchKey { predicate, id }, &id)
}

/// Undoes [`watch`] for `record`, a question whose one version went with its
/// erased answer (FIX 9918).
pub(super) fn unwatch(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &QuestionRecord,
) -> Result<()> {
    let id = record.definition.question.id;
    for unit in &record.definition.units {
        UNIT_WATCH.delete(store, txn, &(*unit, id))?;
    }
    if let Some(binding) = &record.definition.binding {
        let predicate = predicate(&binding.source).to_owned();
        QUESTION_WATCH.delete(store, txn, &WatchKey { predicate, id })?;
    }
    Ok(())
}

/// The key-prefix (bytes after the table's own declared prefix) matching every watcher
/// registered for `predicate`.
fn watch_key_prefix(predicate: &str) -> Vec<u8> {
    [predicate.as_bytes(), &[0]].concat()
}

fn predicate(source: &OutcomeSource) -> &str {
    match source {
        OutcomeSource::Claim { predicate } | OutcomeSource::Event { predicate } => predicate,
        OutcomeSource::Stage { .. } => "crm.stage",
        OutcomeSource::Edge { .. } => "edge.provenance",
    }
}

/// Where an outcome derivation judges the lane a question's version was
/// saved under (FIX SAVED-QUESTION-OUTCOME-IGNORES-READ-LANE). A live
/// owner's own lane needs no judgment beside its reader's. Every other lane,
/// a narrowed one or the own lane of a principal that is not a live owner
/// (FIX OUTCOME-READER-SKIPS-RELATIONSHIP-ACCESS-GATE), is rebuilt over the
/// principal's key, as refresh rebuilds it (OF-506).
#[derive(Clone, Copy)]
pub(super) enum SavedLaneJudge<'a> {
    /// A vault handle: the lane is rebuilt in the derivation's own
    /// snapshot, and each row the label rests on is read inside it.
    Vault(&'a Vault),
    /// A materializing batch, which holds only the store: the lane cannot
    /// be rebuilt here, so it derives no label. A fact that would label but
    /// for that judgment is marked ([`QUESTION_DEFERRED_OUTCOME`]), and the
    /// question pump's next pass judges it under the lane
    /// ([`project_deferred_outcomes`]), whether its window is open, due or
    /// closed. Every read judges each stored label and window again under a
    /// vault handle: calibration, the outcome labels and the closed windows
    /// (FIX STORED-OUTCOME-READS-SKIP-SAVED-LANE).
    Deferred,
}

/// What a question's saved lane says of the rows an outcome label rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SavedLaneVerdict {
    Reads,
    Refuses,
    /// [`SavedLaneJudge::Deferred`] could not rebuild the lane.
    Deferred,
}

/// [`evaluate_fact`]'s judgment of one fact for one answer.
enum FactJudgment {
    Label(OutcomeLabel),
    NoLabel,
    /// The fact labels the answer unless its saved lane refuses a row, and
    /// [`SavedLaneJudge::Deferred`] could not judge that lane.
    Deferred,
}

/// Called after the batch's final entity and edge state is installed, on both
/// ordinary writes and replicated batches. Question metadata remains local.
/// A question saved under a narrowed lane, or asked by a principal that is
/// not a live owner, derives no label here (`SavedLaneJudge::Deferred`): its
/// matching fact is marked for the question pump's next pass
/// ([`project_deferred_outcomes`]).
pub(crate) fn project_arrivals_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
) -> Result<usize> {
    enqueue_arrivals(store, txn, ids)?;
    project(store, txn, ids, None, SavedLaneJudge::Deferred)
}

/// Queues the batch's actual record and topology changes while projecting
/// outcome facts only from the rows the batch materialized.
pub(crate) fn project_arrivals_for_changes_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    materialized_ids: &std::collections::BTreeSet<EntityId>,
    changed_ids: &std::collections::BTreeSet<EntityId>,
) -> Result<usize> {
    enqueue_arrivals(store, txn, changed_ids)?;
    project(store, txn, materialized_ids, None, SavedLaneJudge::Deferred)
}

fn enqueue_arrivals(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
) -> Result<()> {
    for changed in ids {
        // The questions watching the unit itself, and the roots whose
        // standing answer rests on it.
        let mut roots: Vec<(EntityId, EntityId)> = UNIT_WATCH
            .scan_from(store, txn, changed.as_bytes())?
            .into_iter()
            .map(|((_, question), _)| (question, *changed))
            .collect();
        roots.extend(
            RESTS_ON
                .scan_from(store, txn, changed.as_bytes())?
                .into_iter()
                .map(|((_, question, root), _)| (question, root)),
        );
        for (question, unit) in roots {
            let Some(head) = QUESTION_HEAD.get(store, txn, &super::store::HeadKey(question))?
            else {
                continue;
            };
            let Some(record) = QUESTION_VERSION.get(
                store,
                txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
            )?
            else {
                continue;
            };
            if !head.paused
                && record.definition.refresh.on_arrival
                && record.definition.units.contains(&unit)
            {
                PENDING.put(store, txn, &(question, unit), &EntityId::now())?;
            }
        }
    }
    Ok(())
}

/// The facts of `ids` projected for `question` alone, through `vault`: a
/// narrowed saved lane is judged here ([`SavedLaneJudge::Vault`]).
pub(super) fn project_question_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
    question: EntityId,
) -> Result<usize> {
    project(
        &vault.store,
        txn,
        ids,
        Some(&std::collections::BTreeSet::from([question])),
        SavedLaneJudge::Vault(vault),
    )
}

/// [`project_question_in_txn`] for several questions over one pass of `ids`.
pub(super) fn project_questions_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
    questions: &std::collections::BTreeSet<EntityId>,
) -> Result<usize> {
    project(
        &vault.store,
        txn,
        ids,
        Some(questions),
        SavedLaneJudge::Vault(vault),
    )
}

/// Judges, through `vault`, every outcome fact a materializing batch marked
/// because it could not judge its question's narrowed lane
/// ([`SavedLaneJudge::Deferred`]), and returns how many labels it wrote.
/// It runs on every pass of the question pump, whatever the state of the
/// question's windows: a fact recorded after its window closed, with an
/// event time inside it, labels here as it would have at arrival. Each
/// marker goes in the transaction that judged its fact, labelled or
/// refused; a failure keeps every marker for the next pass.
///
/// # Errors
/// A store, fold, clock or decode failure judging a fact.
pub(super) fn project_deferred_outcomes(vault: &Vault) -> Result<usize> {
    let deferred: std::collections::BTreeMap<EntityId, std::collections::BTreeSet<EntityId>> = {
        let txn = vault.store.env.read_txn()?;
        let mut deferred = std::collections::BTreeMap::<_, std::collections::BTreeSet<_>>::new();
        // Several row families share the declaration; decode only exact keys.
        for row in QUESTION_DEFERRED_OUTCOME.iter_raw_from(&vault.store, &txn, &[])? {
            let (key, _) = row?;
            if let Some(key) = DeferredOutcomeKey::decode_key(&key) {
                deferred.entry(key.question).or_default().insert(key.fact);
            }
        }
        deferred
    };
    if deferred.is_empty() {
        return Ok(0);
    }
    vault.with_write_txn_grouped(|txn| {
        let mut count = 0;
        for (question, facts) in &deferred {
            count += project_question_in_txn(vault, txn, facts, *question)?;
            for fact in facts {
                QUESTION_DEFERRED_OUTCOME.delete(
                    &vault.store,
                    txn,
                    &DeferredOutcomeKey {
                        question: *question,
                        fact: *fact,
                    },
                )?;
            }
        }
        Ok(count)
    })
}

fn project(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
    only: Option<&std::collections::BTreeSet<EntityId>>,
    lane: SavedLaneJudge<'_>,
) -> Result<usize> {
    if QUESTION_WATCH.iter_from(store, txn, &[])?.next().is_none() {
        return Ok(0);
    }
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    let mut count = 0;
    for id in ids {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
        else {
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
        let reaction_event = crate::reaction::outcome_fact_admissible_in(store, txn, *id, &body)?;
        if ((!crate::claim::claim_consolidatable(&body)
            || !crate::claim::claim_evidence_admissible(&body))
            && !reaction_event)
            || !crate::gate::claim_consolidation_eligible_in_txn(
                store,
                txn,
                id,
                crate::gate::ConsolidationReader::ArrivalFact,
            )?
        {
            continue;
        }
        let watchers: Vec<EntityId> = QUESTION_WATCH
            .scan_from(store, txn, &watch_key_prefix(&body.predicate))?
            .into_iter()
            .map(|(_, id)| id)
            .collect();
        let fact = Fact {
            id: *id,
            body: &body,
            occurred_at: header.occurred_start,
        };
        for question in watchers {
            if only.is_some_and(|only| !only.contains(&question)) {
                continue;
            }
            count += project_fact(store, txn, &policy, lane, question, &fact)?;
        }
    }
    Ok(count)
}

fn project_fact(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    policy: &PolicyManifestResolution,
    lane: SavedLaneJudge<'_>,
    question: EntityId,
    fact: &Fact<'_>,
) -> Result<usize> {
    let answers: Vec<AnswerRecord> = QUESTION_ANSWER
        .scan_from(store, txn, &family_prefix(question, b"answer"))?
        .into_iter()
        .map(|(_, answer)| answer)
        .collect();
    let mut count = 0;
    for answer in answers {
        let version = answer.decision.receipt.question_version;
        let Some(record) = QUESTION_VERSION.get(
            store,
            txn,
            &VersionKey {
                id: question,
                version,
            },
        )?
        else {
            continue;
        };
        let label = match judge_fact(store, txn, policy, lane, &record, &answer, fact)? {
            FactJudgment::Label(label) => label,
            FactJudgment::NoLabel => continue,
            FactJudgment::Deferred => {
                QUESTION_DEFERRED_OUTCOME.put(
                    store,
                    txn,
                    &DeferredOutcomeKey {
                        question,
                        fact: fact.id,
                    },
                    &(),
                )?;
                continue;
            }
        };
        let label_key = LabelKey {
            question,
            claim: answer.claim,
            fact: fact.id,
        };
        if QUESTION_LABEL.contains(store, txn, &label_key)? {
            continue;
        }
        QUESTION_LABEL.put(store, txn, &label_key, &label)?;
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
/// Every row the label rests on also reads inside the lane `record` was
/// saved under, as `lane` judges it ([`saved_lane_reads_in_txn`]); a lane
/// [`SavedLaneJudge::Deferred`] cannot judge gives no label here.
pub(super) fn evaluate_fact(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    lane: SavedLaneJudge<'_>,
    record: &QuestionRecord,
    answer: &AnswerRecord,
    fact: &Fact<'_>,
) -> Result<Option<OutcomeLabel>> {
    Ok(
        match judge_fact(store, txn, policy, lane, record, answer, fact)? {
            FactJudgment::Label(label) => Some(label),
            FactJudgment::NoLabel | FactJudgment::Deferred => None,
        },
    )
}

/// [`evaluate_fact`], telling a lane it could not judge apart from a
/// refusal.
fn judge_fact(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    lane: SavedLaneJudge<'_>,
    record: &QuestionRecord,
    answer: &AnswerRecord,
    fact: &Fact<'_>,
) -> Result<FactJudgment> {
    record.definition.validate()?;
    let body = fact.body;
    let reaction_event = crate::reaction::outcome_fact_admissible_in(store, txn, fact.id, body)?;
    if record.schema_version != 1
        || record.definition.question.id != answer.decision.receipt.question
        || record.definition.question.version != answer.decision.receipt.question_version
        || record.principal != answer.decision.receipt.principal
        || !record.definition.learning
        || !record.definition.units.contains(&answer.unit)
        || ((!crate::claim::claim_consolidatable(body)
            || !crate::claim::claim_evidence_admissible(body)) && !reaction_event)
        // A classifier's interpretation is a noisy outcome for another
        // question, never a label that corroborates its own prediction.
        || crate::reaction::outcome_question(body)? == Some(record.definition.question.id)
        || !crate::gate::claim_consolidation_eligible_in_txn(
            store,
            txn,
            &fact.id,
            crate::gate::ConsolidationReader::ArrivalFact,
        )?
    {
        return Ok(FactJudgment::NoLabel);
    }
    let Some(binding) = &record.definition.binding else {
        return Ok(FactJudgment::NoLabel);
    };
    if predicate(&binding.source) != body.predicate
        || fact.occurred_at < answer.answered_at
        || fact.occurred_at.saturating_sub(answer.answered_at) > binding.horizon
    {
        return Ok(FactJudgment::NoLabel);
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
    // FIX 7461: each permission below is the principal's bare read first,
    // then its own live authority.
    let reader = Reader::new(store_home(store), record.principal, actor);
    for id in [
        Some(fact.id),
        Some(answer.unit),
        Some(subject),
        other_endpoint,
    ]
    .into_iter()
    .flatten()
    {
        if !reader.readable_in_txn(txn, policy, &id)? {
            return Ok(FactJudgment::NoLabel);
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
        return Ok(FactJudgment::NoLabel);
    }
    let sources = crate::reaction::outcome_sources(body)?;
    for source in &sources {
        if !reader.readable_in_txn(txn, policy, source)? {
            return Ok(FactJudgment::NoLabel);
        }
    }
    if !answer_live(store, txn, policy, &reader, answer)? {
        return Ok(FactJudgment::NoLabel);
    }
    // The reader's own live authority (FIX 7461) adds nothing outside the
    // saved lane: the lane binds each row beside it.
    let rows: Vec<EntityId> = [fact.id, answer.unit, subject]
        .into_iter()
        .chain(other_endpoint)
        .chain(sources)
        .chain([answer.claim])
        .collect();
    let deferred = match saved_lane_verdict_in_txn(store, lane, txn, record, &rows)? {
        SavedLaneVerdict::Reads => false,
        SavedLaneVerdict::Refuses => return Ok(FactJudgment::NoLabel),
        SavedLaneVerdict::Deferred => true,
    };
    let value = match &binding.source {
        OutcomeSource::Stage { campaign } => {
            let stage = crate::write_envelope::cohort_claims::decode_crm_stage_value(&body.value)?;
            if stage.campaign_ref.to_hex() != *campaign {
                return Ok(FactJudgment::NoLabel);
            }
            stage.stage.0
        }
        OutcomeSource::Edge { relation } => {
            if crate::edge::EdgeKind::from_name(relation) != edge_kind {
                return Ok(FactJudgment::NoLabel);
            }
            let provenance = crate::provenance::decode_edge_provenance_body(&body.value)?;
            match provenance.supersession_status {
                crate::provenance::SupersessionStatus::Confirmed => "confirmed",
                crate::provenance::SupersessionStatus::Disputed => "disputed",
                crate::provenance::SupersessionStatus::Retracted => "retracted",
                crate::provenance::SupersessionStatus::Proposed => {
                    return Ok(FactJudgment::NoLabel);
                }
            }
            .into()
        }
        _ if edge_kind.is_some() => return Ok(FactJudgment::NoLabel),
        _ => body
            .value
            .as_str()
            .map_or_else(|| body.value.to_string(), str::to_owned),
    };
    let Some(label) = binding.mapping.get(&value) else {
        return Ok(FactJudgment::NoLabel);
    };
    if deferred {
        return Ok(FactJudgment::Deferred);
    }
    Ok(FactJudgment::Label(OutcomeLabel {
        answer: answer.claim,
        fact: fact.id,
        fact_value_hash: value_hash(&body.value)?,
        label: *label,
        noise_weight: binding.noise_weight,
        occurred_at: fact.occurred_at,
    }))
}

/// Whether the lane `record`'s version was saved under reads every one of
/// `rows` in `txn`, as `lane` judges it (FIX
/// SAVED-QUESTION-OUTCOME-IGNORES-READ-LANE). The own lane of a principal
/// that is a live owner of the vault (the owners census `store` reads) reads
/// them as the question's reader judges them, so it adds nothing here. Every
/// other lane is rebuilt over the principal's key as refresh rebuilds it
/// (OF-506): a narrowed one held to its frozen bounds, reading nothing once
/// its credential is no longer live; the own lane of any other principal (an
/// agent, a member) under its relationship access gate, which the question's
/// positive-gate reader never applies (FIX
/// OUTCOME-READER-SKIPS-RELATIONSHIP-ACCESS-GATE). Its claims are read at
/// every status: the derivation keeps its own status checks. Without a vault
/// handle such a lane reads nothing ([`SavedLaneJudge::Deferred`]), and so
/// does one whose principal's row is gone. A census that fails to read
/// proves no owner ([`principal_is_live_owner_in`]).
///
/// # Errors
/// A store, fold, clock or decode failure rebuilding the lane or reading a
/// row.
pub(super) fn saved_lane_reads_in_txn(
    store: &Store,
    lane: SavedLaneJudge<'_>,
    txn: &heed::RoTxn<'_>,
    record: &QuestionRecord,
    rows: &[EntityId],
) -> Result<bool> {
    Ok(saved_lane_verdict_in_txn(store, lane, txn, record, rows)? == SavedLaneVerdict::Reads)
}

/// [`saved_lane_reads_in_txn`], telling a lane [`SavedLaneJudge::Deferred`]
/// could not rebuild apart from a refusal.
fn saved_lane_verdict_in_txn(
    store: &Store,
    lane: SavedLaneJudge<'_>,
    txn: &heed::RoTxn<'_>,
    record: &QuestionRecord,
    rows: &[EntityId],
) -> Result<SavedLaneVerdict> {
    if record.read_lane.is_principal() && principal_is_live_owner_in(store, txn, record.principal) {
        return Ok(SavedLaneVerdict::Reads);
    }
    let SavedLaneJudge::Vault(vault) = lane else {
        return Ok(SavedLaneVerdict::Deferred);
    };
    let principal = record.principal;
    let key = match super::refresh::source_actor_key(vault, txn, principal, None) {
        Ok(key) => key.require_access_grants(Some(principal)),
        Err(Error::EntityNotFound) => return Ok(SavedLaneVerdict::Refuses),
        Err(error) => return Err(error),
    };
    let saved = super::reader_authority::question_lane(
        vault,
        record.read_lane.narrow_in_txn(vault, txn, key)?,
    )
    .with_claim_status(crate::ports::ClaimReadStatus::Recorded);
    let policy = saved.live_policy_manifest_in(txn)?;
    for row in rows {
        if !saved.is_ref_readable_with_policy_in(txn, &policy, row)? {
            return Ok(SavedLaneVerdict::Refuses);
        }
    }
    Ok(SavedLaneVerdict::Reads)
}

/// Whether `principal` is a live owner of the vault, by the owners census
/// `store` reads. A census that fails to read (a shared vault left with no
/// live Owner, an undecodable grant) proves no owner: the lane is judged as
/// any other principal's, deferred at a fact's arrival and rebuilt under a
/// vault handle. So a census fault here delays an owner's label rather than
/// failing the write a fact arrives on, and never skips the saved lane.
fn principal_is_live_owner_in(store: &Store, txn: &heed::RoTxn<'_>, principal: EntityId) -> bool {
    store_home(store)
        .owners_in(txn)
        .is_ok_and(|owners| owners.contains(&principal))
}

/// Whether `answer`'s claim still stands as the prediction it recorded: live,
/// unarchived, unrejected, readable by `reader` (its old key's positive gate,
/// else its own live authority, FIX 7461) and an eligible claim input.
pub(super) fn answer_live(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    reader: &Reader<'_>,
    answer: &AnswerRecord,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &answer.claim)?
    else {
        return Ok(false);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("outcome answer header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Ok(false);
    }
    let prediction = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    let encoded = encode(answer)?;
    let expected = rmpv::decode::read_value(&mut encoded.as_slice())
        .map_err(|_| Error::CorruptedIndex("outcome answer value"))?;
    let facets = crate::claim::facet_refs_in_port(store, txn, &answer.claim)?;
    if crate::vault_cleanup::is_archived_in_txn(store, txn, &answer.claim)?
        || prediction.stale
        || prediction.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        || prediction.approval == crate::claim::ClaimApprovalStatus::Rejected
        || prediction.predicate != "judgment.answer"
        || prediction.subject != ClaimSubject::Entity(answer.unit)
        || prediction.value != expected
        // Only the permission widens: the old key's gate, else the reader's
        // own live authority, resolved only once every other check holds.
        || !reader.claim_allowed_in_txn(txn, policy, &prediction, &facets)?
        // The answer is a claim input too: matching its recorded value is not
        // its owner's Clear.
        || !crate::gate::claim_consolidation_eligible_in_txn(
            store,
            txn,
            &answer.claim,
            crate::gate::ConsolidationReader::AnswerPrediction,
        )?
    {
        return Ok(false);
    }
    Ok(true)
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
    for edge in store.port_edges(txn, unit, EdgeDirection::Out, None, None)? {
        let edge = edge?;
        if edge.target == *subject
            && Some(edge.kind) == crate::edge::EdgeKind::from_name(relation)
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
    readable_with(store, txn, id, |body, facets| {
        crate::gate::scoped_read_claim_allowed(policy, actor, body, facets)
    })
}

/// [`readable`]'s row prerequisites, with the CLAIM read judged by `allowed`:
/// an archived, absent, wiped or bodyless row is never readable, any other
/// non-CLAIM row is, and a CLAIM is when it is surfaceable and `allowed`
/// admits its body under its current facets.
pub(super) fn readable_with(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    allowed: impl FnOnce(&ClaimBody, &[EntityId]) -> bool,
) -> Result<bool> {
    if crate::vault_cleanup::is_archived_in_txn(store, txn, id)? {
        return Ok(false);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)? else {
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
    let facets = crate::claim::facet_refs_in_port(store, txn, id)?;
    Ok(crate::claim::claim_surfaceable(&body) && allowed(&body, &facets))
}

pub(super) fn value_hash(value: &rmpv::Value) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("outcome value encoding"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
