//! Host-driven answer work: observe under principal, invoke provider outside a write transaction,
//! then atomically recheck source, authority, version and pause before settling claims.

use super::graph_ask::{self, GraphAnswerer, GraphDecision, GraphUnitContext};
use super::{arrival, records::*, store::*};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject, ScopedReadActorKey};
use crate::llm::decision::{
    AskAct, AskRole, AskRoleResolver, AskTo, DecisionReceipt, HolderKind, PairedReading, RoleRank,
    TypedDecision,
};
use crate::side_table::SideKey;
use crate::{
    ClaimCandidate, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};

struct SourceRow {
    kind: u8,
    raw: Vec<u8>,
    frontier: [u8; 32],
}

struct Prepared {
    unit: EntityId,
    frontier: [u8; 32],
    proposal: Proposed,
    /// The graph context the answerer was shown, rechecked before landing.
    context: Option<GraphUnitContext>,
    arrival_marker: Option<Vec<u8>>,
}

/// One unit's answer, and the graph context it rests on when its answerer
/// was shown one.
struct Answered {
    proposal: Proposed,
    context: Option<GraphUnitContext>,
}

/// One unit's answer: a provider's proposal the engine wraps in its own
/// receipt, or a full ladder decision whose receipt it keeps.
enum Proposed {
    Proposal(AnswerProposal),
    Decision(Box<TypedDecision>),
}

/// A unit's answerer: the record, the unit, its entity type and its body.
/// `None` leaves the unit unanswered this run.
type UnitAnswer<'a> =
    dyn FnMut(&QuestionRecord, EntityId, u8, &[u8]) -> Result<Option<Answered>> + 'a;

/// How long a question whose refresh failed waits before it is tried again,
/// in seconds: a failure is not retried on every pass.
const FAILED_REFRESH_HOLD_SECS: u64 = 300;

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
    refresh_with(
        vault,
        actor,
        principal,
        question,
        trigger,
        now,
        &mut |record, unit, _, body| {
            answerer(record, unit, body).map(|p| {
                Some(Answered {
                    proposal: Proposed::Proposal(p),
                    context: None,
                })
            })
        },
    )
}

fn refresh_with(
    vault: &Vault,
    actor: WriteActor,
    principal: EntityId,
    question: EntityId,
    trigger: RefreshTrigger,
    now: u64,
    answerer: &mut UnitAnswer<'_>,
) -> Result<Vec<AnswerRecord>> {
    let (record, head, units, arrival_marker) = {
        let txn = vault.store.env.read_txn()?;
        let head = owned_head(vault, &txn, principal, question)?;
        let record = QUESTION_VERSION
            .get(
                &vault.store,
                &txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
            )?
            .ok_or(Error::EntityNotFound)?;
        record.definition.validate()?;
        if head.paused {
            return Ok(Vec::new());
        }
        let mut arrival_marker = None;
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
                if !record.definition.refresh.on_arrival || !record.definition.units.contains(&unit)
                {
                    return Ok(Vec::new());
                }
                arrival_marker =
                    arrival::PENDING.get_bytes(&vault.store, &txn, &(question, unit))?;
                if arrival_marker.is_none() {
                    return Ok(Vec::new());
                }
                vec![unit]
            }
        };
        (record, head, units, arrival_marker)
    };
    let mut prepared = Vec::new();
    for unit in units {
        let snapshot = {
            let txn = vault.store.env.read_txn()?;
            source(vault, &txn, principal, actor, unit)?
        };
        let Some(SourceRow {
            kind,
            raw,
            frontier,
        }) = snapshot
        else {
            continue;
        };
        let Some(Answered { proposal, context }) =
            answerer(&record, unit, kind, &raw[ENTITY_METADATA_HEADER_LEN..])?
        else {
            continue;
        };
        match &proposal {
            Proposed::Proposal(proposal) => validate_proposal(&record, proposal)?,
            Proposed::Decision(decision) => validate_decided(&record, principal, decision)?,
        }
        prepared.push(Prepared {
            unit,
            frontier,
            proposal,
            context,
            arrival_marker: {
                let txn = vault.store.env.read_txn()?;
                arrival::PENDING.get_bytes(&vault.store, &txn, &(question, unit))?
            },
        });
    }
    // Grant status is judged at the authorization clock, observed before the
    // write snapshot opens.
    if prepared.iter().any(|p| p.context.is_some()) {
        vault.store.authorization_now()?;
    }
    vault.with_write_txn_grouped(|txn| {
        let current = owned_head(vault, txn, principal, question)?;
        if current.version != head.version
            || current.paused
            || current.last_refresh != head.last_refresh
        {
            return Err(Error::ConcurrentWrite(
                "standing question changed during refresh",
            ));
        }
        if let RefreshTrigger::Arrival(unit) = trigger
            && arrival::PENDING.get_bytes(&vault.store, txn, &(question, unit))? != arrival_marker
        {
            return Err(Error::ConcurrentWrite("standing question arrival consumed"));
        }
        // Every input is checked before the first write. A batch is all-or-nothing.
        // A graph context's neighbours and every source it showed are read
        // again through the principal's lane in this snapshot.
        let lane = if prepared.iter().any(|p| p.context.is_some()) {
            Some(vault.scoped_read(graph_ask::asker_reader_in_txn(vault, txn, principal)?))
        } else {
            None
        };
        let mut inputs = Vec::new();
        for p in &prepared {
            let Some(row) = source(vault, txn, principal, actor, p.unit)? else {
                return Err(Error::ConcurrentWrite("standing question source changed"));
            };
            if row.frontier != p.frontier {
                return Err(Error::ConcurrentWrite("standing question source changed"));
            }
            let rows = match (&p.context, &lane) {
                (Some(context), Some(lane)) => {
                    if !graph_ask::neighbors_unchanged_in_txn(lane, txn, context)? {
                        return Err(Error::ConcurrentWrite("standing question source changed"));
                    }
                    let Some(rows) = graph_ask::sources_unchanged_in_txn(lane, txn, context)?
                    else {
                        return Err(Error::ConcurrentWrite("standing question source changed"));
                    };
                    Some(rows)
                }
                _ => None,
            };
            inputs.push((row, rows));
        }
        let mut answers = Vec::new();
        for (
            p,
            (
                SourceRow {
                    kind,
                    raw,
                    frontier,
                },
                rows,
            ),
        ) in prepared.iter().zip(inputs)
        {
            let decision = match &p.proposal {
                Proposed::Proposal(proposal) => TypedDecision {
                    answer: proposal.answer.clone(),
                    probability: proposal.probability,
                    evidence: p.context.as_ref().map_or_else(
                        || vec![p.unit],
                        |context| context.sources.iter().map(|s| s.id).collect(),
                    ),
                    in_band: proposal
                        .probability
                        .is_some_and(|v| record.definition.dial.band.contains(v)),
                    receipt: DecisionReceipt {
                        question,
                        question_version: head.version,
                        principal,
                        providers: proposal.providers.clone(),
                        band: record.definition.dial.band,
                        band_version: 0,
                        evidence_versions: p
                            .context
                            .as_ref()
                            .map(graph_ask::source_versions)
                            .unwrap_or_default(),
                        cost_per_thousand: None,
                        paired: proposal.paired.clone(),
                        person: Vec::new(),
                        time: None,
                        images: Vec::new(),
                    },
                    human_ask: None,
                },
                Proposed::Decision(decision) => (**decision).clone(),
            };
            let answer = AnswerRecord {
                claim: EntityId::now(),
                unit: p.unit,
                decision,
                frontier,
                source_kind: kind,
                answered_at: now,
            };
            land(vault, txn, actor, principal, &answer, &raw, rows.as_deref())?;
            arrival::watch_sources(
                &vault.store,
                txn,
                question,
                answer.unit,
                &answer.decision.evidence,
            )?;
            QUESTION_ANSWER.put(
                &vault.store,
                txn,
                &AnswerKey {
                    question,
                    claim: answer.claim,
                },
                &answer,
            )?;
            answers.push(answer);
        }
        if matches!(trigger, RefreshTrigger::Schedule) {
            let mut updated = current;
            updated.last_refresh = Some(now);
            updated.retry_at = None;
            for p in &prepared {
                let pending = (question, p.unit);
                if p.arrival_marker.is_some()
                    && arrival::PENDING.get_bytes(&vault.store, txn, &pending)? == p.arrival_marker
                {
                    arrival::PENDING.delete(&vault.store, txn, &pending)?;
                }
            }
            QUESTION_HEAD.put(&vault.store, txn, &HeadKey(question), &updated)?;
        }
        // A held unit keeps its marker, so the pump answers it once its
        // owner has answered.
        if let RefreshTrigger::Arrival(unit) = trigger
            && crate::gate::claim_consolidation_eligible_in_txn(
                &vault.store,
                txn,
                &unit,
                crate::gate::ConsolidationReader::QuestionRefreshSource,
            )?
        {
            arrival::PENDING.delete(&vault.store, txn, &(question, unit))?;
        }
        Ok(answers)
    })
}

/// One failed activation, available to the host for a later retry or report.
pub struct RefreshFailure {
    pub question: EntityId,
    pub trigger: RefreshTrigger,
    pub error: Error,
}

/// Successful answers and individual failures from one pump tick.
#[derive(Default)]
pub struct RefreshBatch {
    pub answers: Vec<AnswerRecord>,
    pub failures: Vec<RefreshFailure>,
}

/// Pump due scheduled and materialized-arrival work. The host calls this on its clock
/// and after ingress; an arrival never runs a provider inside the ingress transaction.
/// A failed question does not withhold independent answers from this tick.
pub fn refresh_due_questions(
    vault: &Vault,
    actor: WriteActor,
    now: u64,
    mut answerer: impl FnMut(&QuestionRecord, EntityId, &[u8]) -> Result<AnswerProposal>,
) -> Result<RefreshBatch> {
    let mut batch = RefreshBatch::default();
    for (principal, question, trigger) in due_work(vault, now)? {
        match refresh_question(
            vault,
            actor,
            principal,
            question,
            trigger,
            now,
            &mut answerer,
        ) {
            Ok(answers) => batch.answers.extend(answers),
            Err(error) => {
                hold_failed(vault, question, now);
                batch.failures.push(RefreshFailure {
                    question,
                    trigger,
                    error,
                });
            }
        }
    }
    Ok(batch)
}

/// [`refresh_due_questions`] through graph answerers, one per question:
/// `answerer_for` makes it from the question's record and its principal,
/// who also writes the answers as itself. Each unit is shown with its
/// eligible neighbours, as a one-off graph ask shows it, and with the images
/// those sources hold when the record's media take images and the answerer
/// reads them; a full decision keeps its own receipt. A question whose
/// answerer cannot be made fails alone. A failed question is held for
/// [`FAILED_REFRESH_HOLD_SECS`] before it is due again.
pub fn refresh_due_questions_with<A: GraphAnswerer>(
    vault: &Vault,
    now: u64,
    answerer_for: impl FnMut(&QuestionRecord, WriteActor) -> Result<A>,
) -> Result<RefreshBatch> {
    refresh_due_as(
        vault,
        now,
        |principal| principal_actor(vault, principal),
        answerer_for,
    )
}

/// [`refresh_due_questions_with`] under the responsible-role chain (OF-516).
/// Each due question's person ask goes to its principal as the responsible
/// actor ([`standing_ask_route`]) and climbs to the vault's owners. The run
/// is written by the first live holder of the first role on that chain, so a
/// question whose principal is gone runs as an owner, while its ladder call
/// and answers stay the principal's. With no live holder up to the owners the
/// question is held, unanswered, and tried again after
/// [`FAILED_REFRESH_HOLD_SECS`]. `answerer_for` makes each question's
/// answerer from its record, the run's writer and the ask's route.
pub fn refresh_due_questions_by_role<A: GraphAnswerer>(
    vault: &Vault,
    now: u64,
    mut answerer_for: impl FnMut(&QuestionRecord, WriteActor, AskTo) -> Result<A>,
) -> Result<RefreshBatch> {
    refresh_due_as(
        vault,
        now,
        |principal| role_runner(vault, &standing_ask_route(principal)),
        |record, actor| answerer_for(record, actor, standing_ask_route(record.principal)),
    )
}

/// Where a standing question's person asks go: to its principal as the
/// responsible actor, climbing to the vault's owners, for a judgment.
#[must_use]
pub fn standing_ask_route(principal: EntityId) -> AskTo {
    AskTo {
        role: AskRole::Responsible {
            actor: principal,
            project: None,
        },
        ceiling: RoleRank::Owner,
        act: AskAct::Judgment,
    }
}

/// The run's writer for `to`: the first live holder of the first role on its
/// chain that has one, a person as a human and a bound agent as an agent.
fn role_runner(vault: &Vault, to: &AskTo) -> Result<WriteActor> {
    let holder = vault
        .next_role(to, None)?
        .and_then(|role| role.holders.into_iter().next())
        .ok_or_else(|| {
            Error::InvalidConfig(
                "no live holder up to the vault's owners runs this standing question".into(),
            )
        })?;
    Ok(WriteActor::new(
        holder.actor,
        match holder.kind {
            HolderKind::Person => crate::EdgeActorClass::Human,
            HolderKind::Agent => crate::EdgeActorClass::Agent,
        },
    ))
}

/// Every due question, run by the writer `runner` names for its principal,
/// through the answerer `answerer_for` makes once per question.
fn refresh_due_as<A: GraphAnswerer>(
    vault: &Vault,
    now: u64,
    mut runner: impl FnMut(EntityId) -> Result<WriteActor>,
    mut answerer_for: impl FnMut(&QuestionRecord, WriteActor) -> Result<A>,
) -> Result<RefreshBatch> {
    let mut batch = RefreshBatch::default();
    for (principal, question, trigger) in due_work(vault, now)? {
        let answered = runner(principal).and_then(|actor| {
            let mut answerer: Option<A> = None;
            refresh_with(
                vault,
                actor,
                principal,
                question,
                trigger,
                now,
                &mut |record, unit, kind, body| {
                    if answerer.is_none() {
                        answerer = Some(answerer_for(record, actor)?);
                    }
                    let answerer = answerer.as_mut().expect("made above");
                    graph_proposal(vault, record, answerer, unit, kind, body)
                },
            )
        });
        match answered {
            Ok(answers) => batch.answers.extend(answers),
            Err(error) => {
                hold_failed(vault, question, now);
                batch.failures.push(RefreshFailure {
                    question,
                    trigger,
                    error,
                });
            }
        }
    }
    Ok(batch)
}

/// Holds a failed question's work until [`FAILED_REFRESH_HOLD_SECS`] after
/// `now`. A hold that cannot be written leaves the question due: the failure
/// is already the caller's to report.
fn hold_failed(vault: &Vault, question: EntityId, now: u64) {
    let held = vault.with_write_txn_grouped(|txn| {
        let Some(mut head) = QUESTION_HEAD.get(&vault.store, txn, &HeadKey(question))? else {
            return Ok(());
        };
        head.retry_at = Some(now.saturating_add(FAILED_REFRESH_HOLD_SECS));
        QUESTION_HEAD.put(&vault.store, txn, &HeadKey(question), &head)
    });
    if let Err(error) = held {
        tracing::warn!(kind = ?error.kind(), "a failed standing question was not held");
    }
}

impl Vault {
    /// When the next standing question falls due, in unix seconds; `None`
    /// when none has work. A past instant is due now. Paused questions,
    /// arrivals on a unit awaiting its owner's answer and questions inside a
    /// failure's hold arm nothing until their hold ends or a write changes
    /// them, so a deadline timer armed from this never spins on them.
    pub fn next_question_refresh_at(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        let mut next: Option<u64> = None;
        let mut arm = |at: u64| {
            if next.is_none_or(|current| at < current) {
                next = Some(at);
            }
        };
        for row in QUESTION_HEAD.iter_raw_from(&self.store, &txn, &[])? {
            let (key, _) = row?;
            let Some(HeadKey(id)) = HeadKey::decode_key(&key) else {
                continue;
            };
            let Some(head) = QUESTION_HEAD.get(&self.store, &txn, &HeadKey(id))? else {
                continue;
            };
            if head.paused {
                continue;
            }
            let record = QUESTION_VERSION
                .get(
                    &self.store,
                    &txn,
                    &VersionKey {
                        id,
                        version: head.version,
                    },
                )?
                .ok_or(Error::CorruptedIndex("question version"))?;
            if let Some(interval) = record.definition.refresh.every_seconds {
                let due = head
                    .last_refresh
                    .unwrap_or(record.created_at)
                    .saturating_add(interval);
                arm(due.max(head.retry_at.unwrap_or(0)));
            }
        }
        for row in arrival::PENDING.iter_from(&self.store, &txn, &[])? {
            let ((question, unit), _) = row?;
            let Some(head) = QUESTION_HEAD.get(&self.store, &txn, &HeadKey(question))? else {
                continue;
            };
            if head.paused {
                continue;
            }
            let Some(record) = QUESTION_VERSION.get(
                &self.store,
                &txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
            )?
            else {
                continue;
            };
            // A held unit keeps its marker; its owner's answer is a claim
            // write, which wakes the timer again.
            if !record.definition.refresh.on_arrival
                || !record.definition.units.contains(&unit)
                || !crate::gate::claim_consolidation_eligible_in_txn(
                    &self.store,
                    &txn,
                    &unit,
                    crate::gate::ConsolidationReader::QuestionRefreshSource,
                )?
            {
                continue;
            }
            arm(head.retry_at.unwrap_or(0));
        }
        Ok(next)
    }
}

/// One unit's answer from a graph answerer, read under `record`'s principal:
/// the unit and its eligible neighbours, as a one-off graph ask reads them.
/// A neighbourhood no one answer can stay inside abstains before any model
/// runs, as the answer would read wider than a source it rests on.
fn graph_proposal(
    vault: &Vault,
    record: &QuestionRecord,
    answerer: &mut impl GraphAnswerer,
    unit: EntityId,
    kind: u8,
    body: &[u8],
) -> Result<Option<Answered>> {
    let lane = vault.scoped_read(graph_ask::asker_reader(vault, record.principal)?);
    let Some(context) = graph_ask::unit_context(&lane, unit, kind, body.to_vec())? else {
        return Ok(None);
    };
    {
        let txn = vault.store.env.read_txn()?;
        let Some(rows) = graph_ask::sources_unchanged_in_txn(&lane, &txn, &context)? else {
            return Ok(None);
        };
        let mut probe = ClaimCandidate::new(
            "judgment.answer",
            ClaimSubject::Entity(unit),
            rmpv::Value::Nil,
            1.0,
        );
        if super::standing::constrain_sources(&mut probe, &rows, record.principal).is_err() {
            return Ok(None);
        }
    }
    let images = if answerer.reads_images() && record.definition.media.images {
        graph_ask::unit_images(&lane, &context)?
    } else {
        Vec::new()
    };
    let audio = if answerer.reads_audio() && record.definition.media.audio {
        graph_ask::unit_audio(&lane, &context)?
    } else {
        Vec::new()
    };
    let question = &record.definition.question;
    let proposal = match answerer.decide(question, &context, &images, &audio)? {
        None => None,
        Some(GraphDecision::Prediction(prediction)) => {
            graph_ask::validate_prediction(question, &prediction)?;
            let paired = prediction
                .paired
                .map(|reading| reading.bind(prediction.provider.clone()))
                .into_iter()
                .collect();
            Some(Proposed::Proposal(AnswerProposal {
                answer: prediction.answer,
                probability: Some(prediction.probability),
                providers: vec![prediction.provider],
                paired,
            }))
        }
        Some(GraphDecision::Decision(decision)) => {
            graph_ask::validate_decision(question, record.principal, &decision)?;
            Some(Proposed::Decision(Box::new(graph_ask::decided(
                &context, &images, &audio, *decision,
            ))))
        }
    };
    Ok(proposal.map(|proposal| Answered {
        proposal,
        context: Some(context),
    }))
}

/// The principal as the writer of its own question's answers.
pub(crate) fn principal_actor(vault: &Vault, principal: EntityId) -> Result<WriteActor> {
    let txn = vault.store.env.read_txn()?;
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &principal)?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("question principal header"))?;
    let class = match header.entity_type {
        crate::registry::ENTITY_TYPE_PERSON => crate::EdgeActorClass::Human,
        crate::registry::ENTITY_TYPE_AGENT_DEF => crate::EdgeActorClass::Agent,
        crate::registry::ENTITY_TYPE_MACHINE => crate::EdgeActorClass::System,
        _ => return Err(Error::EntityNotFound),
    };
    Ok(WriteActor::new(principal, class))
}

/// The scheduled and materialized-arrival work due at `now`, with each
/// question's principal.
fn due_work(vault: &Vault, now: u64) -> Result<Vec<(EntityId, EntityId, RefreshTrigger)>> {
    let work = {
        let txn = vault.store.env.read_txn()?;
        let mut work = Vec::new();
        // Four row families share the declaration; decode only exact head keys.
        for row in QUESTION_HEAD.iter_raw_from(&vault.store, &txn, &[])? {
            let (key, _) = row?;
            let Some(HeadKey(id)) = HeadKey::decode_key(&key) else {
                continue;
            };
            let Some(head) = QUESTION_HEAD.get(&vault.store, &txn, &HeadKey(id))? else {
                continue;
            };
            if head.paused || head.retry_at.is_some_and(|at| at > now) {
                continue;
            }
            let record = QUESTION_VERSION
                .get(
                    &vault.store,
                    &txn,
                    &VersionKey {
                        id,
                        version: head.version,
                    },
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
        for row in arrival::PENDING.iter_from(&vault.store, &txn, &[])? {
            let ((question, unit), _) = row?;
            let Some(head) = QUESTION_HEAD.get(&vault.store, &txn, &HeadKey(question))? else {
                continue;
            };
            if head.paused || head.retry_at.is_some_and(|at| at > now) {
                continue;
            }
            let Some(record) = QUESTION_VERSION.get(
                &vault.store,
                &txn,
                &VersionKey {
                    id: question,
                    version: head.version,
                },
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
    Ok(work)
}

/// Scoped receipt read; past versions remain available after edits and switches.
pub fn answer_records(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<AnswerRecord>> {
    let txn = vault.store.env.read_txn()?;
    owned_head(vault, &txn, principal, question)?;
    QUESTION_ANSWER
        .scan_from(&vault.store, &txn, &family_prefix(question, b"answer"))
        .map(|rows| rows.into_iter().map(|(_, answer)| answer).collect())
}

/// A full decision answers this record's question for `principal`, from
/// rungs inside the record's dial.
fn validate_decided(
    record: &QuestionRecord,
    principal: EntityId,
    decision: &TypedDecision,
) -> Result<()> {
    graph_ask::validate_decision(&record.definition.question, principal, decision)?;
    if decision
        .receipt
        .providers
        .iter()
        .any(|p| p.rung < record.definition.dial.first || p.rung > record.definition.dial.ceiling)
    {
        return Err(Error::InvalidConfig(
            "invalid standing question answer".into(),
        ));
    }
    Ok(())
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
        || !PairedReading::rows_valid(
            &proposal.paired,
            record.definition.question.id,
            &proposal.providers,
        )
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
) -> Result<Option<SourceRow>> {
    // Both access checks and the live document projection share this txn.
    // Unscoped storage reads can reveal private NOTE bodies and stale birth text.
    // The manifest permits a keyed read, but relationship membership and
    // AccessGrants belong to the question principal, not the host caller.
    let principal_key =
        source_actor_key(vault, txn, principal, None)?.require_access_grants(Some(principal));
    let actor_key = source_actor_key(vault, txn, actor.entity_ref(), Some(actor.actor_class()))?
        .require_access_grants(Some(principal));
    let Some(raw) = vault
        .scoped_read(principal_key)
        .entity_raw_live_in(txn, &unit)?
    else {
        return Ok(None);
    };
    if vault
        .scoped_read(actor_key)
        .entity_raw_live_in(txn, &unit)?
        .is_none()
    {
        return Ok(None);
    }
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("question source header"))?;
    // A claim awaiting its owner's answer is no unit to answer yet.
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
        || raw.len() == ENTITY_METADATA_HEADER_LEN
        || (header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
            && !crate::gate::claim_consolidation_eligible_in_txn(
                &vault.store,
                txn,
                &unit,
                crate::gate::ConsolidationReader::QuestionRefreshSource,
            )?)
    {
        return Ok(None);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&raw);
    #[cfg(feature = "sync")]
    let document_head = crate::entity_doc::record_head_bytes(&vault.store, txn, &unit)?;
    #[cfg(feature = "sync")]
    if let Some(head) = &document_head {
        hasher.update(head);
    }
    if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
        #[cfg(feature = "sync")]
        let migrated = document_head.is_some();
        #[cfg(not(feature = "sync"))]
        let migrated = false;
        if !migrated {
            hasher.update(&crate::note::live_frontier_in_txn(vault, txn, unit)?);
        }
    }
    Ok(Some(SourceRow {
        kind: header.entity_type,
        raw,
        frontier: *hasher.finalize().as_bytes(),
    }))
}

fn source_actor_key(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    declared: Option<crate::EdgeActorClass>,
) -> Result<ScopedReadActorKey> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("question actor header"))?;
    let class = declared.unwrap_or(match header.entity_type {
        crate::registry::ENTITY_TYPE_PERSON => crate::EdgeActorClass::Human,
        crate::registry::ENTITY_TYPE_AGENT_DEF => crate::EdgeActorClass::Agent,
        crate::registry::ENTITY_TYPE_MACHINE => crate::EdgeActorClass::System,
        _ => return Err(Error::EntityNotFound),
    });
    if crate::provenance::validate_actor_class(header.entity_type, class).is_err() {
        return Err(Error::EntityNotFound);
    }
    let name = match class {
        crate::EdgeActorClass::Human => "human",
        crate::EdgeActorClass::Agent => "agent",
        crate::EdgeActorClass::System => "system",
    };
    ScopedReadActorKey::with_actor_class(id.to_hex(), name)
        .ok_or(Error::InvariantViolation("question actor key"))
}

/// Lands one answer as a proposed claim private to `principal`. An answer
/// resting on a graph context's `rows` reads no wider than any of them, as a
/// one-off graph ask's does; a lone unit bounds it by its own claim terms.
fn land(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    principal: EntityId,
    answer: &AnswerRecord,
    raw: &[u8],
    rows: Option<&[super::standing::Source]>,
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
    if let Some(rows) = rows {
        taint = super::standing::constrain_sources(&mut candidate, rows, principal)?;
    } else if answer.source_kind == crate::registry::ENTITY_TYPE_CLAIM {
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
        .with_evidence(rmpv::Value::Array(
            answer
                .decision
                .evidence
                .iter()
                .map(|id| rmpv::Value::from(id.to_hex()))
                .collect(),
        ));
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
