//! Host-driven answer work: observe under principal, invoke provider outside a write transaction,
//! then atomically recheck source, authority, version and pause before settling claims.

mod asker;
mod calls;
mod execution;
mod manual;
mod pump;

pub(crate) use self::asker::{standing_asker, standing_asker_for_question};
use self::calls::graph_proposal;
use self::execution::refresh_with;
pub use self::manual::refresh_standing_question_with;
pub(super) use self::pump::hold_failed;
use self::pump::{due_work, refresh_due_as, role_runner};

use super::backfill::{BackfillAtKey, QUESTION_BACKFILL_AT};
use super::graph_ask::{self, GraphAnswerer, GraphDecision, GraphUnitContext};
use super::reader_authority::question_lane;
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
    /// The context is a backfill join's own sources (FIX 2383): it has no
    /// neighbourhood to recheck, only its sources.
    joined: bool,
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

/// A unit's answerer: the record, the unit, its entity type, its body and,
/// for a backfill join (FIX 2383), the exact sources it is shown in place of
/// its neighbours. `None` leaves the unit unanswered this run.
type UnitAnswer<'a> = dyn FnMut(&QuestionRecord, EntityId, u8, &[u8], Option<&[EntityId]>) -> Result<Option<Answered>>
    + 'a;

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
        asker::RefreshWriter::Caller(actor),
        principal,
        question,
        trigger,
        now,
        &mut |record, unit, _, body, _| {
            answerer(record, unit, body).map(|p| {
                Some(Answered {
                    proposal: Proposed::Proposal(p),
                    context: None,
                })
            })
        },
    )
}

/// [`refresh_question`] by hand through a graph answerer, as the standing
/// pump answers a due question (OF-506): every unit the question's current
/// version covers, each shown with its eligible neighbours and the media
/// its record takes, a full decision keeping its own receipt.
/// `answerer_for` makes the answerer from the question's record once, when
/// the first unit is read. A paused question answers nothing.
pub fn refresh_question_with<A: GraphAnswerer>(
    vault: &Vault,
    actor: WriteActor,
    principal: EntityId,
    question: EntityId,
    now: u64,
    mut answerer_for: impl FnMut(&QuestionRecord) -> Result<A>,
) -> Result<Vec<AnswerRecord>> {
    let mut answerer: Option<A> = None;
    refresh_with(
        vault,
        asker::RefreshWriter::Caller(actor),
        principal,
        question,
        RefreshTrigger::Manual,
        now,
        &mut |record, unit, kind, body, evidence| {
            if answerer.is_none() {
                answerer = Some(answerer_for(record)?);
            }
            let answerer = answerer.as_mut().expect("made above");
            graph_proposal(vault, record, answerer, unit, kind, body, evidence)
        },
    )
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
/// who also writes the answers as itself, under the class the question's
/// version keeps (FIX 1588). Each unit is shown with its
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
        &mut || true,
        |principal| principal_actor(vault, principal),
        answerer_for,
    )
}

/// [`refresh_due_questions_with`] under the responsible-role chain (OF-516).
/// Each due question's person ask goes to its principal as the responsible
/// actor ([`standing_ask_route`]) and climbs to the vault's owners. The run
/// is written by the first live holder of the first role on that chain (the
/// principal itself under the class its question's version keeps, FIX 1588),
/// so a question whose principal is gone runs as an owner, while its ladder call
/// and answers stay the principal's. With no live holder up to the owners the
/// question is held, unanswered, and tried again after
/// [`FAILED_REFRESH_HOLD_SECS`]. `answerer_for` makes each question's
/// answerer from its record, the run's writer and the ask's route.
pub fn refresh_due_questions_by_role<A: GraphAnswerer>(
    vault: &Vault,
    now: u64,
    answerer_for: impl FnMut(&QuestionRecord, WriteActor, AskTo) -> Result<A>,
) -> Result<RefreshBatch> {
    refresh_due_questions_by_role_while(vault, now, &mut || true, answerer_for)
}

/// [`refresh_due_questions_by_role`] under a host's pause (FIX 7376): no
/// next due question starts once `may_start` says no. The one in flight
/// finishes, and the batch so far returns as an ordinary pass. A question
/// left unstarted is neither failed nor held: it stays due for the next pass.
pub fn refresh_due_questions_by_role_while<A: GraphAnswerer>(
    vault: &Vault,
    now: u64,
    may_start: &mut impl FnMut() -> bool,
    mut answerer_for: impl FnMut(&QuestionRecord, WriteActor, AskTo) -> Result<A>,
) -> Result<RefreshBatch> {
    refresh_due_as(
        vault,
        now,
        may_start,
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
            actor: crate::llm::decision::AnswerActor::Actor(principal),
            project: None,
        },
        ceiling: RoleRank::Owner,
        act: AskAct::Judgment,
    }
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

/// The read `principal`'s own question work reads under (FIX 1229): its key
/// as a question's reads build it, with its own live owner authority. A
/// withdrawal wake's carried made_by is admitted through it when the fresh
/// proposal waits.
pub(crate) fn principal_lane(
    vault: &Vault,
    principal: EntityId,
) -> Result<crate::claim::ScopedRead<'_>> {
    let key = {
        let txn = vault.store.env.read_txn()?;
        source_actor_key(vault, &txn, principal, None)?.require_access_grants(Some(principal))
    };
    Ok(question_lane(vault, key))
}

/// Scoped receipt read; past versions remain available after edits and switches.
pub fn answer_records(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<AnswerRecord>> {
    let txn = vault.store.env.read_txn()?;
    answer_records_in_txn(vault, &txn, principal, question)
}

pub(crate) fn answer_records_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<AnswerRecord>> {
    owned_head(vault, txn, principal, question)?;
    QUESTION_ANSWER
        .scan_from(&vault.store, txn, &family_prefix(question, b"answer"))
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

pub(crate) fn trial_source_frontier(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    read_lane: &crate::claim::FrozenReadLane,
    unit: EntityId,
) -> Result<Option<[u8; 32]>> {
    source(
        vault,
        txn,
        principal,
        read_lane,
        WriteActor::new(principal, crate::EdgeActorClass::Human),
        unit,
    )
    .map(|row| row.map(|row| row.frontier))
}

fn source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    read_lane: &crate::claim::FrozenReadLane,
    actor: WriteActor,
    unit: EntityId,
) -> Result<Option<SourceRow>> {
    // Both access checks and the live document projection share this txn.
    // Unscoped storage reads can reveal private NOTE bodies and stale birth text.
    // The manifest permits a keyed read, but relationship membership and
    // AccessGrants belong to the question principal, not the host caller.
    // The principal reads inside the lane its version was saved under, as
    // every other read of the question does (OF-506, FIX 1712).
    let principal_key = read_lane.narrow_in_txn(
        vault,
        txn,
        source_actor_key(vault, txn, principal, None)?.require_access_grants(Some(principal)),
    )?;
    let actor_key = source_actor_key(vault, txn, actor.entity_ref(), Some(actor.actor_class()))?
        .require_access_grants(Some(principal));
    // FIX 7461: each lane also reads under its own reader's live owner
    // authority once its own admission and Grants refuse.
    let Some(raw) = question_lane(vault, principal_key).entity_raw_live_in(txn, &unit)? else {
        return Ok(None);
    };
    // A file-plane ASSET's row holds its manifest: judge, hash and serve the
    // body in its place (FIX 5398).
    let raw = vault.materialized_row_in_txn(txn, &unit, raw)?;
    if question_lane(vault, actor_key)
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
    let document_head = crate::entity_doc::record_head_bytes(&vault.store, txn, &unit)?;
    if let Some(head) = &document_head {
        hasher.update(head);
    }
    if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
        let migrated = document_head.is_some();
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

pub(super) fn source_actor_key(
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

/// Lands one answer to `record`'s version as a proposed claim, stamped for
/// the audience the version names (FIX 1825). An answer
/// resting on a graph context's `rows` reads no wider than any of them, as a
/// one-off graph ask's does; a lone unit bounds it by its own claim terms.
fn land(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    record: &QuestionRecord,
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
        taint = super::standing::constrain_sources(&mut candidate, rows, record.principal)?;
    } else if answer.source_kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        taint = body.source.unwrap_or(ClaimSource::Imported);
        if let Some(inherited) = crate::claim::claim_evidence_taint(&body) {
            taint = crate::dreamer_consolidation::source_meet(taint, inherited);
        }
        // The answer is a new claim: the unit's initial ClaimOf weight is the
        // unit's own birth fact, so the answer is born at the default (FIX 7022).
        if let Some(scope) = crate::claim::without_initial_weight(body.scope) {
            candidate = candidate.with_scope(scope);
        }
        if let Some(world) = body.world {
            candidate = candidate.with_world(world);
        }
    }
    candidate = super::answer_landing::stamp_answer(candidate.with_evidence_taint(taint)?, record)?
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
