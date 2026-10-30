//! OF-506's doors (ARCH-0076): a one-off graph ask through the host's
//! decision ladder, and the standing-question verbs the 60 s pump
//! ([`crate::decision_graph`]) serves. The generated HTTP facade handler and
//! the MCP dispatcher both call these through `host_doors`.
//!
//! Each is asked for the caller, by `ai.verdict`'s rule: the slip's
//! principal with its actor class, or the vault's own owner for an
//! owner-grade credential that names none; any other credential is refused.
//! No principal, actor or time comes from the request. `vault.graph.ask`
//! reads every unit under the credential's own lane, so a narrowed slip asks
//! inside its narrowing. The standing-question rows store a principal, with
//! the class it authenticated as (FIX 1588), that the pump answers for later,
//! and the caller's own lane, frozen (OF-506, FIX 1857): create and edit save
//! the version under it, so a narrowed credential's question reads inside its
//! narrowing. The rows that read around that lane still refuse a narrowed
//! record scope.
//!
//! Beside its answer, each door lists the rows that answer names
//! (`host_door_lists`): an answer's claim, its unit, every source its
//! decision names as evidence, each neighbour it left out and the
//! principal it was asked for; a question's principal, units and artifacts.
//! A standing question, its head, its backfills and its artifact asks live
//! in side tables, which hold no row.
use std::sync::Arc;

mod question_answers;
mod question_outcomes;
mod saved_lane;

pub(crate) use self::question_answers::vault_questions_answers;
pub(crate) use self::question_outcomes::{
    vault_questions_outcome_windows, vault_questions_outcomes, vault_questions_outcomes_project,
};

use oneiron::llm::decision::questions::{
    AnswerRecord, GraphAnswerer, GraphDecision, GraphPrediction, GraphUnitContext, QuestionRecord,
    QuestionScheduleHead, ScheduledBackfill, pause_question, question_call_budget, read_question,
    read_question_schedule, refresh_artifact_question_now, refresh_standing_question_with,
    run_graph_ask_receipted, schedule_backfill, select_graph_units_by_type, standing_ask_route,
};
use oneiron::llm::decision::{
    DecisionAudio, DecisionDial, DecisionImage, DecisionQuestion, DecisionRung, TypedDecision,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::receipt::{
    GraphAdmitRequest, GraphAskOutcome, GraphAskRequest, QuestionAnswer, QuestionBackfillRequest,
    QuestionCreateRequest, QuestionEditRequest, QuestionPauseRequest, QuestionPaused,
    QuestionReadRequest, QuestionRefreshRequest, QuestionScheduleRequest,
};
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::host_doors::support::{Listed, hex_rows, internal, naming};
use crate::auth::CoreAuth;
use crate::decision_artifact::HostUnitDecider;
use crate::decision_graph::LadderGraphAnswerer;
use crate::server::SyncServer;

/// `vault.graph.ask`: the caller's typed question over graph units, each
/// unit read under the caller's own access and answered on the host's
/// ladder from its first filled rung up to the request's ceiling (`big` when
/// absent), each on its own clock. A per-ask `posture` stricter than the
/// vault's answers without the rungs that send unit text off the host where
/// it forbids that; a looser one is held at the vault's, by the standing
/// question's rule ([`crate::decision_graph::question_posture`]). Every
/// answer lands as a proposed claim private to the caller, written as the
/// caller; a unit that fails stops the ask and names itself beside the
/// answers already committed. The ladder runs on a blocking thread.
/// Beside it, the rows its outcome names ([`outcome_rows`]).
pub(crate) async fn vault_graph_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraphAskRequest,
) -> Listed<GraphAskOutcome> {
    naming(
        vault_graph_ask_answer(server, auth, input).await,
        outcome_rows,
    )
}

async fn vault_graph_ask_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraphAskRequest,
) -> MemoryResult<GraphAskOutcome> {
    const VERB: &str = "vault.graph.ask";
    let asker = asker(auth, server, VERB)?;
    input.validate()?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    super::clock_ingress::run_blocking(move || -> MemoryResult<GraphAskOutcome> {
        let lane = asker_lane(server.vault(), &auth, asker.entity_ref(), VERB)?;
        let units = match input.select {
            Some(select) => select_graph_units_by_type(&lane, select.entity_type, select.limit)?,
            None => input.units,
        };
        let ceiling = input.ceiling.unwrap_or(DecisionRung::Big);
        let budget = question_call_budget(server.vault(), input.unit_deadline_ms)?;
        let dial = server.decision_host().dial(ceiling);
        let mut answerer = LadderGraphAnswerer::new(&server, asker, dial, budget)?
            .with_posture(input.posture)
            .with_criteria(input.criteria.unwrap_or_default());
        match run_graph_ask_receipted(
            &lane,
            asker,
            input.question,
            &units,
            &mut answerer,
            oneiron_vault_contract::now_ts(),
        ) {
            Ok(receipts) => Ok(GraphAskOutcome::from(receipts)),
            Err(failure) => GraphAskOutcome::from_failure(failure),
        }
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.graph.admit`: the caller's own provider measurement for one
/// graph unit, admitted in place of the host ladder's. The unit and its
/// neighbours are read under the caller's own lane exactly as
/// `vault.graph.ask` reads them, and the engine's graph-ask validation
/// judges the whole submitted decision — receipt question, version and
/// principal (the caller), contract, probability, providers and their
/// provider-bound paired/person readings — before its write transaction
/// re-reads every source and lands the answer as a proposed claim
/// private to the caller. An invalid measurement is refused and mints
/// nothing; a unit the caller cannot read is passed over, as in an ask.
/// Beside it, the rows its outcome names ([`outcome_rows`]).
pub(crate) async fn vault_graph_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraphAdmitRequest,
) -> Listed<GraphAskOutcome> {
    naming(
        vault_graph_admit_answer(server, auth, input).await,
        outcome_rows,
    )
}

async fn vault_graph_admit_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraphAdmitRequest,
) -> MemoryResult<GraphAskOutcome> {
    const VERB: &str = "vault.graph.admit";
    let asker = asker(auth, server, VERB)?;
    input.validate()?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    super::clock_ingress::run_blocking(move || -> MemoryResult<GraphAskOutcome> {
        let lane = asker_lane(server.vault(), &auth, asker.entity_ref(), VERB)?;
        let mut answerer = AdmittedAnswerer {
            decision: Some(input.decision),
        };
        match run_graph_ask_receipted(
            &lane,
            asker,
            input.question,
            &[input.unit],
            &mut answerer,
            oneiron_vault_contract::now_ts(),
        ) {
            Ok(receipts) => Ok(GraphAskOutcome::from(receipts)),
            Err(failure) => GraphAskOutcome::from_failure(failure),
        }
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// The answerer an admission runs under: the caller's submitted
/// measurement, taken once. It measures nothing itself and reads no
/// image or clip; the engine validates the decision it hands back.
struct AdmittedAnswerer {
    decision: Option<TypedDecision>,
}

impl GraphAnswerer for AdmittedAnswerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        _context: &GraphUnitContext,
    ) -> oneiron::Result<Option<GraphPrediction>> {
        Ok(None)
    }

    fn decide(
        &mut self,
        _question: &DecisionQuestion,
        _context: &GraphUnitContext,
        _images: &[DecisionImage],
        _audio: &[DecisionAudio],
    ) -> oneiron::Result<Option<GraphDecision>> {
        match self.decision.take() {
            Some(decision) => Ok(Some(GraphDecision::Decision(Box::new(decision)))),
            None => Err(oneiron::Error::InvalidConfig(
                "a graph admission names one decision".into(),
            )),
        }
    }
}

/// `vault.questions.create`: a standing question for the caller, at version
/// 1, unpaused, keeping the class the caller authenticated as (FIX 1588).
/// Its dial must sit inside the host's; the pump answers it as the caller,
/// under that class, from then on.
/// Beside it, the rows the question names ([`question_rows`]).
pub(crate) async fn vault_questions_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionCreateRequest,
) -> Listed<QuestionRecord> {
    naming(
        vault_questions_create_answer(server, auth, input).await,
        question_rows,
    )
}

async fn vault_questions_create_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionCreateRequest,
) -> MemoryResult<QuestionRecord> {
    const VERB: &str = "vault.questions.create";
    let asker = asker(auth, server, VERB)?;
    let mut definition = input.definition;
    definition.dial = inside_host_dial(server, definition.dial, VERB)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    super::clock_ingress::run_blocking(move || -> MemoryResult<QuestionRecord> {
        saved_lane::create_under_caller_lane(&server, &auth, asker, definition, VERB)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.edit`: the caller's standing question's next version,
/// from a whole replacement definition over `expected_version`, keeping the
/// class the caller authenticated as (FIX 1588). Its dial must sit inside
/// the host's.
/// Beside it, the rows the question names ([`question_rows`]).
pub(crate) async fn vault_questions_edit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionEditRequest,
) -> Listed<QuestionRecord> {
    naming(
        vault_questions_edit_answer(server, auth, input).await,
        question_rows,
    )
}

async fn vault_questions_edit_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionEditRequest,
) -> MemoryResult<QuestionRecord> {
    const VERB: &str = "vault.questions.edit";
    let asker = asker(auth, server, VERB)?;
    let mut definition = input.definition;
    definition.dial = inside_host_dial(server, definition.dial, VERB)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    super::clock_ingress::run_blocking(move || -> MemoryResult<QuestionRecord> {
        saved_lane::edit_under_caller_lane(
            &server,
            &auth,
            asker,
            input.id,
            input.expected_version,
            definition,
            VERB,
        )
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.pause`: pauses the caller's standing question, or
/// resumes it with `paused: false`. Another principal's question is not
/// found. Beside it, no row: the question's head lives in a side table.
pub(crate) async fn vault_questions_pause(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionPauseRequest,
) -> Listed<QuestionPaused> {
    naming(
        vault_questions_pause_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

async fn vault_questions_pause_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionPauseRequest,
) -> MemoryResult<QuestionPaused> {
    const VERB: &str = "vault.questions.pause";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<QuestionPaused> {
        pause_question(server.vault(), principal, input.id, input.paused)?;
        Ok(QuestionPaused {
            id: input.id,
            paused: input.paused,
        })
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.backfill`: schedules the caller's standing question's
/// backfill over `expected_version`, due at `at` or now. The pump runs it
/// as it runs the question's scheduled refresh: once, over each covered
/// unit that version has not answered. Beside it, no row: the backfill
/// lives in a side table.
pub(crate) async fn vault_questions_backfill(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionBackfillRequest,
) -> Listed<ScheduledBackfill> {
    naming(
        vault_questions_backfill_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

async fn vault_questions_backfill_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionBackfillRequest,
) -> MemoryResult<ScheduledBackfill> {
    const VERB: &str = "vault.questions.backfill";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<ScheduledBackfill> {
        let now = oneiron_vault_contract::now_ts();
        Ok(schedule_backfill(
            server.vault(),
            principal,
            input.id,
            input.expected_version,
            input.at.unwrap_or(now),
            input.joins,
        )?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.read`: the caller's standing question at its current
/// version or a past one; none when no such question or version is the
/// caller's.
/// Beside it, the rows the question names ([`question_rows`]), none when
/// it found none.
pub(crate) async fn vault_questions_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionReadRequest,
) -> Listed<Option<QuestionRecord>> {
    naming(
        vault_questions_read_answer(server, auth, input).await,
        |record| record.as_ref().map(question_rows).unwrap_or_default(),
    )
}

async fn vault_questions_read_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionReadRequest,
) -> MemoryResult<Option<QuestionRecord>> {
    const VERB: &str = "vault.questions.read";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<Option<QuestionRecord>> {
        Ok(read_question(
            server.vault(),
            principal,
            input.id,
            input.version,
        )?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.refresh`: refreshes the caller's standing question by
/// hand, now, over every unit its current version covers. The answerer is
/// the resident pump's: the host's ladder under the question's own dial,
/// criteria, posture and call clock, a person ask routed to the question's
/// principal and climbing to the vault's owners. The caller writes the
/// answers as the question's principal; another principal's question is not
/// found, and a paused one answers nothing. An artifact question (FIX 3085)
/// asks its artifacts now through the pump's own unit decider, under the
/// class its version keeps, and answers every ask it has made of them, this
/// one included, as `vault.questions.answers` lists them unpaged; an
/// artifact whose earlier answers still wait for Keep is not asked again.
/// The ladder runs on a blocking thread.
/// Beside it, the rows each answer names ([`question_answer_rows`]).
pub(crate) async fn vault_questions_refresh(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionRefreshRequest,
) -> Listed<Vec<QuestionAnswer>> {
    naming(
        vault_questions_refresh_answer(server, auth, input).await,
        |answers| answers.iter().flat_map(question_answer_rows).collect(),
    )
}

async fn vault_questions_refresh_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionRefreshRequest,
) -> MemoryResult<Vec<QuestionAnswer>> {
    const VERB: &str = "vault.questions.refresh";
    let asker = asker(auth, server, VERB)?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<Vec<QuestionAnswer>> {
        let vault = server.vault();
        let now = oneiron_vault_contract::now_ts();
        let bands = server.decision_host().bands();
        let asked = refresh_artifact_question_now(
            vault,
            asker.entity_ref(),
            input.id,
            now,
            &bands,
            |record, actor| {
                Ok(
                    HostUnitDecider::new(&server, actor.actor_class(), "vault.artifacts.ask")
                        .with_question(&record.definition),
                )
            },
        )?;
        if let Some(asks) = asked {
            return Ok(QuestionAnswer::union(Vec::new(), asks));
        }
        // The answers are written, and the answerer answers, as the asker the
        // question's version keeps (FIX 9176).
        let graph = refresh_standing_question_with(
            vault,
            asker,
            asker.entity_ref(),
            input.id,
            now,
            |record, writer| {
                Ok(LadderGraphAnswerer::routed(
                    &server,
                    record.principal,
                    writer,
                    standing_ask_route(record.principal),
                    record.definition.dial,
                    record.definition.deadline(vault)?,
                )
                .with_criteria(record.definition.criteria.clone())
                .with_posture(record.definition.posture))
            },
        )?;
        Ok(QuestionAnswer::union(graph, Vec::new()))
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.schedule`: the caller's standing question's scheduling
/// head — its current version, whether its schedule is paused, when it last
/// refreshed and the hold a failed refresh left — or none when no such
/// question is the caller's. Beside it, no row: the head lives in a side
/// table.
pub(crate) async fn vault_questions_schedule(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionScheduleRequest,
) -> Listed<Option<QuestionScheduleHead>> {
    naming(
        vault_questions_schedule_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

async fn vault_questions_schedule_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionScheduleRequest,
) -> MemoryResult<Option<QuestionScheduleHead>> {
    const VERB: &str = "vault.questions.schedule";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<Option<QuestionScheduleHead>> {
        Ok(read_question_schedule(server.vault(), principal, input.id)?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// The rows one answer names: its claim, its unit, every source its
/// decision names as evidence (the unit and the neighbors it was shown, at
/// the versions read, and each image or clip's source), each neighbor it
/// left out (one the asker read when the answer landed) and the principal
/// it was asked for.
fn answer_rows(answer: &AnswerRecord) -> Vec<EntityId> {
    decision_rows(&answer.decision)
        .chain([answer.claim, answer.unit])
        .chain(answer.omitted.iter().map(|omitted| omitted.id))
        .collect()
}

/// The rows a decision names: its evidence and its principal.
fn decision_rows(decision: &TypedDecision) -> impl Iterator<Item = EntityId> + '_ {
    decision
        .evidence
        .iter()
        .copied()
        .chain(std::iter::once(decision.receipt.principal))
}

/// The rows a graph ask's outcome names: each answer's ([`answer_rows`]),
/// each unit that abstained or failed, and each declined unit with its
/// decision's evidence, a failed ask's as a finished one's (FIX 1582). A
/// unit the caller cannot read is in none of them.
fn outcome_rows(outcome: &GraphAskOutcome) -> Vec<EntityId> {
    let (answers, abstained, declined, failed_unit) = match outcome {
        GraphAskOutcome::Done {
            answers,
            abstained,
            declined,
        } => (answers, abstained, declined, None),
        GraphAskOutcome::Failed {
            failed_unit,
            answers,
            abstained,
            declined,
            ..
        } => (answers, abstained, declined, *failed_unit),
    };
    answers
        .iter()
        .flat_map(answer_rows)
        .chain(abstained.iter().copied())
        .chain(declined.iter().flat_map(|declined| {
            decision_rows(&declined.decision).chain(std::iter::once(declined.unit))
        }))
        .chain(failed_unit)
        .collect()
}

/// The rows a standing question names: its principal, its units and the
/// artifacts it asks.
fn question_rows(record: &QuestionRecord) -> Vec<EntityId> {
    std::iter::once(record.principal)
        .chain(record.definition.units.iter().copied())
        .chain(
            record
                .definition
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact),
        )
        .collect()
}

/// The rows one of a question's answers names: a graph answer's
/// ([`answer_rows`]), or an artifact ask's artifact and the proposal its
/// answers were held under.
fn question_answer_rows(answer: &QuestionAnswer) -> Vec<EntityId> {
    match answer {
        QuestionAnswer::Graph(answer) => answer_rows(answer),
        QuestionAnswer::Artifact(ask) => {
            let mut rows = hex_rows(ask.proposal_ref.iter());
            rows.push(ask.artifact);
            rows
        }
    }
}

/// Whom `verb` is asked for, by `ai.verdict`'s rule: the slip's principal
/// with its actor class, or the vault's own owner (class human) for an
/// owner-grade credential that names none. The writer is made here, never
/// read from the request.
fn asker(auth: &CoreAuth, server: &SyncServer, verb: &str) -> MemoryResult<WriteActor> {
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is asked for an authenticated principal"),
            &["Present a slip that names its principal, or the owner's own credential."],
        )
    };
    // A self-hosted root or the dev mode asks as the owner its host action
    // names; a hosted operator's root asks for no one (FIX 2222).
    if let Some(action) = crate::api::host_action::host_action_of(server.vault(), auth) {
        return Ok(action.map_err(MemoryError::from)?.actor());
    }
    let principal = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| refused())?,
        None => return Err(refused()),
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    Ok(WriteActor::new(principal, class))
}

/// The caller's own read lane, the one `ai.verdict` reads an image under:
/// its verified slip's key, or the key its principal reads under. An
/// owner-grade credential that names no principal reads as `asker`, the
/// owner the door resolved, with the same owner-grade key.
fn asker_lane<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
    asker: EntityId,
    verb: &str,
) -> MemoryResult<oneiron::claim::ScopedRead<'a>> {
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} reads under the caller's scoped read"),
            &["Present a credential that can read the units."],
        )
    };
    if auth.verified_slip().is_none() && auth.principal_ref().is_none() {
        let key = oneiron::claim::ScopedReadActorKey::with_actor_class(asker.to_hex(), "human")
            .ok_or_else(refused)?;
        return Ok(vault.scoped_read(key.at(auth.locality())));
    }
    crate::api::scoped_read_for_core_auth(vault, auth).map_err(|_| refused())
}

/// A standing question's dial, checked inside the host's own: the dial the
/// host's other decisions take, from its first filled rung up to the
/// question's own ceiling past `big` (`DecisionHost::dial`), so a `human`
/// ceiling stays human and asks the next authorised role (FIX 11232). A dial
/// that starts below that rung or sets a band that is not a valid band
/// inside the host's is refused, never stored.
fn inside_host_dial(
    server: &SyncServer,
    dial: DecisionDial,
    verb: &str,
) -> MemoryResult<DecisionDial> {
    let host = server
        .decision_host()
        .dial(dial.ceiling.max(DecisionRung::Big));
    host.narrow(dial).map_err(|_| {
        let first = serde_json::to_value(host.first)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        MemoryError::bad_request_with(
            format!(
                "{verb}'s dial widens the host's: start at or above {first}, end at human or below, \
                 and set a band with low below high inside {}..{}",
                host.band.low, host.band.high
            ),
            &["Start the dial at or above the host's first rung, end it at human or below, and keep its band inside the host's."],
        )
    })
}
