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
//! inside its narrowing. The standing-question rows store a bare principal
//! the pump answers for later, so they refuse a narrowed record scope.
use std::sync::Arc;

use oneiron::llm::decision::questions::{
    AnswerRecord, QuestionRecord, ScheduledBackfill, answer_records, artifact_ask_records,
    create_question, edit_question, pause_question, question_call_budget, read_question,
    refresh_question_with, run_graph_ask_receipted, schedule_backfill, select_graph_units_by_type,
    standing_ask_route,
};
use oneiron::llm::decision::{DecisionDial, DecisionRung};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::receipt::{
    GraphAskOutcome, GraphAskRequest, QuestionAnswer, QuestionAnswersRequest,
    QuestionBackfillRequest, QuestionCreateRequest, QuestionEditRequest, QuestionPauseRequest,
    QuestionPaused, QuestionReadRequest, QuestionRefreshRequest,
};
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::host_doors::internal;
use crate::auth::CoreAuth;
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
pub(crate) async fn vault_graph_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GraphAskRequest,
) -> MemoryResult<GraphAskOutcome> {
    const VERB: &str = "vault.graph.ask";
    let asker = asker(auth, server, VERB)?;
    input.validate()?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || -> MemoryResult<GraphAskOutcome> {
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

/// `vault.questions.create`: a standing question for the caller, at version
/// 1, unpaused. Its dial must sit inside the host's; the pump answers it as
/// the caller from then on.
pub(crate) async fn vault_questions_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionCreateRequest,
) -> MemoryResult<QuestionRecord> {
    const VERB: &str = "vault.questions.create";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let mut definition = input.definition;
    definition.dial = inside_host_dial(server, definition.dial, VERB)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<QuestionRecord> {
        Ok(create_question(
            server.vault(),
            principal,
            definition,
            oneiron_vault_contract::now_ts(),
        )?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.edit`: the caller's standing question's next version,
/// from a whole replacement definition over `expected_version`. Its dial
/// must sit inside the host's.
pub(crate) async fn vault_questions_edit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionEditRequest,
) -> MemoryResult<QuestionRecord> {
    const VERB: &str = "vault.questions.edit";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let mut definition = input.definition;
    definition.dial = inside_host_dial(server, definition.dial, VERB)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<QuestionRecord> {
        Ok(edit_question(
            server.vault(),
            principal,
            input.id,
            input.expected_version,
            definition,
            oneiron_vault_contract::now_ts(),
        )?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.pause`: pauses the caller's standing question, or
/// resumes it with `paused: false`. Another principal's question is not
/// found.
pub(crate) async fn vault_questions_pause(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionPauseRequest,
) -> MemoryResult<QuestionPaused> {
    const VERB: &str = "vault.questions.pause";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<QuestionPaused> {
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
/// unit that version has not answered.
pub(crate) async fn vault_questions_backfill(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionBackfillRequest,
) -> MemoryResult<ScheduledBackfill> {
    const VERB: &str = "vault.questions.backfill";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<ScheduledBackfill> {
        let now = oneiron_vault_contract::now_ts();
        Ok(schedule_backfill(
            server.vault(),
            principal,
            input.id,
            input.expected_version,
            input.at.unwrap_or(now),
        )?)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.questions.read`: the caller's standing question at its current
/// version or a past one; none when no such question or version is the
/// caller's.
pub(crate) async fn vault_questions_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionReadRequest,
) -> MemoryResult<Option<QuestionRecord>> {
    const VERB: &str = "vault.questions.read";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<Option<QuestionRecord>> {
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

/// `vault.questions.answers`: every answer of the caller's standing
/// question, across its versions, tagged by kind: each graph answer receipt,
/// then each artifact the question asked at its last ask, with where its
/// proposal stands ([`QuestionAnswer::union`]).
pub(crate) async fn vault_questions_answers(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionAnswersRequest,
) -> MemoryResult<Vec<QuestionAnswer>> {
    const VERB: &str = "vault.questions.answers";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<Vec<QuestionAnswer>> {
        let graph = answer_records(server.vault(), principal, input.id)?;
        let asks = artifact_ask_records(server.vault(), principal, input.id)?;
        Ok(QuestionAnswer::union(graph, asks))
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
/// found, and a paused one answers nothing. The ladder runs on a blocking
/// thread.
pub(crate) async fn vault_questions_refresh(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionRefreshRequest,
) -> MemoryResult<Vec<AnswerRecord>> {
    const VERB: &str = "vault.questions.refresh";
    let asker = asker(auth, server, VERB)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<Vec<AnswerRecord>> {
        let vault = server.vault();
        Ok(refresh_question_with(
            vault,
            asker,
            asker.entity_ref(),
            input.id,
            oneiron_vault_contract::now_ts(),
            |record| {
                Ok(LadderGraphAnswerer::routed(
                    &server,
                    record.principal,
                    asker,
                    standing_ask_route(record.principal),
                    record.definition.dial,
                    record.definition.deadline(vault)?,
                )
                .with_criteria(record.definition.criteria.clone())
                .with_posture(record.definition.posture))
            },
        )?)
    })
    .await
    .map_err(|_| internal(VERB))?
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
    let principal = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| refused())?,
        None if auth.is_owner_grade() => server
            .vault()
            .ensure_embedded_owner_actor()
            .map_err(|_| refused())?,
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
/// host's other decisions take, from its first filled rung up to `big`
/// (`DecisionHost::dial`). A dial that starts below that rung, climbs past
/// `big` or changes the band is refused, never stored.
fn inside_host_dial(
    server: &SyncServer,
    dial: DecisionDial,
    verb: &str,
) -> MemoryResult<DecisionDial> {
    let host = server.decision_host().dial(DecisionRung::Big);
    host.narrow(dial).map_err(|_| {
        let first = serde_json::to_value(host.first)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        MemoryError::bad_request_with(
            format!(
                "{verb}'s dial widens the host's: start at or above {first}, end at big or below, \
                 and keep the band {}..{}",
                host.band.low, host.band.high
            ),
            &["Start the dial at or above the host's first rung, end it at big or below, and keep the host's band."],
        )
    })
}
