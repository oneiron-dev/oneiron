//! A pumped agent run's host door (OF-533): every host row of the SDK verb
//! table, served for the run's own agent, which holds no MCP credential.
//!
//! Each row runs on a fresh surface under the agent, on this device, that
//! carries the origin the run's dispatcher binds: the run's live lease is the
//! creator of any TASK or wave it starts (OF-532), so that work runs inside
//! the run's lease tree, project and spend scope. A memory row takes the one
//! generated dispatcher, with the engine's own actor and Gate checks, so an
//! owner's or a person's row answers an agent with its own refusal. The rows
//! the host serves from its own seats are served as the host serves them for
//! an agent's credential: `ai.verdict`, `vault.graph.ask` and the standing
//! questions on the host's ladder, `vault.recall` and `report` with the
//! host's embedder, a slide review through the host's decider, a deck
//! preview through its review renderer, and
//! `ai.options` from its model runtime. Its `tasks.wave` is its own wave,
//! queued under its lease, where a credential's is the owner's root one. Its
//! `connector.call` goes through the host's connector transports under the
//! agent's own grant. Its `ai.speech` renders on the run's own line, the
//! meter its entry's model calls spend on (FIX 3194); one no provider
//! answered stops the run on the typed outage, which parks it until a
//! provider recovers. Its `ai.options` lists the speech rows that call could
//! take. Any other `ai.*` media call and a hook replay are the owner's, and
//! refused. A browser or desktop row drives the run's own guest under the
//! browser pack, its checked connection and the vault's standing grants. The
//! board rows, `self.focus.*` and a keyed `describe`, run the engine's board
//! dispatcher over the agent's own board on the run's own STREAM connection,
//! which goes when the door does. Each row's verb hooks fire once around it.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::board_verb::BoardVerbCall;
use oneiron::claim::{CallerLocality, ScopedRead, ScopedReadActorKey};
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall,
};
use oneiron::context_board::StreamConnectionId;
use oneiron::llm::decision::DecisionRung;
use oneiron::llm::decision::questions::{
    answer_records, create_question, edit_question, pause_question, read_question,
    run_graph_ask_receipted, schedule_backfill, select_graph_units_by_type,
};
use oneiron::llm::media::{AiOperation, Modality};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission};
use oneiron::memory::{
    HostWriteOrigin, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE,
    Memory, MemoryError, MemoryResult, ProducerRows,
};
use oneiron::receipt::{
    GraphAskOutcome, GraphAskRequest, QuestionAnswersRequest, QuestionBackfillRequest,
    QuestionCreateRequest, QuestionEditRequest, QuestionPauseRequest, QuestionPaused,
    QuestionReadRequest,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{
    self, AgentVerb, AiOptions, AiOptionsRequest, AiVerdictRequest, BoardRefreshRequest,
    BoardSubscriptionRequest, DescribeRequest, TaskWaveRequest,
};
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{BudgetGuard, EntityId, WriteActor};
use serde_json::Value;

use super::{SyncServer, wave_plan, wave_receipt};
use crate::api::{
    RunGuests, VerdictAsker, deliver_run_board_hooks, drop_run_board, execute_run_board_verb,
};
use crate::decision_artifact::HostUnitDecider;
use crate::decision_graph::LadderGraphAnswerer;
use crate::decision_verdict::{HELD_IMAGE, HeldImage, run_verdict};

/// The host rows whose success lands a turn, which wakes its conversation.
const LANDS_TURN: [AgentVerb; 5] = [
    AgentVerb::SelfMessage,
    AgentVerb::VaultWitness,
    AgentVerb::VaultRoomsSpeak,
    AgentVerb::VaultRoomsOfferAnswer,
    AgentVerb::VaultProjectsRouteTradeoff,
];

/// The door one pumped run binds, under its own agent.
pub(super) struct RunHostDoor {
    server: Arc<SyncServer>,
    actor: WriteActor,
    /// The server's runtime: each row runs on one of its blocking threads.
    runtime: tokio::runtime::Handle,
    /// The run's browser and desktop, removed when the door drops.
    guests: RunGuests,
    /// The run's own board STREAM connection, dropped with the door.
    board: StreamConnectionId,
    /// The run's name on its model lines.
    run: String,
    /// The line the run's entry in flight spends on, which its `ai.speech`
    /// is admitted on (FIX 3194); empty between entries.
    line: Mutex<Option<RunAdmission>>,
}

impl RunHostDoor {
    pub(super) fn new(
        server: &Arc<SyncServer>,
        actor: WriteActor,
        runtime: tokio::runtime::Handle,
        run_id: EntityId,
    ) -> Self {
        Self {
            guests: RunGuests::new(server, run_id),
            board: StreamConnectionId(format!("run:{}", run_id.to_hex())),
            run: format!("agent-run:{}", run_id.to_hex()),
            line: Mutex::new(None),
            server: Arc::clone(server),
            actor,
            runtime,
        }
    }

    /// Binds the meter the run's next entry makes its model calls on, and
    /// the payer they bill, so its `ai.speech` spends there too, as its other
    /// model calls do (FIX 3194). `None` clears it once the entry ends.
    pub(super) fn bind_meter(&self, meter: Option<(BudgetGuard, Option<PayerPerson>)>) {
        let line = meter.map(|(guard, payer)| {
            self.server
                .ai
                .model_runtime()
                .funded_run(self.run.clone(), guard, payer)
        });
        *self.line.lock().unwrap_or_else(PoisonError::into_inner) = line;
    }
}

impl AgentVerbDoor for RunHostDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if call.verb.is_browser() {
            // The run's thread holds the call while its guest acts.
            let memory = agent_memory(&self.server, self.actor, origin, invocation);
            return self.guests.call(
                &self.server,
                &self.runtime,
                call,
                origin,
                &memory,
                VerdictAsker::Agent(self.actor),
                self.actor.entity_ref(),
            );
        }
        let held = matches!(call.verb, AgentVerb::AiVerdict)
            .then(|| self.guests.held_image(&call.input))
            .flatten();
        let board = is_board_row(call.verb, &call.input).then(|| self.board.clone());
        // The run's thread drives its own reactor; the row runs on the
        // server's runtime, which its model rungs block on, and the run's
        // thread waits for it.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = self.actor;
        let origin = origin.clone();
        let verb = call.verb;
        let input = call.input.clone();
        let line = self
            .line
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        self.runtime.spawn_blocking(move || {
            let _ = sender.send(match board {
                Some(board) => {
                    board_as_agent(&server, actor, &origin, invocation, &board, verb, input)
                }
                None => answer_as_agent(
                    &server,
                    actor,
                    &origin,
                    invocation,
                    verb,
                    input,
                    held,
                    line.as_ref(),
                ),
            });
        });
        let Ok(answered) = receiver.recv() else {
            return Ok(Err(AgentVerbRefusal {
                code: MEMORY_CODE_INTERNAL.to_owned(),
            }));
        };
        match answered {
            Ok((output, rows)) => Ok(Ok(AgentVerbAnswer {
                output,
                rows: Some(rows),
            })),
            // A verb hook's stop goes back to the run as the typed stop, and
            // a model call no provider answered as the typed outage, which
            // the run parks on (FIX 3194).
            Err(error) => match (error.hook, error.retry_after) {
                (Some(stop), _) => Err(oneiron::Error::from(*stop)),
                (None, Some(retry_after)) if error.code == MEMORY_CODE_MODEL_UNAVAILABLE => {
                    Err(oneiron::Error::ProviderUnavailable { retry_after })
                }
                (None, _) => Ok(Err(AgentVerbRefusal { code: error.code })),
            },
        }
    }

    /// The run's own calls keep the run's own admission.
    fn admit_run_call(
        &self,
        _call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }
}

impl Drop for RunHostDoor {
    fn drop(&mut self) {
        let server = Arc::clone(&self.server);
        let (actor, board) = (self.actor, self.board.clone());
        self.runtime
            .spawn(async move { drop_run_board(&server, actor, &board).await });
    }
}

/// Whether a call is a board row: `self.focus.*`, or a `describe` of one
/// board key. `describe(self)` is not: it reads a credential's self brief.
fn is_board_row(verb: AgentVerb, input: &Value) -> bool {
    match verb {
        AgentVerb::SelfFocusRefresh
        | AgentVerb::SelfFocusSubscribe
        | AgentVerb::SelfFocusUnsubscribe => true,
        AgentVerb::Describe => {
            input.get("key").is_some_and(|key| !key.is_null())
                && input.get("self").and_then(Value::as_bool) != Some(true)
        }
        _ => false,
    }
}

/// Answers one board row for `actor` over the run's own board connection,
/// with its verb hooks once around it; the rows it answers with are every
/// row the board was derived from. The hook rows it shows are delivered once
/// the answer clears those hooks. Blocking: call it on a blocking thread of
/// the server's runtime.
fn board_as_agent(
    server: &Arc<SyncServer>,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
    board: &StreamConnectionId,
    verb: AgentVerb,
    input: Value,
) -> MemoryResult<(Value, Vec<EntityId>)> {
    let memory = agent_memory(server, actor, origin, invocation);
    let name = verb.as_str();
    let mut rows = Vec::new();
    let mut hooks = None;
    let output = verb_hook_boundary::row(&memory, name, input, |input| {
        sdk::validate_input(name, &input)?;
        let call = match verb {
            AgentVerb::SelfFocusRefresh => BoardVerbCall::Refresh {
                frame_epoch: decode::<BoardRefreshRequest>(input)?.frame_epoch,
            },
            AgentVerb::SelfFocusSubscribe => BoardVerbCall::Subscribe {
                scopes: decode::<BoardSubscriptionRequest>(input)?.scopes,
            },
            AgentVerb::SelfFocusUnsubscribe => BoardVerbCall::Unsubscribe {
                scopes: decode::<BoardSubscriptionRequest>(input)?.scopes,
            },
            _ => {
                let request: DescribeRequest = decode(input)?;
                BoardVerbCall::Expand {
                    key: request
                        .key
                        .ok_or_else(|| MemoryError::bad_request("describe names its board key"))?,
                    frame_epoch: request.frame_epoch,
                }
            }
        };
        let (output, served) = tokio::runtime::Handle::current().block_on(
            execute_run_board_verb(server, actor, board, call, &mut hooks),
        )?;
        rows = served;
        Ok(output)
    })?;
    if let Some(hooks) = hooks {
        tokio::runtime::Handle::current().block_on(deliver_run_board_hooks(server, hooks))?;
    }
    Ok((output, rows))
}

/// Answers one host row for `actor`, with its verb hooks once around it, on
/// a fresh surface under the agent that carries `origin` and `invocation`.
/// The rows it answers with are the ones that surface listed as served;
/// `held` is the run's own screenshot an `ai.verdict` may name, and `line`
/// the run's own line its `ai.speech` spends on. Blocking: call it on a
/// blocking thread of the server's runtime.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the agent's call"
)]
pub(crate) fn answer_as_agent(
    server: &SyncServer,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
    verb: AgentVerb,
    input: Value,
    held: Option<HeldImage>,
    line: Option<&RunAdmission>,
) -> MemoryResult<(Value, Vec<EntityId>)> {
    let producers = ProducerRows::default();
    let memory = agent_memory(server, actor, origin, invocation)
        .with_task_decisions(server.decision_host().task_decisions()?)
        .listing_producers(&producers);
    let name = verb.as_str();
    let output = if served_by_host(verb) {
        verb_hook_boundary::row(&memory, name, input, |input| {
            sdk::validate_input(name, &input)?;
            HELD_IMAGE.sync_scope(held, || host_row(server, actor, &memory, verb, input, line))
        })?
    } else {
        sdk::invoke(&memory, name, input)?
    };
    if LANDS_TURN.contains(&verb) {
        server
            .ai
            .turn_landed_by(server.vault(), actor.entity_ref(), actor.actor_class());
    }
    Ok((output, producers.take()))
}

/// The agent's own surface for one call, on this device.
fn agent_memory<'a>(
    server: &'a SyncServer,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
) -> Memory<'a> {
    server
        .vault
        .memory(actor.entity_ref(), actor.actor_class())
        .at(CallerLocality::OnDevice)
        .with_host_origin(origin.clone())
        .with_invocation(invocation)
}

/// Whether the host serves `verb` from its own seats, not the generated
/// dispatcher alone.
fn served_by_host(verb: AgentVerb) -> bool {
    matches!(
        verb,
        AgentVerb::Report
            | AgentVerb::VaultRecall
            | AgentVerb::VaultHooksReplay
            | AgentVerb::VaultArtifactsReviewSlides
            | AgentVerb::VaultArtifactsBodyDeckPreview
            | AgentVerb::AiOptions
            | AgentVerb::AiImage
            | AgentVerb::AiSpeech
            | AgentVerb::AiTranscribe
            | AgentVerb::AiEmbed
            | AgentVerb::AiVideo
            | AgentVerb::AiVideoPoll
            | AgentVerb::AiVideoCancel
            | AgentVerb::AiVerdict
            | AgentVerb::VaultGraphAsk
            | AgentVerb::VaultQuestionsCreate
            | AgentVerb::VaultQuestionsEdit
            | AgentVerb::VaultQuestionsPause
            | AgentVerb::VaultQuestionsBackfill
            | AgentVerb::VaultQuestionsRead
            | AgentVerb::VaultQuestionsAnswers
            | AgentVerb::TasksWave
            | AgentVerb::ConnectorCall
            | AgentVerb::SelfUse
    )
}

/// One row the host serves, asked for the agent: never for a principal or
/// a time the input names.
fn host_row(
    server: &SyncServer,
    actor: WriteActor,
    memory: &Memory<'_>,
    verb: AgentVerb,
    input: Value,
    line: Option<&RunAdmission>,
) -> MemoryResult<Value> {
    let (principal, class) = (actor.entity_ref(), actor.actor_class());
    let vault = server.vault();
    let now = oneiron_vault_contract::now_ts();
    match verb {
        AgentVerb::Report => {
            let request: oneiron::feedback::ReportRequest = decode(input)?;
            request.validate().map_err(MemoryError::from)?;
            let vector = request
                .embedding_text()
                .and_then(|text| server.embed_query(&text).ok());
            encode(memory.report_with_embedding(request, vector.as_deref())?)
        }
        AgentVerb::VaultRecall => {
            encode(server.recall(memory, principal, class, decode(input)?)?)
        }
        AgentVerb::AiVerdict => {
            let request: AiVerdictRequest = decode(input)?;
            let held = HeldImage::in_task(request.image.as_deref());
            // An image is pulled through the agent's own lane before any
            // model reads it, unless it is the run's own held screenshot.
            let lane = match (&request.image, &held) {
                (Some(_), None) => Some(agent_lane(server, actor)?),
                _ => None,
            };
            encode(run_verdict(
                server,
                principal,
                class,
                memory,
                lane.as_ref(),
                held,
                &request,
            )?)
        }
        AgentVerb::VaultGraphAsk => {
            let request: GraphAskRequest = decode(input)?;
            request.validate()?;
            let lane = agent_lane(server, actor)?;
            let units = match request.select {
                Some(select) => {
                    select_graph_units_by_type(&lane, select.entity_type, select.limit)?
                }
                None => request.units,
            };
            let dial = server
                .decision_host()
                .dial(request.ceiling.unwrap_or(DecisionRung::Big));
            let budget = oneiron::llm::decision::questions::question_call_budget(
                server.vault(),
                request.unit_deadline_ms,
            )?;
            let mut answerer = LadderGraphAnswerer::new(server, actor, dial, budget)?
                .with_posture(request.posture)
                .with_criteria(request.criteria.unwrap_or_default());
            encode(
                match run_graph_ask_receipted(
                    &lane,
                    actor,
                    request.question,
                    &units,
                    &mut answerer,
                    now,
                ) {
                    Ok(receipts) => GraphAskOutcome::from(receipts),
                    Err(failure) => GraphAskOutcome::from_failure(failure)?,
                },
            )
        }
        AgentVerb::VaultQuestionsCreate => {
            let request: QuestionCreateRequest = decode(input)?;
            let mut definition = request.definition;
            definition.dial = inside_host_dial(server, definition.dial, verb)?;
            encode(create_question(vault, principal, definition, now)?)
        }
        AgentVerb::VaultQuestionsEdit => {
            let request: QuestionEditRequest = decode(input)?;
            let mut definition = request.definition;
            definition.dial = inside_host_dial(server, definition.dial, verb)?;
            encode(edit_question(
                vault,
                principal,
                request.id,
                request.expected_version,
                definition,
                now,
            )?)
        }
        AgentVerb::VaultQuestionsPause => {
            let request: QuestionPauseRequest = decode(input)?;
            pause_question(vault, principal, request.id, request.paused)?;
            encode(QuestionPaused {
                id: request.id,
                paused: request.paused,
            })
        }
        AgentVerb::VaultQuestionsBackfill => {
            let request: QuestionBackfillRequest = decode(input)?;
            encode(schedule_backfill(
                vault,
                principal,
                request.id,
                request.expected_version,
                request.at.unwrap_or(now),
            )?)
        }
        AgentVerb::VaultQuestionsRead => {
            let request: QuestionReadRequest = decode(input)?;
            encode(read_question(
                vault,
                principal,
                request.id,
                request.version,
            )?)
        }
        AgentVerb::VaultQuestionsAnswers => {
            let request: QuestionAnswersRequest = decode(input)?;
            encode(answer_records(vault, principal, request.id)?)
        }
        AgentVerb::VaultArtifactsReviewSlides => {
            let request: oneiron::blob_artifact::SlideReviewSubmit = decode(input)?;
            let host = server.decision_host();
            encode(memory.artifacts_review_slides_through(
                &request,
                &HostUnitDecider::new(server, class, "vault.artifacts.review_slides"),
                host.dial(DecisionRung::Big),
                &host.bands(),
                crate::slide_render::host_renderer().map(|renderer| {
                    renderer as &dyn oneiron::edit_roundtrip::slides_review::SlideRenderer
                }),
            )?)
        }
        AgentVerb::VaultArtifactsBodyDeckPreview => encode(memory.artifacts_body_deck_preview(
            &decode(input)?,
            crate::slide_render::host_renderer().map(|renderer| {
                renderer as &dyn oneiron::edit_roundtrip::slides_review::SlideRenderer
            }),
        )?),
        AgentVerb::AiOptions => encode(ai_options(server, line, decode(input)?)?),
        // The run's own speech, on the line its entry spends on (FIX 3194).
        AgentVerb::AiSpeech => {
            let line = line.ok_or_else(|| internal(verb))?;
            encode(tokio::runtime::Handle::current().block_on(
                crate::api::ai_speech_for_run(server, line, decode(input)?),
            )?)
        }
        // The run's own wave: planned for its agent and queued on its own
        // surface, whose bound lease is the wave's creator (OF-532).
        AgentVerb::TasksWave => {
            let request: TaskWaveRequest = decode(input)?;
            let lane = agent_lane(server, actor)?;
            let (epic, constraints) =
                wave_plan(server, actor, |id| lane.is_entity_readable(id), &request)?;
            encode(wave_receipt(memory.enqueue_wave_plan(
                epic,
                &request.objective,
                constraints,
                now,
            )?)?)
        }
        // The agent's own grant and gate, under the step's invocation.
        AgentVerb::ConnectorCall => encode(crate::api::connector_call_as(
            server,
            memory,
            decode(input)?,
        )?),
        // The agent's own handle; a connector call under its grant and gate.
        AgentVerb::SelfUse => encode(crate::api::self_use_as(server, memory, decode(input)?)?),
        AgentVerb::VaultHooksReplay => Err(owners(verb, "hook replays are the owner's")),
        _ => Err(owners(verb, "ai.* media calls are the owner's")),
    }
}

/// `ai.options` from the host's model runtime: the rows the agent could call
/// now (FIX 2942). Its `ai.speech` alone is admitted, on `line`, so it lists
/// the speech rows, with what that line has left (FIX 3194); every other
/// `ai.*` call door is the owner's and refuses the agent.
fn ai_options(
    server: &SyncServer,
    line: Option<&RunAdmission>,
    request: AiOptionsRequest,
) -> MemoryResult<AiOptions> {
    let operation = request
        .operation
        .as_deref()
        .map(|name| {
            AiOperation::parse(name).ok_or_else(|| {
                MemoryError::bad_request(
                    "operation is one of text, image, video, speech, transcribe, embed",
                )
            })
        })
        .transpose()?;
    let inputs = request
        .inputs
        .iter()
        .map(|name| {
            serde_json::from_value::<Modality>(Value::String(name.trim().to_owned())).map_err(
                |_| MemoryError::bad_request("inputs are text, image, audio, video or embedding"),
            )
        })
        .collect::<MemoryResult<BTreeSet<_>>>()?;
    let left = line.map(|line| line.read().remaining_units);
    let listed = crate::api::ai::run_options(server, left, operation, &inputs);
    let options = listed
        .options
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|_| internal(AgentVerb::AiOptions))?;
    Ok(AiOptions {
        options,
        media_units_left: listed.media_units_left,
    })
}

/// The agent's own read lane, on this device: what a unit or an image is
/// read under.
fn agent_lane(server: &SyncServer, actor: WriteActor) -> MemoryResult<ScopedRead<'_>> {
    let key = ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or_else(|| internal(AgentVerb::VaultGraphAsk))?;
    Ok(server.vault().scoped_read(key.at(CallerLocality::OnDevice)))
}

/// A standing question's dial, checked inside the host's own, as the
/// credential door checks it.
fn inside_host_dial(
    server: &SyncServer,
    dial: oneiron::llm::decision::DecisionDial,
    verb: AgentVerb,
) -> MemoryResult<oneiron::llm::decision::DecisionDial> {
    server
        .decision_host()
        .dial(DecisionRung::Big)
        .narrow(dial)
        .map_err(|_| {
            MemoryError::bad_request(format!(
                "{}'s dial widens the host's: start at or above its first rung, end at big or \
                 below, and keep its band",
                verb.as_str()
            ))
        })
}

fn owners(verb: AgentVerb, message: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{}: {message}", verb.as_str()),
        &["Ask the owner to make this call."],
    )
}

fn internal(verb: AgentVerb) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{} did not finish on the run's host door", verb.as_str()),
        &["Report this host-door failure."],
    )
}

fn decode<T: serde::de::DeserializeOwned>(input: Value) -> MemoryResult<T> {
    serde_json::from_value(input).map_err(|error| MemoryError::bad_request(error.to_string()))
}

fn encode<T: serde::Serialize>(output: T) -> MemoryResult<Value> {
    serde_json::to_value(output).map_err(|error| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            error.to_string(),
            &["Report this host-door failure."],
        )
    })
}
