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
//! refused, except to an owner's own program (`owner_program_rows`, FIX
//! 5911), whose media calls, video jobs included, spend on the run's line
//! and whose `ai.options` lists them all (FIX 6083). A browser or desktop
//! row drives the run's own guest under the browser pack, its checked
//! connection and the vault's standing grants. The board rows,
//! `self.focus.*` and a keyed `describe`, run the engine's board dispatcher
//! over the agent's own board on the run's own STREAM connection, which goes
//! when the door does. Its `describe(self)` reads the run's own self brief,
//! and its `vault.weave.lens` renders the agent's own lens on the run's
//! line, its card held for the run (FIX 2086). A successful answer the run
//! reads as it stands carries the frame that connection queued, beside its
//! output (FIX 2135). Each row's verb hooks fire once around it.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::authority::VerifiedSlip;
use oneiron::board_verb::BoardVerbCall;
use oneiron::claim::{CallerLocality, ScopedRead, ScopedReadActorKey};
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall, SelfEffect,
};
use oneiron::context_board::StreamConnectionId;
use oneiron::llm::decision::DecisionRung;
use oneiron::llm::decision::questions::{
    closed_outcome_windows, create_question, edit_question, pause_question, question_answers,
    read_question, run_graph_ask_receipted, schedule_backfill, select_graph_units_by_type,
};
use oneiron::llm::media::{AiOperation, Modality};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission};
use oneiron::memory::{
    HostWriteOrigin, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE,
    Memory, MemoryError, MemoryResult, ProducerRows,
};
use oneiron::receipt::{
    GraphAskOutcome, GraphAskRequest, QuestionAnswersRequest, QuestionBackfillRequest,
    QuestionCreateRequest, QuestionEditRequest, QuestionOutcomeWindowsRequest,
    QuestionPauseRequest, QuestionPaused, QuestionReadRequest,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::skill_attribution::{RunWriteToken, with_run_write_token};
use oneiron::task_verb::sdk::{
    self, AgentVerb, AiOptions, AiOptionsRequest, AiVerdictRequest, BoardRefreshRequest,
    BoardSubscriptionRequest, ConnectorAnswerRequest, DescribeRequest, TaskWaveRequest,
};
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{BudgetGuard, EntityId, WriteActor};
use serde_json::Value;

use super::wave_door::resume_held_wave;
use super::{SyncServer, wave_plan, wave_receipt};
use crate::api::{
    RunGuests, VerdictAsker, deliver_run_board_hooks, drop_run_board, execute_run_board_verb,
};
use crate::decision_artifact::HostUnitDecider;
use crate::decision_graph::LadderGraphAnswerer;
use crate::decision_verdict::{HELD_IMAGE, HeldImage, on_caller_payer, run_verdict};
use crate::slide_render::{AdmittedRenderer, RenderRefusal};

mod board_carrier;
mod host_rows;
mod resident_rows;

use self::host_rows::host_row;

/// The host rows whose success lands a turn, which wakes its conversation.
const LANDS_TURN: [AgentVerb; 5] = [
    AgentVerb::SelfMessage,
    AgentVerb::VaultWitness,
    AgentVerb::VaultRoomsSpeak,
    AgentVerb::VaultRoomsOfferAnswer,
    AgentVerb::VaultProjectsRouteTradeoff,
];

/// The door one pumped run binds, under its own agent; a Dreamer turn
/// program's entry binds one too (DOOR-141 PR2).
pub(crate) struct RunHostDoor {
    server: Arc<SyncServer>,
    actor: WriteActor,
    /// The server's runtime: each row runs on one of its blocking threads.
    runtime: tokio::runtime::Handle,
    /// The run's browser and desktop seats: each guest outlives the door,
    /// for the run's next door, and ends with the run or once idle.
    guests: RunGuests,
    /// The run's own board STREAM connection, dropped with the door.
    board: StreamConnectionId,
    /// The run's id, which its live lens cards are held for.
    run_id: EntityId,
    /// The run's name on its model lines.
    run: String,
    /// The line the run's entry in flight spends on, which its `ai.speech`
    /// is admitted on (FIX 3194); empty between entries.
    line: Mutex<Option<RunAdmission>>,
    /// The live, verified slip whose turn woke a Dreamer turn program this
    /// door serves (FIX 8717): the reads this door admits for the run take
    /// its key. Its rows' surfaces take it from the call's origin. `None`
    /// for a pumped run and a program no slip woke.
    proof: Option<VerifiedSlip>,
}

impl RunHostDoor {
    pub(crate) fn new(
        server: &Arc<SyncServer>,
        actor: WriteActor,
        runtime: tokio::runtime::Handle,
        run_id: EntityId,
    ) -> Self {
        Self {
            guests: RunGuests::new(server, run_id),
            board: StreamConnectionId(format!("run:{}", run_id.to_hex())),
            run: format!("agent-run:{}", run_id.to_hex()),
            run_id,
            line: Mutex::new(None),
            server: Arc::clone(server),
            actor,
            runtime,
            proof: None,
        }
    }

    /// This door, bound to the waking slip's live view of the turn program
    /// it serves, when a slip's turn woke it (FIX 8717).
    #[must_use]
    pub(crate) fn with_waking_proof(mut self, proof: Option<VerifiedSlip>) -> Self {
        self.proof = proof;
        self
    }

    /// The run's own surface for a read this door admits: the agent's, on
    /// this device, under the waking slip when one binds the door.
    fn admitting_memory(&self) -> Memory<'_> {
        let memory = self
            .server
            .vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
            .at(CallerLocality::OnDevice);
        match &self.proof {
            Some(proof) => memory.with_read_proof(proof),
            None => memory,
        }
    }

    /// Binds the meter the run's next entry makes its model calls on, and
    /// the payer they bill, so its `ai.speech` spends there too, as its other
    /// model calls do (FIX 3194). `None` clears it once the entry ends.
    pub(crate) fn bind_meter(&self, meter: Option<(BudgetGuard, Option<PayerPerson>)>) {
        let line = meter.map(|(guard, payer)| {
            self.server
                .ai
                .model_runtime()
                .funded_run(self.run.clone(), guard, payer)
        });
        *self.line.lock().unwrap_or_else(PoisonError::into_inner) = line;
    }

    /// CUA E8b: what this run's browser reached for TASK `task`, kept as
    /// the agent's solved-run evidence when its done-means' browser checks
    /// hold on the page (`goal`, under the run's recorded `type_ref`), under
    /// the run's write `origin`. Logs what it came to; never fails the run.
    pub(crate) fn capture_task_run(
        &self,
        origin: &HostWriteOrigin,
        task: EntityId,
        type_ref: oneiron::learning::TypeRef,
        goal: &oneiron::task_verb::DoneMeans,
    ) {
        let memory = agent_memory(&self.server, self.actor, origin, InvocationId::mint());
        // FIX 10723: the capture writes for the run whose lease the origin
        // seals, as the run's own rows do (FIX 3103).
        let run_writes = RunWriteToken::of_origin(origin);
        with_run_write_token(run_writes.as_ref(), || {
            self.guests
                .capture_task_run(&self.server, &memory, origin, task, type_ref, goal);
        });
    }
}

impl AgentVerbDoor for RunHostDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let line = self
            .line
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if call.verb.is_browser() {
            // The run's thread holds the call while its guest acts; its step
            // verdicts spend on the run's line (FIX 3574).
            let memory = agent_memory(&self.server, self.actor, origin, invocation);
            return self.observed(
                call.verb,
                self.guests.call(
                    &self.server,
                    &self.runtime,
                    call,
                    origin,
                    &memory,
                    VerdictAsker::Agent(self.actor, line),
                    self.actor.entity_ref(),
                ),
            );
        }
        let held = matches!(call.verb, AgentVerb::AiVerdict)
            .then(|| self.guests.held_image(&call.input))
            .flatten();
        let resident = resident_row(call.verb, &call.input);
        let (board, run_id) = (self.board.clone(), self.run_id);
        // The run's thread drives its own reactor; the row runs on the
        // server's runtime, which its model rungs block on, and the run's
        // thread waits for it.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = self.actor;
        let origin = origin.clone();
        let verb = call.verb;
        let input = call.input.clone();
        // FIX 3103: the row writes for the run whose lease the origin seals.
        let run_writes = RunWriteToken::of_origin(&origin);
        self.runtime.spawn_blocking(move || {
            let _ = sender.send(with_run_write_token(
                run_writes.as_ref(),
                || match resident {
                    Some(ResidentRow::Board) => {
                        board_as_agent(&server, actor, &origin, invocation, &board, verb, input)
                            .map(|(output, rows)| (output, Some(rows)))
                    }
                    Some(ResidentRow::SelfBrief) => resident_rows::self_brief_as_agent(
                        &server,
                        actor,
                        &origin,
                        invocation,
                        &board,
                        line.as_ref(),
                        input,
                    )
                    .map(|(output, rows)| (output, Some(rows))),
                    Some(ResidentRow::WeaveLens) => resident_rows::weave_lens_as_agent(
                        &server,
                        actor,
                        run_id,
                        &origin,
                        invocation,
                        line.as_ref(),
                        input,
                    )
                    .map(|(output, rows)| (output, Some(rows))),
                    // An owner's own program takes the owner's rows (FIX 5911).
                    None if super::owner_program_rows::is_owner_row(verb) => {
                        super::owner_program_rows::answer(
                            &server,
                            actor,
                            &origin,
                            invocation,
                            verb,
                            input,
                            line.as_ref(),
                        )
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
                },
            ));
        });
        let Ok(answered) = receiver.recv() else {
            return Ok(Err(AgentVerbRefusal {
                code: MEMORY_CODE_INTERNAL.to_owned(),
            }));
        };
        self.observed(
            verb,
            match answered {
                Ok((output, rows)) => Ok(Ok(AgentVerbAnswer::new(output, rows))),
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
            },
        )
    }

    /// A granted `reveal.wait` the run's step made before a park, made again
    /// as the resumed step replays it (FIX 2360): on the agent's own surface,
    /// the value read again under `lease`; nothing is spent, stamped or
    /// extended. A refusal leaves the step its kept answer.
    fn replay_reveal(
        &self,
        call: &SelfAgentVerbCall,
        lease: EntityId,
        origin: &HostWriteOrigin,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let memory = agent_memory(&self.server, self.actor, origin, invocation);
        let answered = serde_json::from_value::<sdk::RevealWaitRequest>(call.input.clone())
            .map_err(|_| MemoryError::bad_request("reveal.wait takes the reveal id"))
            .and_then(|input| sdk::replay_reveal_as_caller(&memory, input, lease))
            .and_then(|answer| {
                serde_json::to_value(answer)
                    .map_err(|_| MemoryError::bad_request("reveal.wait answer does not encode"))
            });
        Ok(match answered {
            Ok(output) => Ok(AgentVerbAnswer::new(output, None)),
            Err(error) => Err(AgentVerbRefusal { code: error.code }),
        })
    }

    /// The run's own calls keep the run's own admission. A consult landing
    /// reads its refs, a TASK binding its TASK and workflow (FIX 5316), and
    /// a search its hits (FIX 5976), and a repo row its repo (FIX 6867), on
    /// the agent's own lane, on this device (DOOR-063): the run holds no
    /// credential, and its lane is never the owner's.
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        let repo = matches!(call, RunCall::Bridge(effect) if effect.is_repo());
        if !repo
            && !matches!(
                call,
                RunCall::Bridge(
                    SelfEffect::ConsultResult
                        | SelfEffect::WorkflowDispatch
                        | SelfEffect::MemorySearch
                )
            )
        {
            return Ok(None);
        }
        self.admitting_memory()
            .read_key()
            .map(Some)
            .map_err(|error| AgentVerbRefusal { code: error.code })
    }

    /// Its keyed search drops only rows the agent's lane may not read.
    fn keyed_search_surfaceable_only(&self) -> bool {
        false
    }

    /// A browser row's refusal words, as the run's guests kept them (FIX 6887).
    fn refusal_words(&self) -> Option<oneiron::code_run::AgentVerbRefusalWords> {
        self.guests.refusal_words()
    }

    /// The run's answer to its own connector call's questions (ONE-2510),
    /// for its agent: checked under that call's grant and sent through the
    /// server's live question registry. It waits on the connector and maybe
    /// the owner on one of the server's blocking threads, and the run's
    /// thread waits for it.
    fn connector_answer(
        &self,
        request: &ConnectorAnswerRequest,
        invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = self.actor;
        let request = request.clone();
        let proof = self.proof.clone();
        self.runtime.spawn_blocking(move || {
            let memory = server
                .vault
                .memory(actor.entity_ref(), actor.actor_class())
                .at(CallerLocality::OnDevice)
                .with_invocation(invocation);
            let memory = match &proof {
                Some(proof) => memory.with_read_proof(proof),
                None => memory,
            };
            let _ = sender
                .send(crate::api::connector_answer_as(&server, &memory, request).and_then(encode));
        });
        Ok(match receiver.recv() {
            // An answer serves no vault rows: the connector's reply is
            // foreign data.
            Ok(Ok(output)) => Ok(AgentVerbAnswer::new(output, Some(Vec::new()))),
            Ok(Err(error)) => Err(AgentVerbRefusal { code: error.code }),
            Err(_) => Err(AgentVerbRefusal {
                code: MEMORY_CODE_INTERNAL.to_owned(),
            }),
        })
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

/// Which of the run's own seats answers a row: its board, its self brief or
/// its agent's weave lens (FIX 2086). `None` for every other row.
#[derive(Clone, Copy)]
enum ResidentRow {
    Board,
    SelfBrief,
    WeaveLens,
}

/// The seat of the run's own that answers `verb` with `input`, if any.
fn resident_row(verb: AgentVerb, input: &Value) -> Option<ResidentRow> {
    if is_board_row(verb, input) {
        return Some(ResidentRow::Board);
    }
    match verb {
        AgentVerb::Describe if input.get("self").and_then(Value::as_bool) == Some(true) => {
            Some(ResidentRow::SelfBrief)
        }
        AgentVerb::VaultWeaveLens => Some(ResidentRow::WeaveLens),
        _ => None,
    }
}

/// Whether a call is a board row: `self.focus.*`, or a `describe` of one
/// board key. `describe(self)` is not: it reads the run's own self brief.
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
/// The rows it answers with are the ones that surface listed as served, and
/// those its row picked beside the surface's reads (`None` when those are
/// not known);
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
) -> MemoryResult<(Value, Option<Vec<EntityId>>)> {
    // The agent's task work waits its turn in the vault's line (Rule 5), as
    // a served caller's does, and runs on it.
    let turn = verb
        .is_task_work()
        .then(|| Arc::new(server.vault.admit_task_work_blocking(actor.entity_ref())));
    let producers = ProducerRows::default();
    let memory = agent_memory(server, actor, origin, invocation)
        .with_task_decisions(server.decision_host().task_decisions()?)
        .listing_producers(&producers);
    let memory = match turn {
        Some(turn) => memory.with_task_work_turn(turn),
        None => memory,
    };
    let name = verb.as_str();
    // The rows an `ai.verdict`'s evidence refs and image resolved to (FIX
    // 5461), and a connector call's passes picked (FIX 5455).
    let mut evidence = Some(Vec::new());
    let output = if served_by_host(verb) {
        verb_hook_boundary::row(&memory, name, input, |input| {
            sdk::validate_input(name, &input)?;
            HELD_IMAGE.sync_scope(held, || {
                host_row(server, actor, &memory, verb, input, line, &mut evidence)
            })
        })?
    } else {
        sdk::invoke(&memory, name, input)?
    };
    if LANDS_TURN.contains(&verb) {
        server
            .ai
            .turn_landed_by(server.vault(), actor.entity_ref(), actor.actor_class());
    }
    let rows = evidence.map(|mut evidence| {
        let mut rows = producers.take();
        rows.append(&mut evidence);
        rows
    });
    Ok((output, rows))
}

/// The agent's own surface for one call, on this device.
pub(super) fn agent_memory<'a>(
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
            | AgentVerb::VaultQuestionsOutcomeWindows
            | AgentVerb::VaultQuestionsAnswers
            | AgentVerb::TasksWave
            | AgentVerb::ConnectorCall
            | AgentVerb::SelfUse
    )
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
/// credential door checks it: a `human` ceiling stays human (FIX 11232).
fn inside_host_dial(
    server: &SyncServer,
    dial: oneiron::llm::decision::DecisionDial,
    verb: AgentVerb,
) -> MemoryResult<oneiron::llm::decision::DecisionDial> {
    server
        .decision_host()
        .dial(dial.ceiling.max(DecisionRung::Big))
        .narrow(dial)
        .map_err(|_| {
            MemoryError::bad_request(format!(
                "{}'s dial widens the host's: start at or above its first rung, end at human or \
                 below, and keep a valid band inside its band",
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
