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
//! host's embedder, a slide review through the host's decider, and
//! `ai.options` from its model runtime. An `ai.*` media call and a hook
//! replay are the owner's, and refused. A browser or desktop row drives the
//! run's own guest under the browser pack, its checked connection and the
//! vault's standing grants. Each row's verb hooks fire once around it.
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use oneiron::claim::{CallerLocality, ScopedRead, ScopedReadActorKey};
use oneiron::code_run::{AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall};
use oneiron::llm::decision::DecisionRung;
use oneiron::llm::decision::questions::{
    answer_records, create_question, edit_question, pause_question, read_question,
    run_graph_ask_receipted, select_graph_units_by_type,
};
use oneiron::llm::media::{AiOperation, Modality};
use oneiron::memory::{
    HostWriteOrigin, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, Memory, MemoryError,
    MemoryResult, ProducerRows,
};
use oneiron::receipt::{
    GRAPH_ASK_UNIT_DEADLINE_MS, GraphAskOutcome, GraphAskRequest, QuestionAnswersRequest,
    QuestionCreateRequest, QuestionEditRequest, QuestionPauseRequest, QuestionPaused,
    QuestionReadRequest,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{self, AgentVerb, AiOptions, AiOptionsRequest, AiVerdictRequest};
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{EntityId, WriteActor};
use serde_json::Value;

use super::SyncServer;
use crate::api::{RunGuests, VerdictAsker};
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
            server: Arc::clone(server),
            actor,
            runtime,
        }
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
        // The run's thread drives its own reactor; the row runs on the
        // server's runtime, which its model rungs block on, and the run's
        // thread waits for it.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let actor = self.actor;
        let origin = origin.clone();
        let verb = call.verb;
        let input = call.input.clone();
        self.runtime.spawn_blocking(move || {
            let _ = sender.send(answer_as_agent(
                &server, actor, &origin, invocation, verb, input, held,
            ));
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
            // A verb hook's stop goes back to the run as the typed stop.
            Err(error) => match error.hook {
                Some(stop) => Err(oneiron::Error::from(*stop)),
                None => Ok(Err(AgentVerbRefusal { code: error.code })),
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

/// Answers one host row for `actor`, with its verb hooks once around it, on
/// a fresh surface under the agent that carries `origin` and `invocation`.
/// The rows it answers with are the ones that surface listed as served;
/// `held` is the run's own screenshot an `ai.verdict` may name. Blocking:
/// call it on a blocking thread of the server's runtime.
pub(crate) fn answer_as_agent(
    server: &SyncServer,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
    verb: AgentVerb,
    input: Value,
    held: Option<HeldImage>,
) -> MemoryResult<(Value, Vec<EntityId>)> {
    let producers = ProducerRows::default();
    let memory =
        agent_memory(server, actor, origin, invocation).listing_producers(&producers);
    let name = verb.as_str();
    let output = if served_by_host(verb) {
        verb_hook_boundary::row(&memory, name, input, |input| {
            sdk::validate_input(name, &input)?;
            HELD_IMAGE.sync_scope(held, || host_row(server, actor, &memory, verb, input))
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
            | AgentVerb::VaultQuestionsRead
            | AgentVerb::VaultQuestionsAnswers
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
        AgentVerb::VaultRecall => encode(server.recall(memory, principal, class, decode(input)?)?),
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
                Some(select) => select_graph_units_by_type(&lane, select.entity_type, select.limit)?,
                None => request.units,
            };
            let dial = server
                .decision_host()
                .dial(request.ceiling.unwrap_or(DecisionRung::Big));
            let budget = Duration::from_millis(
                request
                    .unit_deadline_ms
                    .unwrap_or(GRAPH_ASK_UNIT_DEADLINE_MS),
            );
            let mut answerer = LadderGraphAnswerer::new(server, actor, dial, budget)?;
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
        AgentVerb::VaultQuestionsRead => {
            let request: QuestionReadRequest = decode(input)?;
            encode(read_question(vault, principal, request.id, request.version)?)
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
            )?)
        }
        AgentVerb::AiOptions => encode(ai_options(server, decode(input)?)?),
        AgentVerb::VaultHooksReplay => Err(owners(verb, "hook replays are the owner's")),
        _ => Err(owners(verb, "ai.* media calls are the owner's")),
    }
}

/// `ai.options` from the host's model runtime: the rows a call could use and
/// what the media meter has left.
fn ai_options(server: &SyncServer, request: AiOptionsRequest) -> MemoryResult<AiOptions> {
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
    let runtime = server.ai.model_runtime();
    let options = runtime
        .ai_options(operation, &inputs)
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|_| internal(AgentVerb::AiOptions))?;
    Ok(AiOptions {
        options,
        media_units_left: runtime.media().units_left(),
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
