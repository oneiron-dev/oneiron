//! `POST /v1/ai/chat`: one chat turn on the generative seat, streamed.
//!
//! One producer feeds three planes (runtime.md): every text delta goes to the
//! engine's ephemeral message presence, which each owner socket on `/ws`
//! already receives; the [`LlmEventBus`] fans events out to live subscribers
//! (this request's NDJSON body is one); and only the terminal reaches the
//! ledger, once, through the bus's terminal sink, which finalizes the
//! assistant MESSAGE. Deltas are never durable.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, LlmEventBus, TerminalSink};
use oneiron::memory::{
    MessageStreamHandle, MessageStreamReceipt, MessageWriteMode, StreamCadence, StreamCancelReason,
    StreamSyncVisibility, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ContentPart, EdgeActorClass, EntityId, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamEvent, ModelTierRef, ResponseFormat, TierPrecedence, Vault, WriteActor,
};
use oneiron_driver::SessionHint;
use serde::{Deserialize, Serialize};

use super::refusal;
use crate::auth::{CoreAuth, CoreScope};
use crate::models::Seat;
use crate::server::SyncServer;

/// The seeded definition that speaks when a request names no agent.
const DEFAULT_AGENT: &str = "sys.default";
const MESSAGE_TYPE: &str = "text";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChatTurnRequest {
    /// Short ref or 32-hex id; a new hex id creates the conversation.
    conversation_ref: String,
    text: String,
    /// Earlier exchange the caller wants the model to see, oldest first.
    #[serde(default)]
    history: Vec<HistoryLine>,
    /// The agent definition that answers; the seeded default otherwise.
    agent_ref: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryLine {
    role: HistoryRole,
    text: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryRole {
    User,
    Assistant,
}

/// One NDJSON line of the response body.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ChatLine {
    Accepted {
        user_turn: String,
        message_id: String,
    },
    Delta {
        text: String,
    },
    Done {
        text: String,
        usage: oneiron::LlmUsage,
        finish_reason: oneiron::FinishReason,
    },
    Saved {
        receipt: MessageStreamReceipt,
    },
    Error {
        code: &'static str,
        message: String,
    },
}

fn line(value: &ChatLine) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// The writer of the user's turn: the slip's principal, or the vault's own
/// owner for an owner-grade credential that names none.
fn principal(auth: &CoreAuth, vault: &Vault) -> Result<(EntityId, EdgeActorClass), Response> {
    let refused = || {
        refusal(
            StatusCode::FORBIDDEN,
            "principal_required",
            "a chat turn is written by an authenticated principal",
        )
    };
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| refused())?,
        None if auth.is_owner_grade() => {
            vault.ensure_embedded_owner_actor().map_err(|_| refused())?
        }
        None => return Err(refused()),
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    Ok((actor, class))
}

fn assistant(
    vault: &Vault,
    agent_ref: Option<&str>,
) -> Result<(EntityId, Option<String>), Response> {
    let unknown = || {
        refusal(
            StatusCode::BAD_REQUEST,
            "agent_unknown",
            "agent_ref names no agent definition in this vault",
        )
    };
    let failed = |_| {
        refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent_unreadable",
            "agent read failed",
        )
    };
    let (id, definition) = match agent_ref {
        Some(reference) => {
            let id = EntityId::from_hex(reference).map_err(|_| unknown())?;
            let definition = vault
                .get_agent_definition(&id)
                .map_err(failed)?
                .ok_or_else(unknown)?;
            (id, definition)
        }
        None => vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_AGENT)
            .map_err(failed)?
            .ok_or_else(unknown)?,
    };
    Ok((
        id,
        definition
            .instructions
            .filter(|text| !text.trim().is_empty()),
    ))
}

fn text_message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

fn witness_turn(
    conversation_ref: &str,
    author: WitnessAuthor,
    content: String,
    at: u64,
) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: conversation_ref.to_owned(),
        turn_ref: None,
        messages: vec![WitnessMessage {
            id: None,
            author,
            message_type: MESSAGE_TYPE.to_owned(),
            content,
            metadata: None,
            is_visible: true,
            order: 0,
        }],
        occurred_at: at,
    }
}

pub(super) async fn chat_turn(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ChatTurnRequest>, JsonRejection>,
) -> Response {
    start_turn(&auth, &server, payload).unwrap_or_else(|refused| refused)
}

fn start_turn(
    auth: &CoreAuth,
    server: &Arc<SyncServer>,
    payload: Result<Json<ChatTurnRequest>, JsonRejection>,
) -> Result<Response, Response> {
    auth.require(CoreScope::Write)
        .map_err(IntoResponse::into_response)?;
    let Json(request) = payload.map_err(|rejection| {
        refusal(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            rejection.body_text(),
        )
    })?;
    if request.text.trim().is_empty() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "text is empty",
        ));
    }
    let seat = server.ai.chat_seat().cloned().ok_or_else(|| {
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_model_configured",
            "no [models] rung serves generative_reasoner",
        )
    })?;
    let vault = Arc::clone(server.vault());
    let (actor, class) = principal(auth, &vault)?;
    let (agent, instructions) = assistant(&vault, request.agent_ref.as_deref())?;
    let settings = server.ai.chat_settings();
    let engine = |error: &dyn std::fmt::Display| {
        refusal(StatusCode::CONFLICT, "turn_refused", error.to_string())
    };

    server.ai.session_hint(SessionHint::AppOpen);
    let at = vault.now_recorded_at();
    let user = vault
        .memory(actor, class)
        .witness(&witness_turn(
            &request.conversation_ref,
            WitnessAuthor::User,
            request.text.clone(),
            at,
        ))
        .map_err(|error| engine(&error))?;
    let handle = vault
        .memory(agent, EdgeActorClass::Agent)
        .begin_message_stream(
            &witness_turn(
                &request.conversation_ref,
                WitnessAuthor::Companion,
                String::new(),
                at,
            ),
            Some(MessageWriteMode::Streamed {
                visibility: StreamSyncVisibility::AllDevices,
                cadence: StreamCadence::PerToken,
            }),
        )
        .map_err(|error| engine(&error))?;

    let mut messages: Vec<LlmMessage> = instructions
        .into_iter()
        .map(|text| text_message(LlmMessageRole::System, text))
        .collect();
    let skip = request.history.len().saturating_sub(settings.history_turns);
    for earlier in request.history.into_iter().skip(skip) {
        let role = match earlier.role {
            HistoryRole::User => LlmMessageRole::User,
            HistoryRole::Assistant => LlmMessageRole::Assistant,
        };
        messages.push(text_message(role, earlier.text));
    }
    messages.push(text_message(LlmMessageRole::User, request.text));
    let call = chat_request(&seat, messages);
    let admitted = vault
        .authorize_raw_inference(
            call,
            &HostInferenceContext {
                binding: HostInferenceBinding::Advertised {
                    model: seat.model.clone(),
                    locality: seat.locality,
                },
                extraction_egress: None,
            },
        )
        .map(oneiron::llm::AuthorizedInference::into_request)
        .and_then(|call| {
            let guard = vault.policy_budget_guard(
                format!("chat:{}", handle.message_id().to_hex()),
                settings.turn_budget_units,
                oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(settings.turn_budget_units),
                BudgetExhaustionPolicy::Suspend,
                WriteActor::new(actor, class),
            )?;
            let lease = guard.admit_for_request(&call).map_err(|denied| {
                oneiron::Error::InvalidConfig(format!("chat budget: {denied:?}"))
            })?;
            Ok((call, guard, lease.lease))
        });
    let (call, guard, lease) = match admitted {
        Ok(admitted) => admitted,
        Err(error) => {
            let _ = vault
                .memory(agent, EdgeActorClass::Agent)
                .cancel_stream(handle, StreamCancelReason::AgentAborted);
            return Err(refusal(
                StatusCode::PAYMENT_REQUIRED,
                "turn_not_admitted",
                error.to_string(),
            ));
        }
    };

    let streamed = Arc::new(Mutex::new(String::new()));
    let saved = Arc::new(Mutex::new(None));
    let mut bus = LlmEventBus::new(Box::new(AssistantMessage {
        vault: Arc::clone(&vault),
        agent,
        handle,
        streamed: Arc::clone(&streamed),
        saved: Arc::clone(&saved),
    }));
    let subscription = bus.subscribe();
    let (finished, outcome) = tokio::sync::oneshot::channel();
    let ai = server.ai.clone();
    tokio::spawn(async move {
        let result = produce(Producer {
            bus,
            seat,
            call,
            guard,
            lease,
            vault,
            agent,
            handle,
            streamed,
        })
        .await;
        ai.session_hint(SessionHint::Activity);
        let line = match result {
            Ok(()) => match saved.lock().ok().and_then(|mut slot| slot.take()) {
                Some(receipt) => ChatLine::Saved { receipt },
                None => ChatLine::Error {
                    code: "not_saved",
                    message: "the terminal message was not recorded".into(),
                },
            },
            Err(message) => ChatLine::Error {
                code: "turn_failed",
                message,
            },
        };
        let _ = finished.send(line);
    });

    let accepted = ChatLine::Accepted {
        user_turn: user.turn_short_id,
        message_id: handle.message_id().to_hex(),
    };
    let head = futures_util::stream::once(async move { line(&accepted) });
    let events = subscription.filter_map(|event| async move {
        match event {
            LlmStreamEvent::TextDelta { text, .. } => Some(line(&ChatLine::Delta { text })),
            LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
            } => Some(line(&ChatLine::Done {
                text: message_text(&message),
                usage,
                finish_reason,
            })),
            _ => None,
        }
    });
    let tail = futures_util::stream::once(async move {
        outcome.await.map_or_else(
            |_| {
                line(&ChatLine::Error {
                    code: "turn_failed",
                    message: "the producer stopped".into(),
                })
            },
            |line_value| line(&line_value),
        )
    });
    let body = head.chain(events).chain(tail).map(Ok::<_, std::io::Error>);
    Ok((
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(body),
    )
        .into_response())
}

fn chat_request(seat: &Seat, messages: Vec<LlmMessage>) -> LlmRequest {
    let purpose = CallPurpose::AnswerGen;
    LlmRequest {
        model: seat.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("answer".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: seat.locality,
        },
        messages,
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

fn message_text(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// The ledger plane: the one durable write of a chat turn.
struct AssistantMessage {
    vault: Arc<Vault>,
    agent: EntityId,
    handle: MessageStreamHandle,
    /// What the producer appended to the presence plane so far.
    streamed: Arc<Mutex<String>>,
    saved: Arc<Mutex<Option<MessageStreamReceipt>>>,
}

impl TerminalSink for AssistantMessage {
    fn record(&mut self, terminal: &LlmResponse) -> oneiron::LlmResult<()> {
        let memory = self.vault.memory(self.agent, EdgeActorClass::Agent);
        // The stream holds what was appended; a terminal carrying text the
        // deltas never did (a provider that sends it only at the end) is
        // appended before the one commit.
        let text = message_text(&terminal.message);
        let streamed = self
            .streamed
            .lock()
            .map_or_else(|_| String::new(), |text| text.clone());
        if let Some(rest) = text.strip_prefix(streamed.as_str())
            && !rest.is_empty()
        {
            memory
                .append_to_stream(self.handle, rest)
                .map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        }
        let receipt = memory
            .finalize_stream(self.handle)
            .map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        if let Ok(mut slot) = self.saved.lock() {
            *slot = Some(receipt);
        }
        Ok(())
    }
}

struct Producer {
    bus: LlmEventBus,
    seat: Seat,
    call: LlmRequest,
    guard: BudgetGuard,
    lease: BudgetLease,
    vault: Arc<Vault>,
    agent: EntityId,
    handle: MessageStreamHandle,
    streamed: Arc<Mutex<String>>,
}

/// Drives the model stream into the presence plane and the bus. Settles the
/// turn's meter on every exit: honest usage on a terminal, the reservation
/// otherwise.
async fn produce(producer: Producer) -> Result<(), String> {
    let Producer {
        mut bus,
        seat,
        call,
        guard,
        lease,
        vault,
        agent,
        handle,
        streamed,
    } = producer;
    let memory = vault.memory(agent, EdgeActorClass::Agent);
    let fail = |reason: String| {
        let _ = memory.cancel_stream(handle, StreamCancelReason::AgentAborted);
        let _ = guard.settle_reserved(&lease);
        Err(reason)
    };
    let mut stream = match seat.backend.stream(call, &lease) {
        Ok(stream) => stream,
        Err(error) => return fail(format!("model stream did not start: {error:?}")),
    };
    while let Some(item) = stream.next().await {
        let event = match item {
            Ok(event) => event,
            Err(error) => return fail(format!("model stream failed: {error:?}")),
        };
        if let LlmStreamEvent::TextDelta { text, .. } = &event {
            if let Err(error) = memory.append_to_stream(handle, text) {
                return fail(format!("message stream refused a delta: {error}"));
            }
            if let Ok(mut so_far) = streamed.lock() {
                so_far.push_str(text);
            }
        }
        let usage = match &event {
            LlmStreamEvent::Done { usage, .. } => Some(usage.clone()),
            _ => None,
        };
        if let Err(error) = bus.publish(event) {
            return fail(format!("terminal message was not saved: {error:?}"));
        }
        if let Some(usage) = usage {
            let settled = if usage.input.total == 0 && usage.output.total == 0 {
                guard.settle_reserved(&lease).map(|_| ())
            } else {
                guard.settle_per_call(&lease, &usage).map(|_| ())
            };
            return settled.map_err(|denied| format!("chat settlement: {denied:?}"));
        }
    }
    fail("model stream ended without a terminal".into())
}
