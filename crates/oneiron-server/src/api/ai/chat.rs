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
use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use oneiron::llm::{LlmEventBus, TerminalSink};
use oneiron::memory::{
    MessageStreamHandle, MessageStreamReceipt, MessageWriteMode, StreamCadence, StreamCancelReason,
    StreamSyncVisibility, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ContentPart, EdgeActorClass, EntityId, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmStreamEvent, ModelTierRef, ResponseFormat, TierPrecedence, Vault, WriteActor,
};
use oneiron_driver::SessionHint;
use serde::{Deserialize, Serialize};

use super::refusal;

/// A refusal answer, boxed: a `Response` is too large to travel as an error.
type Refused = Box<Response>;

fn refused(status: StatusCode, code: &str, message: impl Into<String>) -> Refused {
    Box::new(refusal(status, code, message))
}
use crate::ai_host::{CHAT_ROLE, TurnGuard};
use crate::auth::{CoreAuth, CoreScope};
use crate::models::{RoleRefusal, Seat};
use crate::server::SyncServer;

/// The seeded definition that speaks when a request names no agent.
const DEFAULT_AGENT: &str = "sys.default";
const MESSAGE_TYPE: &str = "text";
/// Under the engine's idle finalization (30 s), so a model that thinks in
/// silence does not have its message closed under it.
const KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(10);

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

/// The verified credential a turn was admitted under, held for the turn's
/// whole life. Once it is revoked or expired the caller gets no more of the
/// reply, and the reply is never saved as an answer.
#[derive(Clone)]
struct TurnCredential {
    auth: CoreAuth,
    vault: Arc<Vault>,
}

impl TurnCredential {
    fn live(&self) -> bool {
        self.auth.credential_is_live(&self.vault)
    }

    fn live_in(&self, txn: &heed::RwTxn<'_>) -> bool {
        self.auth.credential_is_live_in_write_txn(&self.vault, txn)
    }
}

/// Recorded on the assistant MESSAGE a revoked credential's turn leaves.
const REVOKED: &str = "credential_revoked";

fn revoked_line() -> Vec<u8> {
    line(&ChatLine::Error {
        code: REVOKED,
        message: "the credential this turn was admitted under is no longer live".into(),
    })
}

/// The writer of the user's turn: the slip's principal, or the vault's own
/// owner for an owner-grade credential that names none.
fn principal(auth: &CoreAuth, vault: &Vault) -> Result<(EntityId, EdgeActorClass), Refused> {
    let denied = || {
        refused(
            StatusCode::FORBIDDEN,
            "principal_required",
            "a chat turn is written by an authenticated principal",
        )
    };
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| denied())?,
        None if auth.is_owner_grade() => {
            vault.ensure_embedded_owner_actor().map_err(|_| denied())?
        }
        None => return Err(denied()),
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    Ok((actor, class))
}

/// The agent that answers: the seeded default, or one an owner-grade
/// credential names. Either way the caller must be able to read it, and it
/// must pass the dispatch predicate (live, active, approved, enabled), as a
/// dispatched agent would.
fn assistant(
    auth: &CoreAuth,
    vault: &Vault,
    agent_ref: Option<&str>,
) -> Result<(EntityId, Option<String>), Refused> {
    let unknown = || {
        refused(
            StatusCode::BAD_REQUEST,
            "agent_unknown",
            "agent_ref names no agent definition in this vault",
        )
    };
    let id = match agent_ref {
        Some(_) if !auth.is_owner_grade() => {
            return Err(refused(
                StatusCode::FORBIDDEN,
                "agent_ref_requires_owner",
                "only an owner-grade credential picks the answering agent",
            ));
        }
        Some(reference) => EntityId::from_hex(reference).map_err(|_| unknown())?,
        None => {
            vault
                .get_seeded_agent_definition_by_logical_id(DEFAULT_AGENT)
                .map_err(|_| unknown())?
                .ok_or_else(unknown)?
                .0
        }
    };
    let definition = AgentDispatcher::new(vault)
        .dispatchable_definition(&AgentDispatchTarget::Custom(id))
        .map_err(|error| {
            refused(
                StatusCode::BAD_REQUEST,
                "agent_not_dispatchable",
                error.to_string(),
            )
        })?;
    // Its instructions go to the model, so the caller must be able to read
    // the definition itself: the Read verb alone is not that.
    if !auth.can_read_entity(vault, &id).unwrap_or(false) {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "agent_not_readable",
            "the answering agent's definition is not readable by this credential",
        ));
    }
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
    start_turn(&auth, &server, payload).unwrap_or_else(|refused| *refused)
}

fn start_turn(
    auth: &CoreAuth,
    server: &Arc<SyncServer>,
    payload: Result<Json<ChatTurnRequest>, JsonRejection>,
) -> Result<Response, Refused> {
    // A turn reads the agent and the conversation, and writes both turns.
    for scope in [CoreScope::Read, CoreScope::Write] {
        auth.require(scope)
            .map_err(|error| Box::new(error.into_response()))?;
    }
    let Json(request) = payload.map_err(|rejection| {
        refused(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            rejection.body_text(),
        )
    })?;
    if request.text.trim().is_empty() {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "text is empty",
        ));
    }
    let seat = server.ai.chat_seat().cloned().ok_or_else(|| {
        refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_model_configured",
            "no [models] rung serves generative_reasoner",
        )
    })?;
    let vault = Arc::clone(server.vault());
    let (actor, class) = principal(auth, &vault)?;
    let (agent, instructions) = assistant(auth, &vault, request.agent_ref.as_deref())?;
    let settings = server.ai.chat_settings();
    let engine = |error: &dyn std::fmt::Display| {
        refused(StatusCode::CONFLICT, "turn_refused", error.to_string())
    };

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
    messages.push(text_message(LlmMessageRole::User, request.text.clone()));
    // Admitted through its role before anything is written: a vault route
    // this server cannot serve refuses here, with no call made.
    let admitted = server
        .ai
        .admit_role(&vault, CHAT_ROLE, chat_request(&seat, messages))
        .map_err(|refusal| match refusal {
            RoleRefusal::NoSeat => refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "no_model_configured",
                refusal.to_string(),
            ),
            RoleRefusal::RouteNotServed { .. } => refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "model_route_not_served",
                refusal.to_string(),
            ),
            RoleRefusal::Refused(_) => refused(
                StatusCode::PAYMENT_REQUIRED,
                "turn_not_admitted",
                refusal.to_string(),
            ),
        })?;

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

    let call = admitted.request;
    let metered = vault
        .policy_budget_guard(
            format!("chat:{}", handle.message_id().to_hex()),
            settings.turn_budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(settings.turn_budget_units),
            BudgetExhaustionPolicy::Suspend,
            WriteActor::new(actor, class),
        )
        .and_then(|guard| {
            let lease = guard.admit_for_request(&call).map_err(|denied| {
                oneiron::Error::InvalidConfig(format!("chat budget: {denied:?}"))
            })?;
            Ok((guard, lease.lease))
        });
    let (guard, lease) = match metered {
        Ok(metered) => metered,
        Err(error) => {
            let _ = vault
                .memory(agent, EdgeActorClass::Agent)
                .cancel_stream(handle, StreamCancelReason::AgentAborted);
            return Err(refused(
                StatusCode::PAYMENT_REQUIRED,
                "turn_not_admitted",
                error.to_string(),
            ));
        }
    };

    let credential = TurnCredential {
        auth: auth.clone(),
        vault: Arc::clone(&vault),
    };
    let streamed = Arc::new(Mutex::new(String::new()));
    let saved = Arc::new(Mutex::new(None));
    let mut bus = LlmEventBus::new(Box::new(AssistantMessage {
        vault: Arc::clone(&vault),
        agent,
        handle,
        credential: credential.clone(),
        streamed: Arc::clone(&streamed),
        saved: Arc::clone(&saved),
    }));
    let subscription = bus.subscribe();
    let (finished, outcome) = tokio::sync::oneshot::channel();
    let ai = server.ai.clone();
    let turn = server.ai.enter_turn();
    let producer = Producer {
        bus,
        backend: admitted.backend,
        call,
        guard,
        lease,
        vault,
        agent,
        handle,
        credential: credential.clone(),
        streamed,
        turn,
    };
    tokio::spawn(async move {
        let result = produce(producer).await;
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
    // The response body is disclosure too: each line goes out only while the
    // credential is live; the first line after it lapses says so and ends it.
    let body = head
        .chain(events)
        .chain(tail)
        .scan(true, move |open, bytes| {
            let next = if !*open {
                None
            } else if credential.live() {
                Some(bytes)
            } else {
                *open = false;
                Some(revoked_line())
            };
            std::future::ready(next)
        })
        .map(Ok::<_, std::io::Error>);
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
    credential: TurnCredential,
    /// What the producer appended to the presence plane so far.
    streamed: Arc<Mutex<String>>,
    saved: Arc<Mutex<Option<MessageStreamReceipt>>>,
}

impl TerminalSink for AssistantMessage {
    fn record(&mut self, terminal: &LlmResponse) -> oneiron::LlmResult<()> {
        if !self.credential.live() {
            return Err(oneiron::FatalLlmError::InvalidRequest.into());
        }
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
        // A cancelled terminal keeps its text but is recorded as cancelled.
        // An answer commits only while the credential is live in its own
        // write transaction.
        let receipt = if terminal.finish_reason == oneiron::FinishReason::Cancelled {
            memory.cancel_stream(self.handle, StreamCancelReason::ExternalSignal)
        } else {
            let credential = &self.credential;
            memory.finalize_stream_if(self.handle, |txn| credential.live_in(txn))
        }
        .map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        if let Ok(mut slot) = self.saved.lock() {
            *slot = Some(receipt);
        }
        Ok(())
    }
}

struct Producer {
    bus: LlmEventBus,
    backend: Arc<dyn LlmBackend>,
    call: LlmRequest,
    guard: BudgetGuard,
    lease: BudgetLease,
    vault: Arc<Vault>,
    agent: EntityId,
    handle: MessageStreamHandle,
    credential: TurnCredential,
    streamed: Arc<Mutex<String>>,
    turn: TurnGuard,
}

/// Charges what a terminal reports, or the reservation when it reports
/// nothing.
fn settle(
    guard: &BudgetGuard,
    lease: &BudgetLease,
    usage: &oneiron::LlmUsage,
) -> Result<(), String> {
    if usage.input.total == 0 && usage.output.total == 0 {
        guard.settle_reserved(lease).map(|_| ())
    } else {
        guard.settle_per_call(lease, usage).map(|_| ())
    }
    .map_err(|denied| format!("chat settlement: {denied:?}"))
}

/// Drives the model stream into the presence plane and the bus. Settles the
/// turn's meter on every exit: honest usage on a terminal (saved or not),
/// the reservation otherwise. A credential that lapses mid-turn stops the
/// call: nothing more reaches any plane, and the message is cancelled.
async fn produce(producer: Producer) -> Result<(), String> {
    let Producer {
        mut bus,
        backend,
        call,
        guard,
        lease,
        vault,
        agent,
        handle,
        credential,
        streamed,
        mut turn,
    } = producer;
    let memory = vault.memory(agent, EdgeActorClass::Agent);
    let cancel = |reason: StreamCancelReason| {
        let _ = memory.cancel_stream(handle, reason);
    };
    let fail = |reason: String| {
        cancel(StreamCancelReason::AgentAborted);
        let _ = guard.settle_reserved(&lease);
        Err(reason)
    };
    let revoked = || {
        cancel(StreamCancelReason::Custom(REVOKED.into()));
        let _ = guard.settle_reserved(&lease);
        Err("the turn's credential was revoked".to_owned())
    };
    let mut stream = match backend.stream(call, &lease) {
        Ok(stream) => stream,
        Err(error) => return fail(format!("model stream did not start: {error:?}")),
    };
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.reset();
    loop {
        let item = tokio::select! {
            item = stream.next() => item,
            () = turn.stopping() => return fail("the server is stopping".into()),
            _ = keepalive.tick() => {
                if !credential.live() {
                    return revoked();
                }
                if let Err(error) = memory.append_to_stream(handle, "") {
                    return fail(format!("message stream closed while waiting: {error}"));
                }
                continue;
            }
        };
        let Some(item) = item else {
            break;
        };
        let event = match item {
            Ok(event) => event,
            Err(error) => return fail(format!("model stream failed: {error:?}")),
        };
        if let LlmStreamEvent::Done { usage, .. } = &event {
            // The provider spent this whether or not the answer is saved.
            let usage = usage.clone();
            if let Err(error) = bus.publish(event) {
                if credential.live() {
                    cancel(StreamCancelReason::AgentAborted);
                } else {
                    cancel(StreamCancelReason::Custom(REVOKED.into()));
                }
                let _ = settle(&guard, &lease, &usage);
                return Err(format!("terminal message was not saved: {error:?}"));
            }
            return settle(&guard, &lease, &usage);
        }
        if !credential.live() {
            return revoked();
        }
        if let LlmStreamEvent::TextDelta { text, .. } = &event {
            if let Err(error) = memory.append_to_stream(handle, text) {
                return fail(format!("message stream refused a delta: {error}"));
            }
            if let Ok(mut so_far) = streamed.lock() {
                so_far.push_str(text);
            }
        }
        if let Err(error) = bus.publish(event) {
            return fail(format!("model event was not published: {error:?}"));
        }
    }
    fail("model stream ended without a terminal".into())
}
