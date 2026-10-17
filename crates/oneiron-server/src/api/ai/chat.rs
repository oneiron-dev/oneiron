//! `POST /v1/ai/chat`: one chat turn on the generative seat.
//!
//! One producer feeds three planes (runtime.md): every text delta goes to the
//! engine's message stream, which saves it in the stream's seed before a
//! streamed turn publishes it as the presence each owner socket on `/ws`
//! receives; the [`LlmEventBus`] fans events out to live subscribers (a
//! streamed request's NDJSON body is one); and the terminal reaches the
//! ledger once, through the bus's terminal sink, which ends the assistant
//! MESSAGE with the model's finish reason. A reply cut short (a crash, a
//! failed or cut stream, a length stop) stays one MESSAGE that reads
//! incomplete, holding exactly the text that was saved (owner ruling 10-17).
//!
//! A request is answered with the whole saved message by default, and with
//! the NDJSON lines as they come when it sets `stream`. Both run the same
//! producer and checkpoints; a client that goes away never stops it. The
//! turn-action worker's Continue and Retry generate through the same
//! [`begin_answer`], under the same `host.turn.generate` hooks.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use oneiron::claim::ScopedReadActorKey;
use oneiron::conversation::{OutputMark, TurnActionAttempt};
use oneiron::dreamer_wake::{AgentWakeSignals, WakeTurnSubject};
use oneiron::llm::{LlmEventBus, StreamSubscription, TerminalSink};
use oneiron::memory::{
    Memory, MemoryError, MessageStreamError, MessageStreamHandle, MessageStreamReceipt,
    MessageWriteMode, StreamCadence, StreamCancelReason, StreamSyncVisibility, WitnessAuthor,
    WitnessMessage, WitnessTurn, resolve_entity_ref,
};
use oneiron::runtime_hooks::verb::InvocationClaim;
use oneiron::runtime_hooks::{InvocationId, VerbCall, VerbDomain, VerbHookPre, VerbHookStop};
use oneiron::session_lifecycle::SessionKey;
use oneiron::skill_hub::pack_catalog::HookActorClass;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, EdgeActorClass,
    EntityId, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStream, LlmStreamEvent,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault, WriteActor,
};
use oneiron_driver::SessionHint;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::refusal;

/// A refusal answer, boxed: a `Response` is too large to travel as an error.
type Refused = Box<Response>;

fn refused(status: StatusCode, code: &str, message: impl Into<String>) -> Refused {
    Box::new(refusal(status, code, message))
}
use crate::ai_host::{AiHandle, CHAT_ROLE, TurnGuard};
use crate::api::credential_memory;
use crate::api::facade::{self, DoorClaim};
use crate::auth::{CoreAuth, CoreScope};
use crate::models::{RoleCall, RoleRefusal, Seat};
use crate::server::SyncServer;
use crate::voice_host::{EntryWake, EntryWakes, entry_wake, next_entry_wake};

/// The seeded definition that speaks when a request names no agent.
const DEFAULT_AGENT: &str = "sys.default";
/// The header a caller carries a logical verb's id in (ARCH-0080 §3): a retry
/// after a hook's ask carries the same id, and the ask resumes.
const INVOCATION_HEADER: &str = "x-oneiron-invocation";
/// The row a chat turn's user message lands through.
const WITNESS_ROW: &str = "vault.witness";
/// The host verb a chat turn's model call runs under (ARCH-0080 §5).
const HOST_TURN_GENERATE: &str = "host.turn.generate";
const MESSAGE_TYPE: &str = "text";
/// What Continue asks a model that cannot continue a trailing assistant
/// message itself, after the reply's saved text.
pub(crate) const CONTINUE_INSTRUCTION: &str = "Your reply above was cut off. Continue it from \
exactly where it stops: write only the rest, without repeating any of it.";
/// The slowest keepalive. Each runs at a third of the message's idle
/// finalization (the vault's `idle_timeout_ms`, 30 s by default), so a model
/// that thinks in silence does not have its message closed under it.
const KEEPALIVE_MAX: std::time::Duration = std::time::Duration::from_secs(10);
/// The fastest keepalive, for a vault whose idle timeout is tiny.
const KEEPALIVE_MIN: std::time::Duration = std::time::Duration::from_millis(50);

pub(crate) fn keepalive_every(idle_timeout_ms: u64) -> std::time::Duration {
    (std::time::Duration::from_millis(idle_timeout_ms) / 3).clamp(KEEPALIVE_MIN, KEEPALIVE_MAX)
}

#[derive(Deserialize, Serialize)]
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
    /// Answer with NDJSON lines as they come, deltas included; otherwise
    /// with the whole message once it is saved.
    #[serde(default)]
    stream: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoryLine {
    role: HistoryRole,
    text: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
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

/// The whole-message answer: what was saved, and whether it is complete.
#[derive(Serialize)]
struct ChatReply {
    conversation_ref: String,
    /// The assistant TURN, which Continue and Retry name.
    turn_id: String,
    message_id: String,
    text: String,
    incomplete: bool,
    finish_reason: Option<oneiron::FinishReason>,
}

fn line(value: &ChatLine) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// What a turn was admitted under, held for the turn's whole life. Once it
/// lapses the caller gets no more of the reply, and the reply is never saved
/// as an answer.
#[derive(Clone)]
pub(crate) enum TurnCredential {
    /// The verified credential a chat request presented.
    Request { auth: CoreAuth, vault: Arc<Vault> },
    /// A queued turn action's requester, while its actor binding holds.
    Action {
        action: Box<TurnActionAttempt>,
        vault: Arc<Vault>,
    },
}

impl TurnCredential {
    fn live(&self) -> bool {
        match self {
            Self::Request { auth, vault } => auth.credential_is_live(vault),
            Self::Action { action, vault } => action.requester_live(vault),
        }
    }

    fn live_in(&self, txn: &heed::RwTxn<'_>) -> bool {
        match self {
            Self::Request { auth, vault } => auth.credential_is_live_in_write_txn(vault, txn),
            Self::Action { action, vault } => action.requester_live_in(vault, txn),
        }
    }
}

/// Recorded on the assistant MESSAGE a revoked credential's turn leaves.
const REVOKED: &str = "credential_revoked";
/// Recorded on the assistant MESSAGE the newcomer barrier stopped: an
/// attendee entered its conversation while it was being written.
const NEWCOMER: &str = "attendee_entered";

fn revoked_line() -> Vec<u8> {
    line(&ChatLine::Error {
        code: REVOKED,
        message: "the credential this turn was admitted under is no longer live".into(),
    })
}

/// The writer of the user's turn: the slip's principal, or the vault's own
/// owner for an owner-grade credential that names none.
pub(super) fn principal(
    auth: &CoreAuth,
    vault: &Vault,
) -> Result<(EntityId, EdgeActorClass), Refused> {
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

pub(crate) fn text_message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

pub(crate) fn witness_turn(
    conversation_ref: &str,
    turn: Option<EntityId>,
    author: WitnessAuthor,
    content: String,
    at: u64,
) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: conversation_ref.to_owned(),
        turn_ref: turn.map(|turn| turn.to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author,
            message_type: MESSAGE_TYPE.to_owned(),
            content,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: at,
        assertions: Default::default(),
    }
}

pub(super) async fn chat_turn(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    crate::auth::Locality(locality): crate::auth::Locality,
    machine: Option<axum::Extension<oneiron::authority::PeerMachine>>,
    headers: axum::http::HeaderMap,
    payload: Result<Json<ChatTurnRequest>, JsonRejection>,
) -> Response {
    let peer = machine.map_or(oneiron::authority::PeerMachine::Unknown, |machine| {
        machine.0
    });
    // A turn that names its invocation claims it for the whole request
    // (OF-580): a second request naming it for the same turn waits for this
    // one's reply and gets it, and one naming it for another turn is refused.
    let claim = match (invocation(&headers), &payload) {
        (Ok(Some(named)), Ok(Json(request))) => {
            let body = turn_invocation_body(&auth, locality, request);
            match facade::claim_door_invocation(&server, named, body).await {
                DoorClaim::Run(claim) => Some(claim),
                DoorClaim::Answered(outcome) => return facade::door_replay(outcome),
                DoorClaim::InFlight => {
                    return refusal(
                        StatusCode::CONFLICT,
                        facade::INVOCATION_IN_FLIGHT,
                        "another request is still running this invocation; retry once it returns",
                    );
                }
                DoorClaim::Conflict => {
                    return refusal(
                        StatusCode::CONFLICT,
                        facade::INVOCATION_CONFLICT,
                        "this invocation id names a different call",
                    );
                }
            }
        }
        _ => None,
    };
    let response = match start_turn(&auth, &server, peer, locality, &headers, payload) {
        Ok(started) if started.stream => return streamed(started, claim),
        Ok(started) => whole(started).await,
        Err(refused) => *refused,
    };
    match claim {
        Some(claim) => facade::finish_door_claim(claim, response).await,
        None => response,
    }
}

/// What a claimed turn's invocation names: the caller, where it sits, and
/// the request.
fn turn_invocation_body(
    auth: &CoreAuth,
    locality: oneiron::claim::CallerLocality,
    request: &ChatTurnRequest,
) -> [u8; 32] {
    let request = serde_json::to_vec(request).unwrap_or_default();
    facade::invocation_body(
        Some(auth),
        locality,
        &[b"chat".as_slice(), request.as_slice()],
    )
}

/// A turn whose user turn is witnessed and whose answer is running.
struct Started {
    stream: bool,
    conversation_ref: String,
    user_turn: String,
    /// The assistant TURN the answer opened.
    turn: EntityId,
    answering: Answering,
    credential: TurnCredential,
}

fn start_turn(
    auth: &CoreAuth,
    server: &Arc<SyncServer>,
    peer: oneiron::authority::PeerMachine,
    locality: oneiron::claim::CallerLocality,
    headers: &axum::http::HeaderMap,
    payload: Result<Json<ChatTurnRequest>, JsonRejection>,
) -> Result<Started, Refused> {
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
    let invocation = invocation(headers)?;
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
    // `host.turn.generate` (ARCH-0080 §5): its pre chain runs once the turn
    // is admitted, so a refused admission leaves no hook's blocks or notes,
    // and before the user's turn is witnessed, so a skip or an ask ends the
    // turn before anything lands and a retry of it witnesses once.
    // The turn's hooks read under the caller's credential, where its
    // connection sits (ARCH-0080 §3). An owner-grade credential naming no
    // principal reads as the owner it writes as. The surface is bound to the
    // conversation this request starts its work in (OF-221), so a root TASK
    // it creates carries that origin to the agent that realizes it; a ref
    // that does not resolve binds none, and the witness refuses it.
    let origin = resolve_entity_ref(&vault, &request.conversation_ref).ok();
    let hooked = || {
        let memory = match auth.principal_ref() {
            Some(_) => credential_memory(&vault, Some(auth), actor, class).at(locality),
            None => vault.memory(actor, class),
        };
        match origin {
            Some(conversation) => memory.with_origin_conversation(conversation),
            None => memory,
        }
    };
    let reader =
        VerbCall::reader_of(&hooked(), HOST_TURN_GENERATE).map_err(|error| engine(&error))?;
    // Chat resolves no room before the user's turn is witnessed, so its
    // call names none.
    let generating = turn_generate_pre(
        &vault,
        actor,
        invocation,
        reader,
        &request.conversation_ref,
        None,
    )
    .map_err(|error| engine(&error))?
    .map_err(|stop| hook_stopped(&stop))?;

    // The assistant message closes after the vault's idle timeout without
    // an append; read before anything is written.
    let keepalive = keepalive_every(
        vault
            .message_stream_policy()
            .map_err(|error| engine(&error))?
            .idle_timeout_ms,
    );
    let session_key = super::bound_session_key(server, actor, peer, locality)?;
    server.ai.session_hint(session_key, SessionHint::AppOpen);
    let at = vault.now_recorded_at();
    let user_turn = witness_turn(
        &request.conversation_ref,
        None,
        WitnessAuthor::User,
        request.text.clone(),
        at,
    );
    let user = crate::server::blocking(|| {
        let memory = vault.memory(actor, class).with_session(session_key);
        let (memory, hooked) = match invocation {
            Some(id) => (memory.with_invocation(id), hooked().with_invocation(id)),
            None => (memory, hooked()),
        };
        witness_through_row(&vault, &memory, &hooked, &user_turn)
    })
    .map_err(|error| engine(&error))?
    .map_err(|stop| hook_stopped(&stop))?;
    // The caller's view of the receipt, which a hook may have redacted.
    let user_turn = user
        .get("turn_short_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    server.ai.turn_landed(&vault, WakeTurnSubject::Vault);
    let turn = EntityId::now();
    let credential = TurnCredential::Request {
        auth: auth.clone(),
        vault: Arc::clone(&vault),
    };
    // A streamed turn publishes each saved delta to every device; a whole
    // one keeps its partials private.
    let mode = if request.stream {
        MessageWriteMode::Streamed {
            visibility: StreamSyncVisibility::AllDevices,
            cadence: StreamCadence::PerToken,
        }
    } else {
        MessageWriteMode::Atomic
    };
    let hooks_vault = Arc::clone(&vault);
    let answering = begin_answer(
        &server.ai,
        Answer {
            vault,
            agent,
            session_key: Some(session_key),
            open: AnswerOpen::Turn(witness_turn(
                &request.conversation_ref,
                Some(turn),
                WitnessAuthor::Companion,
                String::new(),
                at,
            )),
            mode,
            admitted,
            payer: WriteActor::new(actor, class),
            budget_units: settings.turn_budget_units,
            credential: credential.clone(),
            keepalive,
        },
    )
    .map_err(|refusal| match refusal {
        AnswerRefused::WaitedOut(reason) => {
            refused(StatusCode::SERVICE_UNAVAILABLE, "turn_waited_out", reason)
        }
        AnswerRefused::Engine(reason) => refused(StatusCode::CONFLICT, "turn_refused", reason),
        AnswerRefused::NotAdmitted(reason) => {
            refused(StatusCode::PAYMENT_REQUIRED, "turn_not_admitted", reason)
        }
    })?;
    let answering = after_turn(hooks_vault, generating, answering);
    Ok(Started {
        stream: request.stream,
        conversation_ref: request.conversation_ref,
        user_turn,
        turn,
        answering,
        credential,
    })
}

/// The logical verb's id the caller carried, if it carried one.
fn invocation(headers: &axum::http::HeaderMap) -> Result<Option<InvocationId>, Refused> {
    let Some(value) = headers.get(INVOCATION_HEADER) else {
        return Ok(None);
    };
    value
        .to_str()
        .ok()
        .and_then(InvocationId::parse_hex)
        .map(Some)
        .ok_or_else(|| {
            refused(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "x-oneiron-invocation is not 32 hex digits",
            )
        })
}

/// The call of a turn's `host.turn.generate`. A write a host verb causes
/// stamps the System class. Its invocation derives from the turn's own, so a
/// retry of the turn carries it too. Its hooks read under `reader`, the
/// caller's key, and as `actor` when there is none. `room` is the room the
/// host resolved the turn into, if it did: the call's scope.
fn turn_generate_call(
    actor: EntityId,
    invocation: Option<InvocationId>,
    reader: Option<ScopedReadActorKey>,
    room: Option<EntityId>,
) -> VerbCall {
    VerbCall {
        verb: HOST_TURN_GENERATE.to_owned(),
        invocation: invocation.map_or_else(InvocationId::mint, |id| {
            InvocationId::of_run_step(
                &[id.0.as_slice(), HOST_TURN_GENERATE.as_bytes()].concat(),
                0,
            )
        }),
        actor,
        class: HookActorClass::System,
        scope: room.map(|room| format!("room:{}", room.to_hex())),
        board_epoch: None,
        domain: VerbDomain::Write,
        reader,
    }
}

/// Runs `host.turn.generate`'s pre chain for `actor`'s reply in `room`,
/// its hooks reading under `reader`, the caller's key, when there is one.
/// `resolved` is the room entity the host already read `room` as, if any:
/// a hook scoped to it, or to its world, facet or project, fires.
/// `Err(stop)` when a hook skipped the turn or asked first: the turn ends
/// there, with the stop's reason. Hooks write and run their sandbox, so they
/// run off the runtime's workers.
pub(crate) fn turn_generate_pre(
    vault: &Vault,
    actor: EntityId,
    invocation: Option<InvocationId>,
    reader: Option<ScopedReadActorKey>,
    room: &str,
    resolved: Option<EntityId>,
) -> oneiron::Result<Result<VerbHookPre, VerbHookStop>> {
    let args = json!({
        "room": room,
        "scope": Value::Null,
        "board_epoch": Value::Null,
    });
    crate::server::blocking(|| {
        vault.pre_verb_hooks(
            turn_generate_call(actor, invocation, reader, resolved),
            args.clone(),
            &|rewritten: &Value| host_args_kept(&args, rewritten),
        )
    })
}

/// A host verb's args are the host's: a hook's rewrite of them is refused.
fn host_args_kept(args: &Value, rewritten: &Value) -> Result<(), String> {
    if rewritten == args {
        Ok(())
    } else {
        Err("a host verb's args are the host's".to_owned())
    }
}

/// Lands the user's turn through the `vault.witness` row's boundary, so the
/// row's verb hooks fire on it (ARCH-0080 §3), reading under `hooked`'s key.
/// The answer is the caller's view of the row's receipt.
fn witness_through_row(
    vault: &Vault,
    memory: &Memory<'_>,
    hooked: &Memory<'_>,
    turn: &WitnessTurn,
) -> Result<Result<Value, VerbHookStop>, MemoryError> {
    let args = serde_json::to_value(turn)
        .map_err(|_| MemoryError::bad_request("witness turn does not encode"))?;
    vault.verb_hooks(
        VerbCall::for_memory(hooked, WITNESS_ROW, VerbDomain::Write)?,
        args,
        &|args: &Value| {
            oneiron::task_verb::sdk::validate_input(WITNESS_ROW, args)
                .map_err(|error| error.to_string())
        },
        |args| {
            let turn: WitnessTurn = serde_json::from_value(args)
                .map_err(|_| MemoryError::bad_request("witness turn does not decode"))?;
            let receipt = memory.witness(&turn)?;
            serde_json::to_value(receipt)
                .map_err(|_| MemoryError::bad_request("witness receipt does not encode"))
        },
    )
}

/// A turn a verb hook stopped (ARCH-0080 §3): a skip is a conflict, an ask
/// is accepted and pending on its handle, a hidden answer is denied. The body
/// carries the stop, with the invocation a retry carries.
fn hook_stopped(stop: &VerbHookStop) -> Refused {
    let (status, code) = match stop {
        VerbHookStop::Skipped { .. } => (StatusCode::CONFLICT, "verb_hook_skipped"),
        VerbHookStop::Pending { .. } => (StatusCode::ACCEPTED, "verb_hook_pending"),
        VerbHookStop::Hidden { .. } => (StatusCode::FORBIDDEN, "verb_hook_hidden"),
        // The call ran once its ask settled: the stop carries what it
        // returned, and nothing runs it again.
        VerbHookStop::Completed { .. } => (StatusCode::OK, "verb_hook_completed"),
        VerbHookStop::CompletedWithError { .. } => {
            (StatusCode::CONFLICT, "verb_hook_completed_with_error")
        }
    };
    Box::new(
        (
            status,
            Json(json!({"error": {"code": code, "message": stop.to_string(), "hook": stop}})),
        )
            .into_response(),
    )
}

/// Runs `host.turn.generate`'s post chain once the reply's producer ends,
/// whether or not a caller still listens. A block a post-hook adds lands the
/// next turn; the reply stands whatever a post-hook says.
pub(crate) fn after_turn(
    vault: Arc<Vault>,
    generating: VerbHookPre,
    answering: Answering,
) -> Answering {
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    let (finished, forwarded) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok(ended) = outcome.await else {
            return;
        };
        let result = json!({
            "message_id": handle.message_id().to_hex(),
            "text": ended.text,
            "saved": ended.saved.is_some(),
            "complete": ended.saved.as_ref().is_some_and(MessageStreamReceipt::complete),
            "finish_reason": ended.saved.as_ref().and_then(|receipt| receipt.finish_reason.clone()),
        });
        let posted = crate::server::blocking(|| vault.post_verb_hooks(generating, result));
        if let Err(error) = posted {
            tracing::warn!(
                ?error,
                "host.turn.generate post-hooks failed on a finished turn"
            );
        }
        let _ = finished.send(ended);
    });
    Answering {
        handle,
        subscription,
        outcome: forwarded,
    }
}

/// The NDJSON answer: accepted, each delta, the terminal, then saved or the
/// error. A claimed invocation stays claimed until the last line goes out; a
/// stream leaves no reply to send again, so a duplicate waiting on it is
/// told to retry.
fn streamed(started: Started, claim: Option<InvocationClaim>) -> Response {
    let Started {
        user_turn,
        answering,
        credential,
        ..
    } = started;
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    let accepted = ChatLine::Accepted {
        user_turn,
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
            |outcome| {
                line(&match outcome.result {
                    Ok(()) => match outcome.saved {
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
                })
            },
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
        .map(move |bytes| {
            let _claimed = &claim;
            Ok::<_, std::io::Error>(bytes)
        });
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(body),
    )
        .into_response()
}

/// The whole-message answer, once the reply is saved. A reply cut short is
/// answered as saved and incomplete; one that saved nothing is an error.
async fn whole(started: Started) -> Response {
    let Started {
        conversation_ref,
        turn,
        answering,
        credential,
        ..
    } = started;
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    drop(subscription);
    let outcome = outcome.await;
    // The answer is disclosure too: none goes out once the credential lapsed.
    if !credential.live() {
        return refusal(
            StatusCode::FORBIDDEN,
            REVOKED,
            "the credential this turn was admitted under is no longer live",
        );
    }
    let Ok(outcome) = outcome else {
        return refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "turn_failed",
            "the producer stopped",
        );
    };
    let Some(receipt) = outcome.saved else {
        return match outcome.result {
            Ok(()) => refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "not_saved",
                "the terminal message was not recorded",
            ),
            Err(message) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "turn_failed", message),
        };
    };
    Json(ChatReply {
        conversation_ref,
        turn_id: turn.to_hex(),
        message_id: handle.message_id().to_hex(),
        text: outcome.text,
        incomplete: !receipt.complete(),
        finish_reason: receipt.finish_reason,
    })
    .into_response()
}

/// One assistant reply to generate: whose, where it is written, and the
/// call admitted for it.
pub(crate) struct Answer {
    pub(crate) vault: Arc<Vault>,
    /// The answering agent definition, which writes the MESSAGE.
    pub(crate) agent: EntityId,
    /// The authenticated actor/machine sitting of a live chat request.
    pub(crate) session_key: Option<SessionKey>,
    pub(crate) open: AnswerOpen,
    pub(crate) mode: MessageWriteMode,
    pub(crate) admitted: RoleCall,
    /// The actor whose budget line the turn runs on.
    pub(crate) payer: WriteActor,
    pub(crate) budget_units: u64,
    pub(crate) credential: TurnCredential,
    pub(crate) keepalive: Duration,
}

/// Where a reply is written.
pub(crate) enum AnswerOpen {
    /// A new MESSAGE in the turn this names.
    Turn(WitnessTurn),
    /// A Retry's new MESSAGE in the turn this names, answering `source`
    /// again: its terminal links the two by a `regenerates` edge.
    Retry { turn: WitnessTurn, source: EntityId },
    /// More of an existing MESSAGE, after its saved text.
    Continue(EntityId),
}

/// Why a reply never started: no model was called.
pub(crate) enum AnswerRefused {
    WaitedOut(String),
    Engine(String),
    NotAdmitted(String),
}

/// A reply being generated.
pub(crate) struct Answering {
    pub(crate) handle: MessageStreamHandle,
    /// The live events; dropping it costs the producer nothing.
    pub(crate) subscription: StreamSubscription,
    pub(crate) outcome: tokio::sync::oneshot::Receiver<AnswerOutcome>,
}

/// How a reply's producer ended.
pub(crate) struct AnswerOutcome {
    /// Whether it reached its terminal.
    pub(crate) result: Result<(), String>,
    /// The receipt its MESSAGE was saved under: by the terminal, or by the
    /// cancel a failure made.
    pub(crate) saved: Option<MessageStreamReceipt>,
    /// The text the stream accepted, which is what was saved.
    pub(crate) text: String,
}

/// Opens the reply's stream, admits its run and starts the model call, then
/// drives it on a task of its own: a caller that goes away does not stop it.
pub(crate) fn begin_answer(ai: &AiHandle, answer: Answer) -> Result<Answering, AnswerRefused> {
    let Answer {
        vault,
        agent,
        session_key,
        open,
        mode,
        admitted,
        payer,
        budget_units,
        credential,
        keepalive,
    } = answer;
    // The newcomer barrier (OF-365 P5): marked before the reply's stream
    // opens, so no delta goes out into its conversation once an attendee
    // entered it from here on.
    let mark = vault.container_output_mark();
    // Past the vault's message-stream row the stream waits its turn (rule 5),
    // so it waits off the runtime's workers.
    let begun = crate::server::blocking(|| {
        let memory = answer_memory(&vault, agent, session_key);
        match &open {
            AnswerOpen::Turn(turn) => memory.begin_message_stream(turn, Some(mode)),
            AnswerOpen::Retry { turn, source } => {
                memory.begin_message_regeneration(turn, *source, Some(mode))
            }
            AnswerOpen::Continue(message) => memory.begin_message_continuation(message, Some(mode)),
        }
    });
    let handle = match begun {
        Ok(handle) => handle,
        Err(MessageStreamError::WaitedOut(waited)) => {
            return Err(AnswerRefused::WaitedOut(waited.to_string()));
        }
        Err(error) => return Err(AnswerRefused::Engine(error.to_string())),
    };
    let container = answer_container(&vault, &open);
    let wakes = container.map(|_| vault.subscribe_task_updates());

    // The turn is a run on the vault's budget policy for this actor, one line
    // per turn. Each rung the call reaches is admitted on its own permit and
    // settles itself; the first is admitted here, so a turn the line cannot
    // hold is refused before any model is called.
    let started = vault
        .policy_budget_guard(
            format!("chat:{}", handle.message_id().to_hex()),
            budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(budget_units),
            BudgetExhaustionPolicy::Suspend,
            payer,
        )
        .map_err(|error| error.to_string())
        .and_then(|meter| {
            let run = ai.undeclared_run(format!("chat:{}", handle.message_id().to_hex()), meter);
            admitted
                .ladder
                .stream(&run, admitted.request, None)
                .map_err(|error| format!("chat budget: {error:?}"))
        });
    let stream = match started {
        Ok(stream) => stream,
        Err(reason) => {
            let _ = answer_memory(&vault, agent, session_key)
                .cancel_stream(handle, StreamCancelReason::AgentAborted);
            return Err(AnswerRefused::NotAdmitted(reason));
        }
    };

    let streamed = Arc::new(Mutex::new(String::new()));
    let saved = Arc::new(Mutex::new(None));
    let mut bus = LlmEventBus::new(Box::new(AssistantMessage {
        vault: Arc::clone(&vault),
        agent,
        session_key,
        handle,
        credential: credential.clone(),
        streamed: Arc::clone(&streamed),
        saved: Arc::clone(&saved),
    }));
    let subscription = bus.subscribe();
    let (finished, outcome) = tokio::sync::oneshot::channel();
    let ai = ai.clone();
    let landed = (Arc::clone(&vault), agent);
    let turn = ai.enter_turn();
    let producer = Producer {
        bus,
        stream,
        vault,
        agent,
        session_key,
        handle,
        credential,
        streamed: Arc::clone(&streamed),
        saved: Arc::clone(&saved),
        keepalive,
        turn,
        mark,
        container,
        wakes,
    };
    tokio::spawn(async move {
        let result = produce(producer).await;
        if let Some(session_key) = session_key {
            ai.session_hint(session_key, SessionHint::Activity);
        }
        // The answer is the agent's turn, so its own cadence dial counts it.
        ai.turn_landed(
            &landed.0,
            WakeTurnSubject::Agent {
                id: landed.1,
                signals: AgentWakeSignals::default(),
            },
        );
        let _ = finished.send(AnswerOutcome {
            result,
            saved: saved.lock().ok().and_then(|mut slot| slot.take()),
            text: streamed
                .lock()
                .map_or_else(|_| String::new(), |text| text.clone()),
        });
    });
    Ok(Answering {
        handle,
        subscription,
        outcome,
    })
}

/// The conversation a reply is written into: its TURN's, or the continued
/// MESSAGE's. `None` when it lies in none, or cannot be placed.
fn answer_container(vault: &Vault, open: &AnswerOpen) -> Option<EntityId> {
    let record = match open {
        AnswerOpen::Turn(turn) | AnswerOpen::Retry { turn, .. } => {
            EntityId::from_hex(turn.turn_ref.as_deref()?).ok()?
        }
        AnswerOpen::Continue(message) => *message,
    };
    vault
        .record_container(record)
        .inspect_err(
            |error| tracing::warn!(%error, "chat: the reply's conversation was not placed"),
        )
        .ok()
        .flatten()
}

pub(crate) fn chat_request(seat: &Seat, messages: Vec<LlmMessage>) -> LlmRequest {
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

fn answer_memory(
    vault: &Vault,
    agent: EntityId,
    session_key: Option<SessionKey>,
) -> oneiron::memory::Memory<'_> {
    let memory = vault.memory(agent, EdgeActorClass::Agent);
    match session_key {
        Some(key) => memory.with_session(key),
        None => memory,
    }
}

/// The ledger plane: the one durable write of a chat turn.
struct AssistantMessage {
    vault: Arc<Vault>,
    agent: EntityId,
    session_key: Option<SessionKey>,
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
        let memory = answer_memory(&self.vault, self.agent, self.session_key);
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
            if let Ok(mut so_far) = self.streamed.lock() {
                so_far.push_str(rest);
            }
        }
        // The model's finish reason ends the MESSAGE: a stop or a tool call
        // finalizes it, a length cut or any other stop leaves it partial, and
        // a cancelled terminal keeps its text but is recorded as cancelled.
        // An answer commits only while the credential is live in its own
        // write transaction.
        let credential = &self.credential;
        let receipt = memory
            .finalize_model_stream_if(self.handle, terminal.finish_reason.clone(), |txn| {
                credential.live_in(txn)
            })
            .map_err(|_| oneiron::FatalLlmError::InvalidRequest)?;
        if let Ok(mut slot) = self.saved.lock() {
            *slot = Some(receipt);
        }
        Ok(())
    }
}

struct Producer {
    bus: LlmEventBus,
    /// The turn's call, admitted and settled rung by rung under its run.
    stream: LlmStream<'static>,
    vault: Arc<Vault>,
    agent: EntityId,
    session_key: Option<SessionKey>,
    handle: MessageStreamHandle,
    credential: TurnCredential,
    streamed: Arc<Mutex<String>>,
    /// Where a failure's cancel leaves the receipt it saved.
    saved: Arc<Mutex<Option<MessageStreamReceipt>>>,
    keepalive: std::time::Duration,
    turn: TurnGuard,
    /// Taken before the reply's stream opened: no delta goes out into
    /// `container` once an attendee entered it since.
    mark: OutputMark,
    container: Option<EntityId>,
    /// Committed TASKs, while the reply listens for an entry.
    wakes: EntryWakes,
}

/// Drives the model stream into the presence plane and the bus. The run
/// settles each rung: honest usage on a terminal (saved or not), the
/// reservation of a rung that went out and failed, or was stopped. A
/// credential that lapses mid-turn stops the call: nothing more reaches any
/// plane, and the message is cancelled, keeping every delta it saved.
async fn produce(producer: Producer) -> Result<(), String> {
    let Producer {
        mut bus,
        mut stream,
        vault,
        agent,
        session_key,
        handle,
        credential,
        streamed,
        saved,
        keepalive,
        mut turn,
        mark,
        container,
        mut wakes,
    } = producer;
    let memory = answer_memory(&vault, agent, session_key);
    let cancel = |reason: StreamCancelReason| {
        if let Ok(receipt) = memory.cancel_stream(handle, reason)
            && let Ok(mut slot) = saved.lock()
        {
            *slot = Some(receipt);
        }
    };
    let fail = |reason: String| {
        cancel(StreamCancelReason::AgentAborted);
        Err(reason)
    };
    let revoked = || {
        cancel(StreamCancelReason::Custom(REVOKED.into()));
        Err("the turn's credential was revoked".to_owned())
    };
    // The newcomer barrier: the reply was assembled for the audience before
    // the entry. Its MESSAGE keeps what it saved and is cancelled; the next
    // turn is assembled afresh.
    let newcomer = || {
        cancel(StreamCancelReason::Custom(NEWCOMER.into()));
        Err("an attendee entered the conversation".to_owned())
    };
    let mut keepalive = tokio::time::interval(keepalive);
    keepalive.reset();
    loop {
        let item = tokio::select! {
            item = stream.next() => item,
            () = turn.stopping() => return fail("the server is stopping".into()),
            woke = next_entry_wake(&mut wakes) => {
                if let Some(container) = container
                    && !matches!(
                        entry_wake(&vault, container, woke, &mut wakes),
                        EntryWake::Quiet
                    )
                {
                    return newcomer();
                }
                continue;
            }
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
        // The publish arm, before any delta or the terminal goes out: an
        // attendee entered the conversation since the reply was marked,
        // whatever its wake says.
        if container.is_some_and(|container| !vault.container_output_admits(mark, container)) {
            return newcomer();
        }
        if matches!(event, LlmStreamEvent::Done { .. }) {
            // The run settled the answer before it arrived: the provider
            // spent it whether or not the answer is saved.
            if let Err(error) = bus.publish(event) {
                if credential.live() {
                    cancel(StreamCancelReason::AgentAborted);
                } else {
                    cancel(StreamCancelReason::Custom(REVOKED.into()));
                }
                return Err(format!("terminal message was not saved: {error:?}"));
            }
            return Ok(());
        }
        if !credential.live() {
            return revoked();
        }
        if let LlmStreamEvent::TextDelta { text, .. } = &event {
            // The stream saves each delta in the vault before it is
            // published, so the append is a write: it runs off the workers.
            let appended = crate::server::blocking(|| memory.append_to_stream(handle, text));
            if let Err(error) = appended {
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
