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
use oneiron::attempt_queue::ManifestEntry;
use oneiron::claim::ScopedReadActorKey;
use oneiron::conversation::{OutputMark, TurnActionAttempt};
use oneiron::dreamer_wake::{AgentWakeSignals, WakeTurnSubject};
use oneiron::llm::run_admission::PayerPerson;
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
use oneiron::task_verb::verb_hook_boundary;
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
use crate::ai_host::payer_funding::room_launch_funding;
use crate::ai_host::{AiHandle, TurnGuard};
use crate::api::credential_memory;
use crate::api::facade::{self, DoorClaim};
use crate::auth::{CoreAuth, CoreScope};
use crate::models::{RoleCall, RoleRefusal, Seat};
use crate::server::SyncServer;
use crate::voice_host::{EntryWake, EntryWakes, entry_wake, next_entry_wake};

mod admission;
mod answer;
mod assertions;
mod compaction;
mod delivery;
mod hook_ask;
mod hooks;
mod recall;
mod segments;
mod sitting;
mod sources;

pub(crate) use answer::{begin_answer, chat_request};
pub(crate) use assertions::ReplyAssertionCollector;
pub(crate) use compaction::{
    AnswerBreakpoint, ChatReuse, live_fork_unavailable, reuse_chat_breakpoint,
};
pub(crate) use hooks::{after_turn, turn_generate_pre};

use admission::start_turn;
use answer::begin_sourced_answer;
use delivery::{produce, streamed, whole};
use hooks::{hook_stopped, witness_through_row};

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

/// The writer of the user's turn: the slip's principal, or the owner a
/// self-hosted root or the dev mode acts as (FIX 2222).
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
    // A self-hosted root or the dev mode writes as the owner its host action
    // names; a hosted operator's root writes as nobody (FIX 2222).
    if let Some(action) = crate::api::host_action::host_action_of(vault, auth) {
        let actor = action
            .map_err(|error| match error {
                oneiron::Error::HostActionRequiresSupportGrant => {
                    Box::new(crate::api::host_action::host_action_refusal(error).into_response())
                }
                _ => denied(),
            })?
            .actor();
        return Ok((actor.entity_ref(), actor.actor_class()));
    }
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| denied())?,
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
    // FIX 6794: the turn reads the vault's memory through the context board,
    // before anything is written.
    let board = match &payload {
        Ok(Json(request)) => recall::turn_board(&server, &auth, request).await,
        Err(_) => None,
    };
    let response = match start_turn(&auth, &server, peer, locality, &headers, payload, board) {
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

/// Marks the end of message `message` of a self turn's `request` as a
/// cache boundary (FIX 6676): the end of its history, before the turn's
/// context. A request that cannot carry the mark is sent without it.
fn mark_history_end(request: &mut LlmRequest, message: usize) {
    let Some(part) = request
        .messages
        .get(message)
        .and_then(|held| held.content.len().checked_sub(1))
    else {
        return;
    };
    let boundary = oneiron::code_run::CacheBoundary::Message { message, part };
    if oneiron::code_run::mark_cache_boundary(request, boundary).is_err() {
        tracing::debug!("a self agent's chat history carries no cache boundary");
    }
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

/// One assistant reply to generate: whose, where it is written, and the
/// call admitted for it.
pub(crate) struct Answer {
    pub(crate) vault: Arc<Vault>,
    /// The answering agent definition, which writes the MESSAGE.
    pub(crate) agent: EntityId,
    /// The authenticated actor/machine sitting of a live chat request.
    pub(crate) session_key: Option<SessionKey>,
    /// The sitting the answer's end signals activity on: the request's own,
    /// but for a turn that signals none (`sitting`, FIX 5564).
    pub(crate) activity: Option<SessionKey>,
    pub(crate) open: AnswerOpen,
    pub(crate) mode: MessageWriteMode,
    pub(crate) admitted: RoleCall,
    /// The actor whose budget line the turn runs on.
    pub(crate) payer: WriteActor,
    /// Who the turn bills when a room pays for it (FIX 805), which its
    /// caller resolved before anything was written; `None` is the vault
    /// owner.
    pub(crate) funding: Option<PayerPerson>,
    pub(crate) budget_units: u64,
    pub(crate) credential: TurnCredential,
    pub(crate) keepalive: Duration,
    /// The newcomer barrier (OF-365 P5, FIX 1389): the container output mark
    /// the caller took before the first read its request was assembled from,
    /// so no delta goes out into the reply's conversation once an attendee
    /// entered it from there on.
    pub(crate) mark: OutputMark,
    /// A self agent's breakpoint on its live fork (FIX 4465 D); `None`
    /// leaves the answer as it always was.
    pub(crate) breakpoint: Option<AnswerBreakpoint>,
    /// The call a turn action would always have sent, when `admitted` is
    /// its reused prefix: sent instead if the captured rung fails before it
    /// speaks.
    pub(crate) today: Option<RoleCall>,
    /// The craft `admitted` shows with no attempt to stamp it on (OF-490),
    /// in its order: kept on the reply's receipt once it is saved. `None`
    /// for a call shown none, a turn that keeps no record, and a turn
    /// action, whose attempt's manifest names its craft.
    pub(crate) craft: Option<Vec<ManifestEntry>>,
    /// The records this reply cited or created, as trusted host code notes
    /// them (FIX 3416): a fresh collector per reply, Continue's and Retry's
    /// too, never an earlier reply's.
    pub(crate) assertions: ReplyAssertionCollector,
}

/// Where a reply is written.
pub(crate) enum AnswerOpen {
    /// A new MESSAGE in the turn this names.
    Turn(WitnessTurn),
    /// A Retry's new MESSAGE, answering `action`'s reply again in a new
    /// TURN that its terminal lands with it (FIX 3152), linked to the old
    /// reply by a `regenerates` edge.
    Retry {
        turn: WitnessTurn,
        action: Box<TurnActionAttempt>,
    },
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
    /// Whether a reused prefix's captured rung gave way to the call a turn
    /// action would always have sent (`today`), which answered instead.
    pub(crate) fell_back: bool,
}

/// What a saved reply's craft receipt names (OF-490).
struct ReplyCraft {
    agent: EntityId,
    session_key: Option<SessionKey>,
    conversation: EntityId,
    message: EntityId,
    entries: Vec<ManifestEntry>,
    request_digest: String,
    result_digest: String,
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
        // appended before the one commit. An incomplete terminal (FIX 8617)
        // is the streamed text itself, saved once already: nothing is
        // appended, and its reason ends the MESSAGE partial.
        let text = message_text(&terminal.message);
        let streamed = self
            .streamed
            .lock()
            .map_or_else(|_| String::new(), |text| text.clone());
        let partial = matches!(
            terminal.finish_reason,
            oneiron::FinishReason::Incomplete { .. }
        );
        if !partial
            && let Some(rest) = text.strip_prefix(streamed.as_str())
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
        // write transaction. The records the producer stamped on its
        // terminal are judged and kept with it (FIX 3416).
        let credential = &self.credential;
        let asserted = assertions::witness_assertions(&terminal.reply_assertions);
        let finish_reason = terminal.finish_reason.clone();
        let receipt = memory
            .finalize_model_stream_if(self.handle, finish_reason, &asserted, |txn| {
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
    /// The reply's host-side records, stamped on its terminal.
    assertions: ReplyAssertionCollector,
}
