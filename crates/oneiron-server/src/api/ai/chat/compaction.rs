//! A self agent's chat turn on its own live fork (FIX 4465 D). Only for an
//! agent whose engine-owned profile names `self` under a row that reads the
//! live context: `live_fork`, or `auto` (FIX 6029, the default), whose flight
//! forks the warm prefix or, cold, is written by the cheap writer as the
//! agent. A row on the retained turns and every other agent keep the chat
//! path as it was.
//!
//! Such a turn's log is read from the retained ledger as its caller reads
//! it, landed summaries in place of the turns they cover; the caller's own
//! lines are neither the log nor evidence. Right before the answer's
//! stream, its breakpoint captures the answer's own admitted call: past the
//! profile's threshold its flight compacts off the answer's path, and a
//! landed summary serves the turns after it. Once the reply is saved, its
//! breakpoint keeps the request its rung sent, so the reply's Continue and
//! Retry reuse that prefix on that rung. A breakpoint that is missing, stale
//! or not admitted again leaves the action to run as it always did; only
//! the live fork is unavailable.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::StreamExt;
use oneiron::attempt_queue::ManifestEntry;
use oneiron::claim::CallerLocality;
use oneiron::compaction::{ChatLog, ChatLogLine, ConversationCompactionUnavailable, read_chat_log};
use oneiron::conversation::{
    ChatBreakpoint, ChatBreakpointRung, TurnAction, TurnActionAttempt, TurnActionContext,
    chat_breakpoint, chat_breakpoint_stands, keep_chat_breakpoint,
};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission};
use oneiron::memory::{Memory, MessageStreamReceipt, WitnessAuthor, resolve_entity_ref};
use oneiron::{
    EntityId, LlmCapability, LlmMessage, LlmMessageRole, LlmRequest, LlmResult, LlmStream,
    LlmStreamEvent, Vault, WriteActor,
};

use super::{CONTINUE_INSTRUCTION, text_message};
use crate::ai_host::{AiHandle, CHAT_ROLE, ChatBreakpointCall, ChatSelfMode};
use crate::models::RoleCall;

/// What a self agent's answer brings to its breakpoint.
pub(crate) struct AnswerBreakpoint {
    mode: ChatSelfMode,
    /// The log a chat turn's request was assembled from; a reused prefix
    /// carries none and seals no flight.
    log: Option<ChatLog>,
    locality: CallerLocality,
    reader: WriteActor,
    instructions_digest: Option<String>,
    /// A reused prefix's kept breakpoint: the new reply keeps it again.
    source: Option<ChatBreakpoint>,
    /// The call carries a recalled context board (FIX 6794): its reply keeps
    /// no seed, whose sources cover only the log, so no replay sends the
    /// recalled rows again past an erase or a narrowed read.
    recalled: bool,
}

/// A chat turn's self mode and the log its caller read.
pub(super) struct SelfChat {
    mode: ChatSelfMode,
    log: ChatLog,
}

/// `chat_compaction_sources`: the self mode of `agent`'s answer in
/// `conversation_ref`, its log read from the retained ledger as `reader`
/// reads it, `history_lines` raw messages after its summaries. `None` keeps
/// the chat path as it was: a non-self agent, a row on the retained turns,
/// a room's audience, a conversation with no ledger yet, or a log the
/// caller could not read.
pub(super) fn self_chat(
    ai: &AiHandle,
    vault: &Vault,
    reader: &Memory<'_>,
    agent: EntityId,
    conversation_ref: &str,
    history_lines: usize,
) -> Option<SelfChat> {
    let mode = ai.chat_self_mode(vault, agent)?;
    let conversation = resolve_entity_ref(vault, conversation_ref).ok()?;
    match read_chat_log(reader, conversation, mode.hot_turns(), history_lines) {
        Ok(Some(log)) => Some(SelfChat { mode, log }),
        Ok(None) => None,
        Err(_) => {
            tracing::info!(
                reason = "chat_log_unread",
                "a self agent's chat log was not read; the turn keeps the chat path"
            );
            None
        }
    }
}

impl SelfChat {
    /// The log as the model reads it: each landed summary as the agent's
    /// own record of the turns it covers, then each retained message by its
    /// author.
    pub(super) fn push_log(&self, messages: &mut Vec<LlmMessage>) {
        for line in &self.log.lines {
            messages.push(match line {
                ChatLogLine::Summary { epoch, text, .. } => text_message(
                    LlmMessageRole::System,
                    serde_json::json!({"compacted_turns": {"epoch": epoch, "summary": text}})
                        .to_string(),
                ),
                ChatLogLine::Message { author, text } => text_message(
                    if *author == WitnessAuthor::User {
                        LlmMessageRole::User
                    } else {
                        LlmMessageRole::Assistant
                    },
                    text.clone(),
                ),
            });
        }
    }

    /// The turn's breakpoint, its log read as `reader` where it sits.
    pub(super) fn breakpoint(
        self,
        reader: WriteActor,
        locality: CallerLocality,
        recalled: bool,
    ) -> AnswerBreakpoint {
        let instructions_digest = self.mode.instructions().map(digest_hex);
        AnswerBreakpoint {
            mode: self.mode,
            log: Some(self.log),
            locality,
            reader,
            instructions_digest,
            source: None,
            recalled,
        }
    }
}

/// Marks where a self turn's request ends, as its fork marks it (FIX 4930).
/// A request that cannot carry the mark is sent unmarked.
pub(super) fn mark_prefix(request: &mut LlmRequest) {
    if oneiron::code_run::main_prefix_boundary(request).is_err() {
        tracing::debug!("a self agent's chat request carries no cache boundary");
    }
}

/// What the reply keeps once it is saved, and whether its own captured
/// call answered it.
pub(super) struct PendingSeed {
    seed: Option<ChatBreakpoint>,
    live: Arc<AtomicBool>,
}

impl PendingSeed {
    /// Whether the call it was entered with answered: `false` once a reused
    /// prefix's captured rung gave way to today's call (OF-490 reads this
    /// for the craft the reply was shown).
    pub(super) fn answered_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
}

/// The turn's meter, as the flight's own guard is opened on it.
pub(super) struct TurnMeter {
    pub(super) payer: WriteActor,
    pub(super) funding: Option<PayerPerson>,
    pub(super) budget_units: u64,
}

/// The answer's breakpoint, right before its stream: the seed its reply
/// keeps (a chat turn's, captured from its own admitted call; a reuse's,
/// its source's again), and, for a chat turn past its threshold, its flight
/// queued off the answer's path. `message` is the reply's MESSAGE.
pub(super) fn enter(
    ai: &AiHandle,
    vault: &Arc<Vault>,
    breakpoint: AnswerBreakpoint,
    admitted: &RoleCall,
    message: EntityId,
    meter: TurnMeter,
) -> PendingSeed {
    let AnswerBreakpoint {
        mode,
        log,
        locality,
        reader,
        instructions_digest,
        source,
        recalled,
    } = breakpoint;
    let seed = match source {
        Some(source) => Some(source),
        None if recalled => None,
        None => log
            .as_ref()
            .and_then(|log| capture_seed(mode.agent(), reader, log, instructions_digest, admitted)),
    };
    if let Some(log) = log {
        let call = ChatBreakpointCall {
            vault: Arc::clone(vault),
            mode,
            log,
            locality,
            payer: meter.payer,
            funding: meter.funding,
            budget_units: meter.budget_units,
            message,
        };
        match crate::server::blocking(|| ai.enter_chat_breakpoint(call, admitted)) {
            Ok(()) | Err(ConversationCompactionUnavailable::Quiet) => {}
            Err(why) => tracing::info!(
                reason = why.as_str(),
                "a chat turn's own compaction is unavailable; its log stays raw"
            ),
        }
    }
    PendingSeed {
        seed,
        live: Arc::new(AtomicBool::new(true)),
    }
}

/// The seed a chat turn's reply keeps: its request exactly as the rung its
/// walk takes now sends it, the rung by ref, and the log's sources. None
/// for a log whose turns were not all pinned, or a call no rung takes now.
fn capture_seed(
    agent: EntityId,
    reader: WriteActor,
    log: &ChatLog,
    instructions_digest: Option<String>,
    admitted: &RoleCall,
) -> Option<ChatBreakpoint> {
    if !log.pinned {
        return None;
    }
    let (rung, request) = admitted.ladder.live_rung(&admitted.request)?;
    let digest = request.canonical_hash().ok()?;
    Some(ChatBreakpoint {
        agent,
        reader: reader.entity_ref(),
        reader_class: reader.actor_class() as u8,
        conversation: log.conversation,
        branch: log.branch,
        session: log.session,
        request: serde_json::to_string(&request).ok()?,
        request_digest: hex(&digest),
        rung: ChatBreakpointRung {
            offer_digest: oneiron::code_run::live_fork_offer_digest(&rung.offer)?,
            provider: rung.provider,
            position: rung.position,
            wire_model: rung.wire_model,
        },
        instructions_digest,
        sources: log.sources.clone(),
        summaries: log.summaries.clone(),
    })
}

/// The answer's stream. With no `today` it is the admitted call's own, as
/// it always was. A reused prefix sends first on its captured rung: when
/// that rung fails before it speaks, the call is sent as the action would
/// always have sent it, on `today`'s route.
pub(super) fn open_stream(
    run: &RunAdmission,
    admitted: RoleCall,
    today: Option<RoleCall>,
    pending: Option<&PendingSeed>,
) -> LlmResult<LlmStream<'static>> {
    let Some(today) = today else {
        return admitted.ladder.stream(run, admitted.request, None);
    };
    let live = pending.map_or_else(
        || Arc::new(AtomicBool::new(true)),
        |pending| Arc::clone(&pending.live),
    );
    if let Err(reason) = live_attempt_headroom(run) {
        live.store(false, Ordering::Release);
        live_fork_unavailable(reason);
        return today.ladder.stream(run, today.request, None);
    }
    match admitted.ladder.stream(run, admitted.request, None) {
        Ok(stream) => Ok(first_or_today(stream, run.clone(), today, live)),
        Err(_) => {
            live.store(false, Ordering::Release);
            today.ladder.stream(run, today.request, None)
        }
    }
}

/// `live_attempt_headroom`: whether the reply's budget line, as its run
/// reads now, covers the kept rung's reservation and today's first one
/// beside it, each the line's own per-call reservation the ladder admits a
/// rung with. A line that cannot cover both skips the live attempt: today's
/// call goes alone, as it always did, and the live fork is unavailable.
fn live_attempt_headroom(run: &RunAdmission) -> Result<(), &'static str> {
    let reserve = run.declaration().budget().reserve_units;
    if run.read().remaining_units >= reserve.saturating_mul(2) {
        Ok(())
    } else {
        Err("budget_headroom")
    }
}

/// Reports a turn action's live fork unavailable, typed by `reason`: the
/// action runs as it always did.
pub(crate) fn live_fork_unavailable(reason: &'static str) {
    tracing::info!(
        reason,
        "a turn action's live fork is unavailable; the action runs as it always did"
    );
}

/// One leg of a reused prefix's stream.
enum Leg {
    First(Box<FirstLeg>),
    Rest(LlmStream<'static>),
    Done,
}

/// The captured rung's stream before it spoke, and the call behind it.
struct FirstLeg {
    live: LlmStream<'static>,
    run: RunAdmission,
    today: RoleCall,
    used: Arc<AtomicBool>,
}

/// `live`, unless its first event is a failure: then `today`'s stream.
fn first_or_today(
    live: LlmStream<'static>,
    run: RunAdmission,
    today: RoleCall,
    used: Arc<AtomicBool>,
) -> LlmStream<'static> {
    let first = Leg::First(Box::new(FirstLeg {
        live,
        run,
        today,
        used,
    }));
    LlmStream::new(futures_util::stream::unfold(first, |leg| async move {
        match leg {
            Leg::First(first) => {
                let FirstLeg {
                    mut live,
                    run,
                    today,
                    used,
                } = *first;
                match live.next().await {
                    Some(Ok(event)) => Some((Ok::<LlmStreamEvent, _>(event), Leg::Rest(live))),
                    _ => {
                        used.store(false, Ordering::Release);
                        drop(live);
                        match today.ladder.stream(&run, today.request, None) {
                            Ok(mut stream) => {
                                stream.next().await.map(|item| (item, Leg::Rest(stream)))
                            }
                            Err(error) => Some((Err(error), Leg::Done)),
                        }
                    }
                }
            }
            Leg::Rest(mut stream) => stream.next().await.map(|item| (item, Leg::Rest(stream))),
            Leg::Done => None,
        }
    }))
}

/// Keeps the saved reply's breakpoint, when its own captured call answered
/// it. A breakpoint that is not kept leaves the reply's actions to run as
/// they always did.
pub(super) fn keep(
    vault: &Vault,
    pending: Option<PendingSeed>,
    saved: Option<&MessageStreamReceipt>,
) {
    let (
        Some(PendingSeed {
            seed: Some(seed),
            live,
        }),
        Some(receipt),
    ) = (pending, saved)
    else {
        return;
    };
    if !live.load(Ordering::Acquire) {
        return;
    }
    let kept = crate::server::blocking(|| {
        keep_chat_breakpoint(vault, receipt.message_id, receipt.generation, seed)
    });
    if let Err(error) = kept {
        tracing::warn!(kind = ?error.kind(), "a chat reply's breakpoint was not kept");
    }
}

/// What a queued Continue or Retry answers with (FIX 4465 D).
pub(crate) enum ChatReuse {
    /// Not a self agent on its live fork: the action runs as it always did.
    Today,
    /// Its breakpoint is missing, stale or not admitted again: the action
    /// runs as it always did, and its live fork is unavailable for this
    /// reason.
    Unavailable(&'static str),
    /// The kept prefix, admitted again on its rung (a Continue's with the
    /// saved reply and its suffix after it), and the reply's breakpoint.
    Reused(Box<ChatReused>),
}

/// A reused prefix and the breakpoint its reply keeps.
pub(crate) struct ChatReused {
    pub(crate) live: RoleCall,
    pub(crate) breakpoint: AnswerBreakpoint,
    /// The craft the captured request shows (OF-490), in its order, as its
    /// craft message names it: what the reused call is shown, never today's.
    /// Empty for a request captured with none.
    pub(crate) craft: Vec<ManifestEntry>,
}

/// `reuse_chat_breakpoint`: a self agent's Retry clones its reply's kept
/// prefix, its user request once; its Continue extends that prefix with the
/// reply as saved now and, when the rung cannot continue a trailing reply
/// itself, the continuation ask, after its cache boundary. The prefix is
/// admitted again as exactly its model, then sent on its captured rung with
/// no second prompt and no other route. A breakpoint that is missing, kept
/// for another reader, stale, or not admitted again is unavailable: the
/// action runs as it always did, and nothing is rebuilt and called the same
/// fork. With the row on the retained turns nothing changes.
pub(crate) fn reuse_chat_breakpoint(
    ai: &AiHandle,
    vault: &Vault,
    action: &TurnActionAttempt,
    context: &TurnActionContext,
) -> ChatReuse {
    let Some(mode) = ai.chat_self_mode(vault, context.agent) else {
        return ChatReuse::Today;
    };
    let seed = match chat_breakpoint(vault, action.conversation, action.message) {
        Ok(Some(seed)) => seed,
        Ok(None) => return ChatReuse::Unavailable("breakpoint_missing"),
        Err(_) => return ChatReuse::Unavailable("breakpoint_unreadable"),
    };
    let Ok((actor, class)) = action.requester() else {
        return ChatReuse::Unavailable("requester_unbound");
    };
    if seed.agent != context.agent {
        return ChatReuse::Unavailable("breakpoint_other_agent");
    }
    // A prefix read for one requester is never sent for another.
    if seed.reader != actor || seed.reader_class != class as u8 {
        return ChatReuse::Unavailable("breakpoint_other_reader");
    }
    if seed.instructions_digest != mode.instructions().map(digest_hex) {
        return ChatReuse::Unavailable("instructions_changed");
    }
    match chat_breakpoint_stands(vault, &seed) {
        Ok(Ok(())) => {}
        Ok(Err(stale)) => return ChatReuse::Unavailable(stale.as_str()),
        Err(_) => return ChatReuse::Unavailable("breakpoint_unreadable"),
    }
    let Some(mut request) = seed.captured_request() else {
        return ChatReuse::Unavailable("request_changed");
    };
    let asks = request.messages.last().is_some_and(|last| {
        last.role == LlmMessageRole::User && message_text(last) == context.user_text
    });
    if !asks {
        return ChatReuse::Unavailable("user_turn_changed");
    }
    let craft = crate::ai_host::resident_craft::captured_craft(&request, vault.now_recorded_at());
    let Some(ladder) = readmit_rung(ai, vault, &seed, &request) else {
        return ChatReuse::Unavailable("rung_not_admitted");
    };
    if action.action == TurnAction::Continue && !context.saved.is_empty() {
        let prefill = ladder.supports(&request.model, &LlmCapability::AssistantPrefill);
        request.messages.push(text_message(
            LlmMessageRole::Assistant,
            context.saved.clone(),
        ));
        if !prefill {
            request.messages.push(text_message(
                LlmMessageRole::User,
                CONTINUE_INSTRUCTION.to_owned(),
            ));
        }
    }
    let Ok(admitted) = ai
        .model_runtime()
        .admit_seat_bound(vault, CHAT_ROLE, request)
    else {
        return ChatReuse::Unavailable("rung_not_admitted");
    };
    let locality = if action.off_device {
        CallerLocality::OffDevice
    } else {
        CallerLocality::OnDevice
    };
    ChatReuse::Reused(Box::new(ChatReused {
        live: RoleCall {
            request: admitted.request,
            ladder: Arc::new(ladder),
        },
        breakpoint: AnswerBreakpoint {
            mode,
            log: None,
            locality,
            reader: WriteActor::new(actor, class),
            instructions_digest: seed.instructions_digest.clone(),
            source: Some(seed),
            recalled: false,
        },
        craft,
    }))
}

/// The one-rung ladder `seed`'s rung is sent on, when the live route still
/// admits `request` as exactly its model and that rung takes it now.
fn readmit_rung(
    ai: &AiHandle,
    vault: &Vault,
    seed: &ChatBreakpoint,
    request: &LlmRequest,
) -> Option<crate::models::OfferLadder> {
    let admitted = ai
        .model_runtime()
        .admit_seat_bound(vault, CHAT_ROLE, request.clone())
        .ok()?;
    let rung = admitted.ladder.live_rung_by_ref(
        &seed.rung.provider,
        seed.rung.position,
        &seed.rung.wire_model,
        &seed.rung.offer_digest,
        &admitted.request,
    )?;
    admitted.ladder.live_fork_ladder(&rung)
}

fn message_text(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            oneiron::ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// The hex BLAKE3 of `text`.
fn digest_hex(text: &str) -> String {
    hex(blake3::hash(text.as_bytes()).as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
