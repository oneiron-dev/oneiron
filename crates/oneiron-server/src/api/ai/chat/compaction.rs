//! A self agent's chat turn on its own live fork (FIX 4465 D). Only for an
//! agent whose engine-owned profile names `self`, under every self row:
//! `live_fork`; `auto` (FIX 6029, the default), whose flight forks the warm
//! prefix or, cold, is written by the cheap writer as the agent; and the
//! retained turns, whose flight the cheap writer always writes as the agent
//! (L10-33). Every other agent keeps the chat path as it was.
//!
//! Such a turn's log is read from the retained ledger as its caller reads
//! it, landed summaries in place of the turns they cover; the caller's own
//! lines are neither the log nor evidence. Right before the answer's
//! stream, its breakpoint captures the answer's own admitted call: past the
//! profile's threshold its flight compacts off the answer's path, and a
//! landed summary serves the turns after it. The reply's seed is kept for
//! its stream generation before its call is sent (FIX 5028, `seeds`), so
//! the reply's Continue and Retry reuse that prefix on that rung, after a
//! crash too (`reuse`); a reused prefix seals its own flight (FIX 5027).
//! A conversation's first turn binds its breakpoint once its witness minted
//! the conversation (FIX 5034). A breakpoint that is missing, stale or not
//! admitted again leaves the action to run as it always did; only the live
//! fork is unavailable.

use std::sync::Arc;

use oneiron::attempt_queue::ManifestEntry;
use oneiron::claim::CallerLocality;
use oneiron::compaction::{ChatLog, ChatLogLine, read_chat_log, read_first_chat_log};
use oneiron::conversation::{
    ChatBreakpoint, ChatBreakpointUserTurn, TurnAction, TurnActionAttempt,
};
use oneiron::llm::run_admission::PayerPerson;
use oneiron::memory::{Memory, WitnessAuthor, resolve_entity_ref};
use oneiron::{EntityId, LlmMessage, LlmMessageRole, LlmRequest, Vault, WriteActor};

use super::{AnswerStream, text_message};
use crate::ai_host::{AiHandle, ChatSelfMode};
use crate::models::RoleCall;

mod reuse;
mod seeds;

pub(super) use reuse::captured_opener;
pub(crate) use reuse::{ChatReuse, ChatReused, reuse_chat_breakpoint};
pub(crate) use seeds::live_fork_unavailable;
pub(super) use seeds::{PendingSeed, keep, open_stream};

/// What a self agent's answer brings to its breakpoint.
pub(crate) struct AnswerBreakpoint {
    mode: ChatSelfMode,
    /// The log the answer's request was assembled from, or a reused
    /// prefix's own action log (FIX 5027), with whether its flight compacts
    /// it: a board-less Retry only captures its target-bound request
    /// (#5481). `None` seals no flight.
    log: Option<BreakpointLog>,
    locality: CallerLocality,
    reader: WriteActor,
    instructions_digest: Option<String>,
    /// A reused prefix's kept breakpoint: the new reply keeps it again.
    source: Option<ChatBreakpoint>,
    /// The call carries a recalled context board (FIX 6794): its reply keeps
    /// no seed, whose sources cover only the log, so no replay sends the
    /// recalled rows again past an erase or a narrowed read.
    recalled: bool,
    /// The craft rows the host's snapshot read for the request (FIX 9439):
    /// a chat turn's seed keeps them beside its request.
    craft: Vec<ManifestEntry>,
    /// The user turn the request answers, by the rows its witness wrote
    /// (FIX 5033): a captured seed binds it apart from its log. `None`
    /// keeps no seed.
    user_turn: Option<ChatBreakpointUserTurn>,
}

impl AnswerBreakpoint {
    /// The breakpoint, binding `user_turn`, the user turn its request
    /// answers (FIX 5033). A reused prefix keeps its source's own.
    pub(crate) fn with_user_turn(mut self, user_turn: Option<ChatBreakpointUserTurn>) -> Self {
        self.user_turn = user_turn;
        self
    }
}

/// An ordinary turn compacts its log; an action only captures its exact
/// target-bound request for a later Retry.
enum BreakpointLog {
    Compact(ChatLog),
    CaptureOnly(ChatLog),
}

impl BreakpointLog {
    fn log(&self) -> &ChatLog {
        match self {
            Self::Compact(log) | Self::CaptureOnly(log) => log,
        }
    }
}

/// A chat turn's self mode and the log its caller read.
pub(super) struct SelfChat {
    mode: ChatSelfMode,
    log: ChatLog,
}

/// A self agent's chat turn, as its caller read it before the user's turn
/// was witnessed.
pub(super) enum ChatEntry {
    /// The log its caller read.
    Read(SelfChat),
    /// No log read: a conversation with no ledger yet, or a log the caller
    /// could not read. A first turn binds its log once its witness minted
    /// the conversation (FIX 5034).
    Unread(ChatSelfMode),
}

/// `chat_compaction_sources`: the self mode of `agent`'s answer in
/// `conversation_ref`, its log read from the retained ledger as `reader`
/// reads it (a room's audience through the room's held projection, FIX
/// 5031), `history_lines` raw messages after its summaries. `None` keeps
/// the chat path as it was: a non-self agent, or a ref that names nothing.
pub(super) fn self_chat(
    ai: &AiHandle,
    vault: &Vault,
    reader: &Memory<'_>,
    agent: EntityId,
    conversation_ref: &str,
    history_lines: usize,
) -> Option<ChatEntry> {
    let mode = ai.chat_self_mode(vault, agent)?;
    let conversation = resolve_entity_ref(vault, conversation_ref).ok()?;
    match read_chat_log(reader, conversation, mode.hot_turns(), history_lines) {
        Ok(log) => Some(ChatEntry::Read(SelfChat { mode, log })),
        Err(_) => {
            tracing::info!(
                reason = "chat_log_unread",
                "a self agent's chat log was not read; the turn keeps the chat path"
            );
            Some(ChatEntry::Unread(mode))
        }
    }
}

/// A conversation's first turn's self chat (FIX 5034), bound once its
/// witness minted `conversation`: `mode`'s, its log the history before the
/// user's turn, whose `written` MESSAGE rows `reader` reads alone there.
/// That history is empty, proven on the ledger; the user's turn is never
/// read into it again. `None` keeps the chat path as it was.
pub(super) fn first_turn_chat(
    mode: ChatSelfMode,
    reader: &Memory<'_>,
    conversation: EntityId,
    written: Option<&[EntityId]>,
) -> Option<SelfChat> {
    match read_first_chat_log(reader, conversation, written?) {
        Ok(log) => log.map(|log| SelfChat { mode, log }),
        Err(_) => {
            tracing::info!(
                reason = "chat_log_unread",
                "a self agent's first chat log was not read; the turn keeps the chat path"
            );
            None
        }
    }
}

impl SelfChat {
    /// The log as its caller read it, which the turn's segment manifest
    /// names its lines from (DESIGN-V2 R2).
    pub(super) fn log(&self) -> &ChatLog {
        &self.log
    }

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

    /// The rows the log's lines were read from (FIX 6935): each summary
    /// standing in them and each retained turn they hold, with its messages.
    /// `None` for a log whose turns were not all pinned, whose rows it does
    /// not all name.
    pub(super) fn sources(&self) -> Option<Vec<EntityId>> {
        if !self.log.pinned {
            return None;
        }
        let mut rows = self.log.summaries.clone();
        for span in &self.log.sources {
            rows.push(span.turn);
            rows.extend_from_slice(&span.messages);
        }
        Some(rows)
    }

    /// The turn's breakpoint, its log read as `reader` where it sits, with
    /// `craft`, the rows its snapshot craft read showed (FIX 9439).
    pub(super) fn breakpoint(
        self,
        reader: WriteActor,
        locality: CallerLocality,
        recalled: bool,
        craft: Vec<ManifestEntry>,
    ) -> AnswerBreakpoint {
        let instructions_digest = self.mode.instructions().map(digest_hex);
        AnswerBreakpoint {
            mode: self.mode,
            log: Some(BreakpointLog::Compact(self.log)),
            locality,
            reader,
            instructions_digest,
            source: None,
            recalled,
            craft,
            user_turn: None,
        }
    }
}

/// Captures only a board-less Retry's exact target-bound call. It keeps no
/// flight and changes neither this request nor its admission.
pub(crate) fn action_breakpoint(
    ai: &AiHandle,
    vault: &Vault,
    action: &TurnActionAttempt,
    agent: EntityId,
    log: ChatLog,
    craft: Vec<ManifestEntry>,
    assembled: &[LlmMessage],
    admitted: &RoleCall,
) -> Option<AnswerBreakpoint> {
    if action.action != TurnAction::Retry
        || serde_json::to_vec(&admitted.request.messages).ok()?
            != serde_json::to_vec(assembled).ok()?
    {
        return None;
    }
    let mode = ai.chat_self_mode(vault, agent)?;
    let instructions_digest = mode.instructions().map(digest_hex);
    let (actor, class) = action.requester().ok()?;
    Some(AnswerBreakpoint {
        mode,
        log: Some(BreakpointLog::CaptureOnly(log)),
        locality: if action.off_device {
            CallerLocality::OffDevice
        } else {
            CallerLocality::OnDevice
        },
        reader: WriteActor::new(actor, class),
        instructions_digest,
        source: None,
        recalled: false,
        craft,
        user_turn: None,
    })
}

/// Marks where a self turn's request ends, as its fork marks it (FIX 4930).
/// A request that cannot carry the mark is sent unmarked.
pub(super) fn mark_prefix(request: &mut LlmRequest) {
    if oneiron::code_run::main_prefix_boundary(request).is_err() {
        tracing::debug!("a self agent's chat request carries no cache boundary");
    }
}

/// The turn's meter, as the flight's own guard is opened on it.
pub(super) struct TurnMeter {
    pub(super) payer: WriteActor,
    pub(super) funding: Option<PayerPerson>,
    pub(super) budget_units: u64,
}

/// The answer's breakpoint, right before its stream: held until the answer
/// ends, when [`keep`] binds the rung that answered it (FIX 4933), never the
/// rung its walk would take now. A reuse's seed, its source's again, is
/// known now: it is kept for `handle`'s generation right before the call is
/// sent (FIX 5028). A chat turn that compacts its log, or a reused prefix
/// that compacts its own action log (FIX 5027), keeps a copy of its own
/// `admitted` call for its flight. `sources` is every row `admitted` was
/// read from, `None` when not all were witnessed.
pub(super) fn enter(
    vault: &Arc<Vault>,
    breakpoint: AnswerBreakpoint,
    admitted: &RoleCall,
    handle: &AnswerStream,
    meter: TurnMeter,
    sources: Option<Vec<EntityId>>,
) -> PendingSeed {
    let admitted = matches!(breakpoint.log, Some(BreakpointLog::Compact(_))).then(|| RoleCall {
        request: admitted.request.clone(),
        ladder: Arc::clone(&admitted.ladder),
    });
    PendingSeed::new(vault, handle, breakpoint, admitted, meter, sources)
}

pub(super) fn message_text(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            oneiron::ContentPart::Text { text, .. } => Some(text.as_str()),
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
