//! A queued Continue's or Retry's reuse of its reply's kept prefix (FIX
//! 4465 D), and the flight that reuse seals of its own (FIX 5027).
//!
//! The prefix is checked again as its requester reads now, through the
//! action's live reader: where it asked from, under the authority its action
//! stands on, a room's audience through the room's held projection (FIX
//! 5031). The flight's log is read through that same reader, cut at the turn
//! the action answers again, never at whatever HEAD is now: a Continue's or
//! a Retry's own reply is past the cut, so neither becomes a window's turn.
//! The flight takes the conversation's one flight claim, as a chat turn's
//! does (FIX 5030). The kept request, its fallback, a Continue's saved text,
//! a Retry's new TURN beside the old one with HEAD where it was, the
//! action's standing, its sources and its assertions are as they were.

use std::sync::Arc;

use oneiron::attempt_queue::ManifestEntry;
use oneiron::claim::CallerLocality;
use oneiron::compaction::{
    ChatLog, ChatLogCut, ChatLogLine, ConversationCompactionUnavailable, read_action_chat_log,
};
use oneiron::conversation::{
    ChatBreakpoint, TurnAction, TurnActionAttempt, TurnActionContext, chat_breakpoint,
    chat_breakpoint_stands,
};
use oneiron::memory::Memory;
use oneiron::{EntityId, LlmCapability, LlmMessage, LlmMessageRole, LlmRequest, Vault, WriteActor};

use super::{
    AnswerBreakpoint, BreakpointLog, ChatEntry, SelfChat, digest_hex, hex, message_text, self_chat,
};
use crate::ai_host::{AiHandle, CHAT_ROLE, ChatSelfMode};
use crate::api::ai::chat::{CONTINUE_INSTRUCTION, TurnSources, text_message, turn_opener};
use crate::models::RoleCall;

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
    /// The rows in this captured request, not today's fallback.
    pub(crate) sources: Option<Vec<EntityId>>,
}

/// `reuse_chat_breakpoint`: a self agent's Retry clones its reply's kept
/// prefix, its user request once; its Continue extends that prefix with the
/// reply as saved now and, when the rung cannot continue a trailing reply
/// itself, the continuation ask, after its cache boundary. The prefix is
/// admitted again as exactly its model, then sent on its captured rung with
/// no second prompt. Like any ladder stream it keeps that rung's quota
/// fallback, which may answer it on another route (FIX 7282; the board's
/// locality bound covers that route). A breakpoint that is missing, kept
/// for another reader, stale, or not admitted again is unavailable: the
/// action runs as it always did, and nothing is rebuilt and called the same
/// fork. With the row on the retained turns nothing changes. A reused
/// prefix carries its action's own flight log (FIX 5027).
pub(crate) fn reuse_chat_breakpoint(
    ai: &AiHandle,
    vault: &Vault,
    action: &TurnActionAttempt,
    context: &TurnActionContext,
) -> ChatReuse {
    let Some(mode) = ai.chat_self_mode(vault, context.agent) else {
        return ChatReuse::Today;
    };
    let mut seed = match chat_breakpoint(vault, action.conversation, action.message) {
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
    // The requester's own reader as it stands now: one whose action no
    // longer stands reads nothing kept for it.
    let Some(reader) = crate::ai_host::action_reader(vault, action) else {
        return ChatReuse::Unavailable("requester_unbound");
    };
    match chat_breakpoint_stands(&reader, &seed) {
        Ok(Ok(())) => {}
        Ok(Err(stale)) => return ChatReuse::Unavailable(stale.as_str()),
        Err(_) => return ChatReuse::Unavailable("breakpoint_unreadable"),
    }
    let Some(mut request) = seed.captured_request() else {
        return ChatReuse::Unavailable("request_changed");
    };
    // The captured call closes with the user's words, or with its opener
    // right after them (FIX 14676).
    let opened = captured_opener(&request.messages, &context.user_text);
    let asks = opened
        || request
            .messages
            .last()
            .is_some_and(|last| asks_with(last, &context.user_text));
    if !asks {
        return ChatReuse::Unavailable("user_turn_changed");
    }
    // A Retry answers now, so it closes with today's opener, never the
    // captured one; a Continue keeps the one its saved reply followed.
    if opened && action.action == TurnAction::Retry {
        request.messages.pop();
        if let Some(opener) = turn_opener(ai.chat_settings().turn_opener, vault) {
            request
                .messages
                .push(text_message(LlmMessageRole::User, opener));
        }
        // The Retry's reply follows the opener sent now, so the breakpoint
        // that reply keeps names this request and its digest, and a later
        // Continue of it resends the same opener. The original reply's own
        // breakpoint row is left as it was.
        let (Ok(text), Ok(digest)) = (serde_json::to_string(&request), request.canonical_hash())
        else {
            return ChatReuse::Unavailable("request_changed");
        };
        seed.request = text;
        seed.request_digest = hex(&digest);
    }
    // The craft it showed is what the host kept with it, never what its
    // user text reads as (FIX 9439).
    let craft = crate::ai_host::resident_craft::captured_craft(
        &request,
        &seed.craft_entries,
        vault.now_recorded_at(),
    );
    let Some(ladder) = readmit_rung(ai, vault, &seed, &request) else {
        return ChatReuse::Unavailable("rung_not_admitted");
    };
    let mut sources = TurnSources::of_agent(seed.agent);
    sources.add(Some(&seed.summaries));
    for span in &seed.sources {
        sources.add(Some(&[span.turn]));
        sources.add(Some(&span.messages));
    }
    sources.craft(&seed.craft_entries);
    sources.add(context.user_sources.as_deref());
    if action.action == TurnAction::Continue && !context.saved.is_empty() {
        sources.add(Some(&[action.assistant_turn, action.message]));
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
    let log = action_flight_log(&reader, action, &mode);
    ChatReuse::Reused(Box::new(ChatReused {
        live: RoleCall {
            request: admitted.request,
            ladder: Arc::new(ladder),
        },
        breakpoint: AnswerBreakpoint {
            mode,
            log: log.map(BreakpointLog::Compact),
            locality,
            reader: WriteActor::new(actor, class),
            instructions_digest: seed.instructions_digest.clone(),
            source: Some(seed),
            recalled: false,
            craft: Vec::new(),
            user_turn: None,
        },
        craft,
        sources: sources.rows(),
    }))
}

/// The log a reused action's own flight compacts (FIX 5027): its
/// conversation read through the action's live `reader`, cut at the turn
/// the action answers again. `None` when it does not read: the action seals
/// no flight, and its kept request is sent as it is.
fn action_flight_log(
    reader: &Memory<'_>,
    action: &TurnActionAttempt,
    mode: &ChatSelfMode,
) -> Option<ChatLog> {
    let cut = ChatLogCut {
        target: action.assistant_turn,
        before: action.user_turn,
    };
    match read_action_chat_log(reader, action.conversation, cut, mode.hot_turns()) {
        Ok(log) => Some(log),
        Err(_) => {
            tracing::info!(
                reason = ConversationCompactionUnavailable::LogUnreadable.as_str(),
                "a turn action's own compaction is unavailable; its log stays raw"
            );
            None
        }
    }
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

/// Whether `message` is the user's turn whose words are `user_text`.
fn asks_with(message: &LlmMessage, user_text: &str) -> bool {
    message.role == LlmMessageRole::User && message_text(message) == user_text
}

/// Whether `messages` close with the turn's opener alone right after the
/// user's turn whose words are `user_text` (FIX 14676).
pub(in crate::api::ai::chat) fn captured_opener(messages: &[LlmMessage], user_text: &str) -> bool {
    let [.., user, opener] = messages else {
        return false;
    };
    asks_with(user, user_text)
        && opener.role == LlmMessageRole::User
        && oneiron::context_board::is_turn_opener_line(&message_text(opener))
}

impl AnswerBreakpoint {
    /// The captured action's original request and log, re-read under its
    /// live action proof. Only the source rows the breakpoint already names
    /// form its old prefix; Continue's saved reply is borrowed separately.
    /// Its own flight's log is read apart from this one (FIX 5027).
    pub(in crate::api::ai::chat) fn action_chat(
        &self,
        ai: &AiHandle,
        vault: &Vault,
        reader: &Memory<'_>,
        action: &TurnActionAttempt,
    ) -> Option<(SelfChat, Vec<EntityId>, Vec<LlmMessage>)> {
        let seed = self.source.as_ref()?;
        let request = seed.captured_request()?;
        let Some(ChatEntry::Read(mut chat)) = self_chat(
            ai,
            vault,
            reader,
            seed.agent,
            &action.conversation.to_hex(),
            usize::MAX,
        ) else {
            return None;
        };
        if !chat.log.pinned
            || !seed
                .sources
                .iter()
                .all(|source| chat.log.sources.contains(source))
            || !seed
                .summaries
                .iter()
                .all(|summary| chat.log.summaries.contains(summary))
        {
            return None;
        }
        let user = chat
            .log
            .sources
            .iter()
            .find(|span| span.turn == action.user_turn)?;
        let mut borrowed = vec![user.turn];
        borrowed.extend_from_slice(&user.messages);
        if action.action == TurnAction::Continue {
            borrowed.push(action.assistant_turn);
            borrowed.push(action.message);
        }
        let messages: std::collections::BTreeSet<_> = seed
            .sources
            .iter()
            .flat_map(|span| span.messages.iter().copied())
            .collect();
        let mut lines = Vec::new();
        let mut ids = Vec::new();
        for (line, id) in chat.log.lines.into_iter().zip(chat.log.message_ids) {
            let retained = match &line {
                ChatLogLine::Summary { summary, .. } => seed.summaries.contains(summary),
                ChatLogLine::Message { .. } => id.is_some_and(|id| messages.contains(&id)),
            };
            if retained {
                lines.push(line);
                ids.push(id);
            }
        }
        chat.log.lines = lines;
        chat.log.message_ids = ids;
        chat.log
            .sources
            .retain(|source| seed.sources.contains(source));
        chat.log
            .summaries
            .retain(|summary| seed.summaries.contains(summary));
        Some((chat, borrowed, request.messages))
    }

    pub(in crate::api::ai::chat) fn agent(&self) -> Option<EntityId> {
        self.source.as_ref().map(|seed| seed.agent)
    }
}
