//! `chat_compaction_sources` (FIX 4465 D): a self agent's model-facing chat
//! log, read from the retained ledger as its reader reads it, the same
//! transcript a turn action's history is read from: a DAG conversation's
//! branch to its HEAD, any other's time order. Each summary that landed for
//! the conversation stands in for the turns it covers once its reader reads
//! every one of them, re-reads each pinned turn of its evidence to the
//! fingerprint its landing pinned, and reads its words. A summary any of
//! that misses for leaves its turns raw. The retained ledger is the log
//! and the evidence: a caller's own lines are neither, and none of them is
//! given a ref here.
//!
//! Every turn the log holds is pinned by its projection's fingerprint, read
//! as the reader in one snapshot. The window a flight may compact is the
//! run of turns after the last covered one and before the hot tail that is
//! complete, read exactly as its projection reads it, and witnessed into
//! one SESSION, numbered by its conversation's order there (FIX 5029).
//!
//! A conversation a room's audience reads (a roster or a live call) is read
//! through the room's held projection (FIX 5031): its transcript, its raw
//! pins, its summaries' evidence and their words all meet the roster, each
//! member's entry, each private thread and each live speaker, as the room's
//! next turn would. A projection that refuses or holds stops the log.
//!
//! A queued Continue or Retry reads its own log cut at the turn it answers
//! again (FIX 5027): the branch that leads to that turn, before the user turn
//! it answers, so neither its reply nor any turn after it is a window's turn.
//! A conversation's first turn, whose witness mints the conversation, reads
//! its log once that turn is witnessed (FIX 5034): the history before it,
//! proven empty on the ledger.
//!
//! A log is planned before its raw history is read (FIX 5032,
//! [`read_plan`]): the turns a standing summary covers are read through its
//! evidence and never hydrated; only the gaps between them and the turns
//! after the last one are read raw. The raw-history cap, the threshold's
//! count and the window are taken from those raw turns as before. The plan
//! judges its summaries in its own snapshot; the raw pins, the window and
//! the SESSION are read in the log's snapshot after it. Grant time is
//! persisted before each one (FIX 6188).
//!
//! A turn action reads only the raw turns it is answered from (FIX 5032,
//! [`action_selection`]): its TARGET turn, the user turn before it and the
//! turns whose lines fill its history. No summary stands in there. A Retry's
//! breakpoint seed pins those turns.

use std::collections::BTreeSet;

use super::ConversationTurnSpan;
use super::window::{ChatLogWindow, pin, window};
use crate::compaction::driver::ConversationBinding;
use crate::conversation::{TurnActionAttempt, TurnActionContext};
use crate::memory::{Memory, RoomTurnHandle, TranscriptTurn, WitnessAuthor};
use crate::tokenizer::count_context_pack_tokens;
use crate::{EntityId, Error};
use oneiron_contracts::memory::MemoryResult;

mod action_selection;
mod read_plan;

pub(crate) use action_selection::select_action_turns;
use read_plan::{PlannedTurn, plan_chat_log};

/// One line of a self agent's model-facing chat log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatLogLine {
    /// A landed summary in place of the turns it covers: the agent's own
    /// words about them.
    Summary {
        summary: EntityId,
        epoch: u64,
        text: String,
    },
    /// One retained message, as its reader reads it.
    Message { author: WitnessAuthor, text: String },
}

/// A self agent's chat log, as one reader read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatLog {
    pub conversation: EntityId,
    /// The branch read: a DAG conversation's HEAD, or a retry action's TARGET turn.
    pub branch: Option<EntityId>,
    /// The model-facing lines, oldest first.
    pub lines: Vec<ChatLogLine>,
    /// Each line's MESSAGE, aligned with `lines`: `None` for a summary,
    /// whose line names its own id (DESIGN-V2 R2 segment locators).
    pub message_ids: Vec<Option<EntityId>>,
    /// Each retained turn the lines hold, in order, by revision.
    pub sources: Vec<ConversationTurnSpan>,
    /// The summaries standing in the lines.
    pub summaries: Vec<EntityId>,
    /// Whether every turn the lines hold was pinned by its projection: a
    /// log that is not keeps no breakpoint.
    pub pinned: bool,
    /// The SESSION the latest retained turn was witnessed into.
    pub session: Option<EntityId>,
    /// The tokens of every retained turn no summary covers yet: what the
    /// profile's threshold is held against.
    pub uncompacted_tokens: u64,
    /// Whether the log was read through its room's held projection (FIX
    /// 5031): a roster or a live call reads the conversation.
    pub room_projection: bool,
    pub(crate) window: Option<ChatLogWindow>,
}

/// One retained turn as its reader read it.
pub(super) struct ReadTurn {
    pub(super) id: EntityId,
    /// Its non-system messages with text, in order.
    pub(super) lines: Vec<(EntityId, WitnessAuthor, String)>,
    /// Every message id its reader read.
    pub(super) messages: Vec<EntityId>,
    /// A message of it is generating or ended incomplete.
    pub(super) open: bool,
}

/// Where a queued Continue's or Retry's chat log ends (FIX 5027).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChatLogCut {
    /// The assistant TURN the action answers again: a DAG log reads the
    /// branch that leads to it, never whatever HEAD is now.
    pub target: EntityId,
    /// The user TURN `target` answers: the log holds the turns before it.
    pub before: EntityId,
}

/// Reads `conversation`'s chat log as `memory`'s reader: at most
/// `history_lines` raw messages after its summaries, the last
/// `hot_turns` turns never in a window. When a room's audience reads the
/// conversation (a roster or a live call), every read goes through the
/// room's held projection (FIX 5031).
///
/// # Errors
///
/// A conversation the reader may not read, a room projection that refuses
/// or holds, and storage errors.
pub fn read_chat_log(
    memory: &Memory<'_>,
    conversation: EntityId,
    hot_turns: u64,
    history_lines: usize,
) -> MemoryResult<ChatLog> {
    read_log(memory, conversation, None, hot_turns, history_lines)
}

/// [`read_chat_log`] for a queued Continue or Retry (FIX 5027): the log of
/// the turns before `cut`'s user turn, on the branch that leads to the turn
/// the action answers again, read as `memory` reads it, the last `hot_turns`
/// never in a window. What the action's own flight compacts; the action's
/// request stays the one its breakpoint kept.
///
/// # Errors
///
/// [`read_chat_log`]'s, and a cut whose user turn the reader does not read
/// on that branch.
pub fn read_action_chat_log(
    memory: &Memory<'_>,
    conversation: EntityId,
    cut: ChatLogCut,
    hot_turns: u64,
) -> MemoryResult<ChatLog> {
    read_log(memory, conversation, Some(cut), hot_turns, usize::MAX)
}

/// The log a conversation's first chat turn was assembled from (FIX 5034):
/// none, proven on the ledger. Read as `memory` reads it once the user's
/// turn was witnessed, the conversation holds that turn alone, its MESSAGE
/// rows exactly `written`, and no summary. The log returned is the history
/// before that turn: empty and pinned, on no branch and in no SESSION.
/// `None` when the reader reads any other line or summary of the
/// conversation, the turn it reads is not the one written, or its pin does
/// not hold.
///
/// # Errors
///
/// [`read_chat_log`]'s.
pub fn read_first_chat_log(
    memory: &Memory<'_>,
    conversation: EntityId,
    written: &[EntityId],
) -> MemoryResult<Option<ChatLog>> {
    let read = read_log(memory, conversation, None, 0, usize::MAX)?;
    let [span] = read.sources.as_slice() else {
        return Ok(None);
    };
    let only_written = !written.is_empty()
        && span.messages == written
        && read
            .message_ids
            .iter()
            .all(|id| id.is_some_and(|id| written.contains(&id)));
    if !read.pinned || !read.summaries.is_empty() || !only_written {
        return Ok(None);
    }
    Ok(Some(ChatLog {
        conversation,
        branch: None,
        lines: Vec::new(),
        message_ids: Vec::new(),
        sources: Vec::new(),
        summaries: Vec::new(),
        pinned: true,
        session: None,
        uncompacted_tokens: 0,
        room_projection: read.room_projection,
        window: None,
    }))
}

/// The held room handle `conversation`'s chat log is read through (FIX
/// 5031): `Some` when a room's audience reads it (a roster or a live call),
/// whose words reach the room's roster, so the read is held, each private
/// thread met turn by turn, as a queued action's history is. `None` reads
/// as `memory` itself.
///
/// # Errors
///
/// A room projection that refuses or holds, and storage errors.
pub(crate) fn chat_log_room<'v>(
    memory: &Memory<'v>,
    conversation: EntityId,
) -> MemoryResult<Option<RoomTurnHandle<'v>>> {
    let vault = memory.vault();
    let roomed = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let roster = crate::context_board::room_roster_in(vault, &txn, conversation)?;
        roster.is_some_and(|members| !members.is_empty()) || vault.room_has_live_call(conversation)
    };
    if !roomed {
        return Ok(None);
    }
    Ok(Some(memory.for_room_projection(conversation)?.held()))
}

/// [`read_chat_log`], cut at `cut` when an action reads it.
fn read_log(
    memory: &Memory<'_>,
    conversation: EntityId,
    cut: Option<ChatLogCut>,
    hot_turns: u64,
    history_lines: usize,
) -> MemoryResult<ChatLog> {
    let vault = memory.vault();
    let room = chat_log_room(memory, conversation)?;
    let roomed = room.is_some();
    let memory = room.as_ref().map_or(memory, RoomTurnHandle::memory);
    // The reader's whole key, with its credential's, locality's and room
    // turn's ceilings, resolved before any snapshot: the room resolver opens
    // its own. The plan's evidence and words, and the raw pins, are read
    // under it.
    let scoped = vault.scoped_read(memory.read_key()?);
    // FIX 6188: grant time is persisted before the snapshot, never inside it,
    // so a grant that has expired is judged expired for these reads.
    scoped.persist_grant_clock()?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    // FIX 5032: the summaries that stand, judged in this one snapshot that
    // the raw pins, the window and the SESSION are read in too, and the raw
    // turns read.
    let plan = plan_chat_log(memory, &scoped, &txn, conversation, cut)?;
    // The lines, summaries in place, then the raw cap. `raws` holds each raw
    // turn read, in order.
    let mut raws: Vec<&ReadTurn> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut emitted = BTreeSet::new();
    for turn in &plan.prefix {
        let turn = match turn {
            PlannedTurn::Covered { summary, .. } => {
                if emitted.insert(*summary) {
                    entries.push(Entry::Summary(*summary));
                }
                continue;
            }
            PlannedTurn::Raw(turn) => turn,
        };
        entries.extend((0..turn.lines.len()).map(|line| Entry::Raw(raws.len(), line)));
        raws.push(turn);
    }
    for turn in &plan.suffix {
        entries.extend((0..turn.lines.len()).map(|line| Entry::Raw(raws.len(), line)));
        raws.push(turn);
    }
    let raw = entries
        .iter()
        .filter(|entry| matches!(entry, Entry::Raw(..)))
        .count();
    let mut skip = raw.saturating_sub(history_lines);
    entries.retain(|entry| match entry {
        Entry::Raw(..) if skip > 0 => {
            skip -= 1;
            false
        }
        _ => true,
    });
    let mut lines = Vec::new();
    let mut message_ids = Vec::new();
    let mut summaries = Vec::new();
    let mut held: Vec<usize> = Vec::new();
    for entry in &entries {
        match *entry {
            Entry::Summary(at) => {
                let (receipt, text) = &plan.standing[at];
                summaries.push(receipt.summary);
                lines.push(ChatLogLine::Summary {
                    summary: receipt.summary,
                    epoch: receipt.epoch,
                    text: text.clone(),
                });
                message_ids.push(None);
            }
            Entry::Raw(index, line) => {
                let (id, author, text) = &raws[index].lines[line];
                if !held.contains(&index) {
                    held.push(index);
                }
                lines.push(ChatLogLine::Message {
                    author: *author,
                    text: text.clone(),
                });
                message_ids.push(Some(*id));
            }
        }
    }
    let mut pinned = true;
    let mut sources = Vec::new();
    for &index in &held {
        match pin(&scoped, &txn, raws[index])? {
            Some((span, _)) => sources.push(span),
            None => pinned = false,
        }
    }
    // The turns after the last covered one are what the threshold counts and
    // what the window may take, short of the hot tail.
    let uncompacted_tokens = plan
        .suffix
        .iter()
        .flat_map(|turn| &turn.lines)
        .map(|(_, _, text)| count_context_pack_tokens(text) as u64)
        .sum();
    let hot = usize::try_from(hot_turns).unwrap_or(usize::MAX);
    let window = window(
        &scoped,
        &txn,
        ConversationBinding {
            conversation,
            branch: plan.branch,
        },
        &plan.suffix[..plan.suffix.len().saturating_sub(hot)],
    )?;
    let session = match plan.last_turn() {
        Some(turn) => crate::compaction::turn_session_membership_in_txn(&vault.store, &txn, &turn)?,
        None => None,
    };
    Ok(ChatLog {
        conversation,
        branch: plan.branch,
        lines,
        message_ids,
        sources,
        summaries,
        pinned,
        session,
        uncompacted_tokens,
        room_projection: roomed,
        window,
    })
}

/// A line of the log before the cap: a standing summary, or one raw
/// message (its turn, its line).
enum Entry {
    Summary(usize),
    Raw(usize, usize),
}

fn read_turn(turn: &TranscriptTurn) -> MemoryResult<ReadTurn> {
    let mut lines = Vec::new();
    let mut messages = Vec::new();
    let mut open = false;
    for message in &turn.messages {
        let id = EntityId::from_hex(&message.id)?;
        messages.push(id);
        open |= message.generating || message.incomplete;
        if let Some(author) = WitnessAuthor::parse(&message.role)
            && author != WitnessAuthor::System
            && !message.text.is_empty()
        {
            lines.push((id, author, message.text.clone()));
        }
    }
    Ok(ReadTurn {
        id: EntityId::from_hex(&turn.id)?,
        lines,
        messages,
        open,
    })
}

/// Reads `action`'s retry-target pinned log as `memory`'s reader: the raw
/// retained turns on the branch to the action's TARGET turn, cut at the
/// action's user turn, capped to `history_lines` raw lines exactly as a turn
/// action's history is, and required to equal `expected` (the context the
/// action's call was assembled from) line for line before any pin is built.
/// FIX 5032: it reads only TARGET, the user turn before it and the turns
/// whose lines fill the capped history, backward from TARGET, never the
/// whole branch. `None` keeps the cold path as it was: a room's audience, a
/// target or user turn that no longer reads as admitted, any contributing
/// racing edit, reorder or extra line, or any turn whose projection no
/// longer pins. The log carries raw lines only, never HEAD, never summaries,
/// never a window: it keeps a seed, it starts no flight.
///
/// # Errors
///
/// Storage errors, and a conversation the reader may not read.
pub fn read_action_pinned_log(
    memory: &Memory<'_>,
    action: &TurnActionAttempt,
    expected: &TurnActionContext,
    history_lines: usize,
) -> MemoryResult<Option<ChatLog>> {
    let vault = memory.vault();
    let conversation = action.conversation;
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let roster = crate::context_board::room_roster_in(vault, &txn, conversation)?;
        if roster.is_some_and(|members| !members.is_empty())
            || vault.room_has_live_call(conversation)
        {
            return Ok(None);
        }
    }
    let Some(selection) =
        select_action_turns(memory, conversation, action.assistant_turn, history_lines)?
    else {
        return Ok(None);
    };
    // The latest user turn before TARGET, required to be the action's own,
    // with its exact text and sources and the exact capped history.
    let Some(user) = selection.user.filter(|user| user.id == action.user_turn) else {
        return Ok(None);
    };
    if user.text != expected.user_text
        || user.sources != expected.user_sources
        || user.history != expected.history
    {
        return Ok(None);
    }
    // The reader's whole key, as `read_chat_log` pins its turns (FIX 5031).
    let scoped = vault.scoped_read(memory.read_key()?);
    // FIX 6188: grant time is persisted before the snapshot, never inside it,
    // so a grant that has expired is judged expired for these reads.
    scoped.persist_grant_clock()?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    // Each history turn the cap keeps lines of; the oldest may be partial.
    let mut sources = Vec::new();
    for turn in &user.history_turns {
        match pin(&scoped, &txn, &read_turn(turn)?)? {
            Some((span, _)) => sources.push(span),
            None => return Ok(None),
        }
    }
    // The user turn verifies too, but stays ephemeral: sources hold history only.
    if pin(&scoped, &txn, &read_turn(&user.turn)?)?.is_none() {
        return Ok(None);
    }
    let session =
        crate::compaction::turn_session_membership_in_txn(&vault.store, &txn, &action.user_turn)?;
    let mut lines = Vec::new();
    let mut message_ids = Vec::new();
    for line in &user.history {
        lines.push(ChatLogLine::Message {
            author: line.author,
            text: line.text.clone(),
        });
        message_ids.push(
            line.sources
                .as_ref()
                .and_then(|sources| sources.get(1).copied()),
        );
    }
    Ok(Some(ChatLog {
        conversation,
        branch: selection.branch,
        lines,
        message_ids,
        sources,
        summaries: Vec::new(),
        pinned: true,
        session,
        uncompacted_tokens: 0,
        room_projection: false,
        window: None,
    }))
}
