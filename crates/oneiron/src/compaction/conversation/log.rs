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

use std::collections::{BTreeMap, BTreeSet};

use super::ConversationTurnSpan;
use super::standing::standing_words_in;
use super::storage::{ConversationLandingReceipt, conversation_receipts_in};
use super::window::{ChatLogWindow, pin, window};
use crate::compaction::MAX_TRANSCRIPT_PAGE_TURNS;
use crate::compaction::driver::ConversationBinding;
use crate::memory::{Memory, RoomTurnHandle, TranscriptTurn, WitnessAuthor};
use crate::tokenizer::count_context_pack_tokens;
use crate::{EntityId, Error};
use oneiron_contracts::memory::MemoryResult;

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
    /// The branch read: a DAG conversation's HEAD.
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
    let vault = memory.vault();
    let roomed = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let roster = crate::context_board::room_roster_in(vault, &txn, conversation)?;
        roster.is_some_and(|members| !members.is_empty()) || vault.room_has_live_call(conversation)
    };
    // The words reach the room's roster, so the read is held, each private
    // thread met turn by turn, as a queued action's history is.
    let room = if roomed {
        Some(memory.for_room_projection(conversation)?.held())
    } else {
        None
    };
    let memory = room.as_ref().map_or(memory, RoomTurnHandle::memory);
    let (transcript, branch) = retained_turns(memory, conversation)?;
    let turns = transcript
        .iter()
        .map(read_turn)
        .collect::<MemoryResult<Vec<_>>>()?;
    // The reader's whole key, with its credential's, locality's and room
    // turn's ceilings, resolved before the snapshot: the room resolver opens
    // its own. Raw pins, a summary's evidence and its words are read under it.
    let scoped = vault.scoped_read(memory.read_key()?);
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let read: BTreeSet<EntityId> = turns.iter().map(|turn| turn.id).collect();
    // Summaries whose turns the reader reads, every one, whose evidence
    // still reads to its pins as this reader, and whose words stand.
    let mut standing: Vec<(ConversationLandingReceipt, String)> = Vec::new();
    let mut covering: BTreeMap<EntityId, usize> = BTreeMap::new();
    for receipt in conversation_receipts_in(&vault.store, &txn, conversation)? {
        let Some(evidence) = receipt.evidence() else {
            continue;
        };
        if !evidence.turns.iter().all(|span| read.contains(&span.turn))
            || evidence
                .turns
                .iter()
                .any(|span| covering.contains_key(&span.turn))
        {
            continue;
        }
        let Some(text) = standing_words_in(&scoped, &txn, &receipt)? else {
            continue;
        };
        for span in &evidence.turns {
            covering.insert(span.turn, standing.len());
        }
        standing.push((receipt, text));
    }
    // The lines, summaries in place, then the raw cap.
    let mut entries: Vec<Entry> = Vec::new();
    let mut emitted = BTreeSet::new();
    let mut last_covered = None;
    for (index, turn) in turns.iter().enumerate() {
        if let Some(&at) = covering.get(&turn.id) {
            if emitted.insert(at) {
                entries.push(Entry::Summary(at));
            }
            last_covered = Some(index);
            continue;
        }
        for line in 0..turn.lines.len() {
            entries.push(Entry::Raw(index, line));
        }
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
                let (receipt, text) = &standing[at];
                summaries.push(receipt.summary);
                lines.push(ChatLogLine::Summary {
                    summary: receipt.summary,
                    epoch: receipt.epoch,
                    text: text.clone(),
                });
                message_ids.push(None);
            }
            Entry::Raw(index, line) => {
                let (_, author, text) = &turns[index].lines[line];
                if !held.contains(&index) {
                    held.push(index);
                }
                lines.push(ChatLogLine::Message {
                    author: *author,
                    text: text.clone(),
                });
                message_ids.push(Some(turns[index].lines[line].0));
            }
        }
    }
    let mut pinned = true;
    let mut sources = Vec::new();
    for &index in &held {
        match pin(&scoped, &txn, &turns[index])? {
            Some((span, _)) => sources.push(span),
            None => pinned = false,
        }
    }
    let first_open = last_covered.map_or(0, |index| index + 1).min(turns.len());
    let uncompacted_tokens = turns[first_open..]
        .iter()
        .flat_map(|turn| &turn.lines)
        .map(|(_, _, text)| count_context_pack_tokens(text) as u64)
        .sum();
    let hot = usize::try_from(hot_turns).unwrap_or(usize::MAX);
    let hot_start = turns.len().saturating_sub(hot);
    let window = window(
        &scoped,
        &txn,
        ConversationBinding {
            conversation,
            branch,
        },
        &turns[first_open.min(hot_start)..hot_start],
    )?;
    let session = match turns.last() {
        Some(turn) => {
            crate::compaction::turn_session_membership_in_txn(&vault.store, &txn, &turn.id)?
        }
        None => None,
    };
    Ok(ChatLog {
        conversation,
        branch,
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

/// The conversation's retained turns as the reader reads them, and the
/// branch read.
fn retained_turns(
    memory: &Memory<'_>,
    conversation: EntityId,
) -> MemoryResult<(Vec<TranscriptTurn>, Option<EntityId>)> {
    let vault = memory.vault();
    let dag = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::conversation_dag::keeps_dag_topology(&vault.store, &txn, &conversation)?
    };
    if dag {
        let Some(head) = vault.head(&conversation)? else {
            return Ok((Vec::new(), None));
        };
        let page = memory.turn_action_branch_transcript(&conversation, &head)?;
        return Ok((page.map(|page| page.turns).unwrap_or_default(), Some(head)));
    }
    let mut turns = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = memory
            .conversation_transcript(&conversation, after.as_deref(), MAX_TRANSCRIPT_PAGE_TURNS)?
            .value;
        turns.extend(page.turns);
        match page.next {
            Some(next) => after = Some(next),
            None => return Ok((turns, None)),
        }
    }
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
