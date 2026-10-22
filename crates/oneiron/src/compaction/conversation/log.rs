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
//! one SESSION in that SESSION's own order.

use std::collections::{BTreeMap, BTreeSet};

use super::ConversationTurnSpan;
use super::storage::{ConversationLandingReceipt, conversation_receipts_in};
use crate::claim::ScopedRead;
use crate::compaction::self_writer::hex32;
use crate::compaction::{CompactionWindowMessage, decode_epoch_summary_body};
use crate::dreamer_consolidation::{ConversationSpanRead, conversation_span_text_in};
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{
    MAX_TRANSCRIPT_PAGE_TURNS, Memory, MemoryResult, TranscriptTurn, WitnessAuthor,
};
use crate::tokenizer::count_context_pack_tokens;
use crate::{EntityId, Error, Vault, WriteActor};

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

/// What a flight may compact now: one SESSION's turns in its own order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChatLogWindow {
    pub(crate) session: EntityId,
    pub(crate) messages: Vec<CompactionWindowMessage>,
    /// Every record the window's words were read from.
    pub(crate) sources: Vec<EntityId>,
    pub(crate) spans: Vec<ConversationTurnSpan>,
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
    pub(crate) window: Option<ChatLogWindow>,
}

/// One retained turn as its reader read it.
struct ReadTurn {
    id: EntityId,
    /// Its non-system messages with text, in order.
    lines: Vec<(EntityId, WitnessAuthor, String)>,
    /// Every message id its reader read.
    messages: Vec<EntityId>,
    /// A message of it is generating or ended incomplete.
    open: bool,
}

/// Reads `conversation`'s chat log as `memory`'s reader: at most
/// `history_lines` raw messages after its summaries, the last
/// `hot_turns` turns never in a window. `None` when a room's audience
/// reads the conversation (a roster or a live call): its turns keep the
/// chat path as it was.
///
/// # Errors
///
/// A conversation the reader may not read, and storage errors.
pub fn read_chat_log(
    memory: &Memory<'_>,
    conversation: EntityId,
    hot_turns: u64,
    history_lines: usize,
) -> MemoryResult<Option<ChatLog>> {
    let vault = memory.vault();
    {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let roster = crate::context_board::room_roster_in(vault, &txn, conversation)?;
        if roster.is_some_and(|members| !members.is_empty())
            || vault.room_has_live_call(conversation)
        {
            return Ok(None);
        }
    }
    let (transcript, branch) = retained_turns(memory, conversation)?;
    let turns = transcript
        .iter()
        .map(read_turn)
        .collect::<MemoryResult<Vec<_>>>()?;
    let reader = WriteActor::new(memory.actor(), memory.actor_class());
    // The reader's whole key, with its credential's, locality's and room
    // turn's ceilings, resolved before the snapshot: the room resolver opens
    // its own. A summary's evidence and words are read under it.
    let evidence_read = vault.scoped_read(memory.read_key()?);
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
        if evidence.turns.is_empty()
            || !evidence.turns.iter().all(|span| read.contains(&span.turn))
            || evidence
                .turns
                .iter()
                .any(|span| covering.contains_key(&span.turn))
        {
            continue;
        }
        if !evidence_reads_as_pinned(&evidence_read, &txn, &evidence.turns)? {
            continue;
        }
        let Some(text) = summary_words(&evidence_read, &txn, &receipt.summary)? else {
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
        match pin(vault, &txn, reader, &turns[index])? {
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
        vault,
        &txn,
        reader,
        &turns[first_open.min(hot_start)..hot_start],
    )?;
    let session = match turns.last() {
        Some(turn) => {
            crate::compaction::turn_session_membership_in_txn(&vault.store, &txn, &turn.id)?
        }
        None => None,
    };
    Ok(Some(ChatLog {
        conversation,
        branch,
        lines,
        message_ids,
        sources,
        summaries,
        pinned,
        session,
        uncompacted_tokens,
        window,
    }))
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

/// Whether every pinned turn of a summary's evidence reads, as `read` in
/// `txn`, to the fingerprint its landing pinned. A turn the reader may not
/// read now, or one that reads other words, rows, authors or stream state
/// than it was cut from, keeps the summary out: its turns render raw.
fn evidence_reads_as_pinned(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    spans: &[ConversationTurnSpan],
) -> MemoryResult<bool> {
    let Some(pins) = spans
        .iter()
        .map(|span| Some((span.turn, hex32(&span.fingerprint)?)))
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(false);
    };
    Ok(matches!(
        conversation_span_text_in(read, txn, &pins)?,
        ConversationSpanRead::Ready(_)
    ))
}

/// The words of a landed summary while they stand, read as `read`: the
/// summary's own row and its sources' disclosure fence admit them.
fn summary_words(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    summary: &EntityId,
) -> MemoryResult<Option<String>> {
    let Some((kind, _, body)) = read
        .get_entities_parts_in_txn(txn, std::slice::from_ref(summary))?
        .pop()
        .flatten()
    else {
        return Ok(None);
    };
    if kind != crate::registry::ENTITY_TYPE_SUMMARY {
        return Ok(None);
    }
    Ok(decode_epoch_summary_body(&body)
        .ok()
        .map(|body| body.text)
        .filter(|text| !text.trim().is_empty()))
}

/// `turn` pinned by its projection read as `reader`, with the projection's
/// text; `None` when the projection refuses it or reads other words than
/// the transcript does, or the turn speaks for more than one author.
fn pin(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: WriteActor,
    turn: &ReadTurn,
) -> MemoryResult<Option<(ConversationTurnSpan, String)>> {
    use crate::ports::EntityStore;
    let mut authors = turn.lines.iter().map(|(_, author, _)| *author);
    let Some(author) = authors.next() else {
        return Ok(None);
    };
    if authors.any(|other| other != author) {
        return Ok(None);
    }
    let Some(row) = vault.port_entity_get(txn, &turn.id)? else {
        return Ok(None);
    };
    let Ok(text) =
        crate::dreamer_consolidation::live_turn_text_in(vault, txn, reader, &turn.id, &row.body)
    else {
        return Ok(None);
    };
    let Some(words) = text.text().map(str::to_owned) else {
        return Ok(None);
    };
    let read: Vec<&str> = turn
        .lines
        .iter()
        .map(|(_, _, text)| text.as_str())
        .collect();
    if words.is_empty() || words != read.join("\n") {
        return Ok(None);
    }
    let Ok(fingerprint) = text.summary_fingerprint() else {
        return Ok(None);
    };
    Ok(Some((
        ConversationTurnSpan {
            turn: turn.id,
            role: author.as_str().to_owned(),
            messages: turn.messages.clone(),
            fingerprint: bytes_to_hex_lower(&fingerprint),
        },
        words,
    )))
}

/// The window `candidates` hold: from the first, while each turn is
/// complete, pinned and witnessed into the first one's SESSION, in that
/// SESSION's own order.
fn window(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: WriteActor,
    candidates: &[ReadTurn],
) -> MemoryResult<Option<ChatLogWindow>> {
    let mut session: Option<(EntityId, Vec<EntityId>)> = None;
    let mut next: Option<u64> = None;
    let mut messages = Vec::new();
    let mut sources = Vec::new();
    let mut spans = Vec::new();
    for turn in candidates {
        if turn.open {
            break;
        }
        let Some(member) =
            crate::compaction::turn_session_membership_in_txn(&vault.store, txn, &turn.id)?
        else {
            break;
        };
        if session.is_none() {
            let order = crate::compaction::SESSION_TURNS
                .scan_keys(&vault.store, txn, member.as_bytes())?
                .into_iter()
                .map(|(_, turn)| turn)
                .collect();
            session = Some((member, order));
        }
        let Some((held, order)) = session.as_ref() else {
            break;
        };
        if *held != member {
            break;
        }
        let Some(number) = order
            .iter()
            .position(|id| *id == turn.id)
            .and_then(|at| u64::try_from(at).ok())
        else {
            break;
        };
        if next.is_some_and(|expected| expected != number) {
            break;
        }
        let Some((span, words)) = pin(vault, txn, reader, turn)? else {
            break;
        };
        let content = format!("{}: {words}", span.role);
        messages.push(CompactionWindowMessage {
            message_id: turn.lines.first().map_or(turn.id, |(id, _, _)| *id),
            turn_id: turn.id,
            tokens: count_context_pack_tokens(&content) as u64,
            content,
            turn: number,
        });
        sources.push(turn.id);
        sources.extend(turn.messages.iter().copied());
        spans.push(span);
        next = number.checked_add(1);
    }
    Ok(session
        .filter(|_| !messages.is_empty())
        .map(|(session, _)| ChatLogWindow {
            session,
            messages,
            sources,
            spans,
        }))
}
