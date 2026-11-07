//! The window a chat flight may compact, and each turn's pin.
//!
//! A turn is pinned by its projection read through the log's own lane (FIX
//! 5031): the reader's whole key, its room's held ceiling, proof and
//! locality included, so raw pins meet the same read the evidence and the
//! summaries meet. The window is the run of complete, pinned turns
//! witnessed into one SESSION, numbered by their place in their
//! conversation's order within that SESSION (FIX 5029).

use super::ConversationTurnSpan;
use super::log::ReadTurn;
use super::order::conversation_turn_order_in;
use crate::EntityId;
use crate::claim::ScopedRead;
use crate::compaction::CompactionWindowMessage;
use crate::compaction::driver::ConversationBinding;
use crate::entity_id::bytes_to_hex_lower;
use crate::tokenizer::count_context_pack_tokens;
use oneiron_contracts::memory::MemoryResult;

/// What a flight may compact now: one SESSION's turns of one conversation,
/// in that conversation's order there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChatLogWindow {
    pub(crate) session: EntityId,
    pub(crate) messages: Vec<CompactionWindowMessage>,
    /// Every record the window's words were read from.
    pub(crate) sources: Vec<EntityId>,
    pub(crate) spans: Vec<ConversationTurnSpan>,
}

/// `turn` pinned by its projection read as `read`, with the projection's
/// text; `None` when the projection refuses it, withholds a message of it or
/// reads other words than the transcript does, or the turn speaks for more
/// than one author.
pub(super) fn pin(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: &ReadTurn,
) -> MemoryResult<Option<(ConversationTurnSpan, String)>> {
    let mut authors = turn.lines.iter().map(|(_, author, _)| *author);
    let Some(author) = authors.next() else {
        return Ok(None);
    };
    if authors.any(|other| other != author) {
        return Ok(None);
    }
    let Ok(Some(text)) = crate::dreamer_consolidation::scoped_turn_text_in(read, txn, &turn.id)
    else {
        return Ok(None);
    };
    let Some(words) = text.text().map(str::to_owned) else {
        return Ok(None);
    };
    let transcript: Vec<&str> = turn
        .lines
        .iter()
        .map(|(_, _, text)| text.as_str())
        .collect();
    if words.is_empty() || words != transcript.join("\n") {
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
/// complete, pinned and witnessed into the first one's SESSION, at the next
/// place of `binding`'s conversation order within that SESSION.
pub(super) fn window(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    binding: ConversationBinding,
    candidates: &[ReadTurn],
) -> MemoryResult<Option<ChatLogWindow>> {
    let store = &read.vault().store;
    let mut session: Option<(EntityId, Vec<EntityId>)> = None;
    let mut next: Option<u64> = None;
    let mut messages = Vec::new();
    let mut sources = Vec::new();
    let mut spans = Vec::new();
    for turn in candidates {
        if turn.open {
            break;
        }
        let Some(member) = crate::compaction::turn_session_membership_in_txn(store, txn, &turn.id)?
        else {
            break;
        };
        if session.is_none() {
            let Some(order) = conversation_turn_order_in(store, txn, member, binding)? else {
                break;
            };
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
        let Some((span, words)) = pin(read, txn, turn)? else {
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
