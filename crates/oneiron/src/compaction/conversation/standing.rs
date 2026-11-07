//! Whether a landed conversation summary stands for a reader now: the one
//! reader a chat log ([`super::read_chat_log`]) and a folded turn's board
//! history (FIX 5038) both use. A summary stands while every pinned turn of
//! its evidence reads, as the reader in one snapshot, to the fingerprint its
//! landing pinned, and its own words pass the reader's read and its sources'
//! disclosure fence. One that misses any of that stands for nothing: its
//! turns stay raw in a log, and their boards stay refused in history.

use super::ConversationTurnSpan;
use super::storage::{ConversationLandingReceipt, conversation_receipts_in};
use crate::claim::ScopedRead;
use crate::compaction::decode_epoch_summary_body;
use crate::compaction::self_writer::hex32;
use crate::dreamer_consolidation::conversation_span_text_in;
use crate::store::conversation_span::ConversationSpanRead;
use crate::{EntityId, Result};

/// Whether every pinned turn of a summary's evidence reads, as `read` in
/// `txn`, to the fingerprint its landing pinned. A turn the reader may not
/// read now, or one that reads other words, rows, authors or stream state
/// than it was cut from, keeps the summary out.
fn evidence_reads_as_pinned(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    spans: &[ConversationTurnSpan],
) -> Result<bool> {
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
) -> Result<Option<String>> {
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

/// The words `receipt`'s summary stands with for `read` in `txn`: `None`
/// when it names no evidence, its evidence does not read to its pins, or
/// its words do not stand.
pub(super) fn standing_words_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    receipt: &ConversationLandingReceipt,
) -> Result<Option<String>> {
    let Some(evidence) = receipt.evidence() else {
        return Ok(None);
    };
    if evidence.turns.is_empty() || !evidence_reads_as_pinned(read, txn, &evidence.turns)? {
        return Ok(None);
    }
    summary_words(read, txn, &receipt.summary)
}

/// The epoch summary a conversation's compaction folded one turn into, as
/// its reader reads it now (FIX 5038).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FoldedTurnSummary {
    pub(crate) summary: EntityId,
    /// The epoch's lineage: the conversation's turns within the SESSION.
    pub(crate) session: EntityId,
    pub(crate) conversation: EntityId,
    pub(crate) epoch: u64,
    pub(crate) turn_start: u64,
    pub(crate) turn_end: u64,
    pub(crate) text: String,
}

/// The standing summary whose landing folded `turn`, read as `read` in
/// `txn` (FIX 5038): the one receipt of `turn`'s conversation whose evidence
/// names `turn`, while it stands for `read`. `None` when no receipt names
/// it, more than one does, or the one that does stands for nothing now: the
/// exact board stays refused.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn folded_turn_summary_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<FoldedTurnSummary>> {
    let store = &read.vault().store;
    let Ok(conversation) = crate::conversation_dag::conversation_of(store, txn, turn) else {
        return Ok(None);
    };
    let mut covering = conversation_receipts_in(store, txn, conversation)?
        .into_iter()
        .filter(|receipt| {
            receipt
                .evidence()
                .is_some_and(|evidence| evidence.turns.iter().any(|span| span.turn == *turn))
        });
    let (Some(receipt), None) = (covering.next(), covering.next()) else {
        return Ok(None);
    };
    let Some(text) = standing_words_in(read, txn, &receipt)? else {
        return Ok(None);
    };
    Ok(Some(FoldedTurnSummary {
        summary: receipt.summary,
        session: receipt.session,
        conversation: receipt.conversation,
        epoch: receipt.epoch,
        turn_start: receipt.turn_start,
        turn_end: receipt.turn_end,
        text,
    }))
}
