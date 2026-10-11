//! The conversation list, read as the bound actor (ARCH-0006a, DEC-0005).
//!
//! The type index names the conversations; every row the list returns, and
//! every turn and message a row's preview quotes, comes through the actor's
//! read lane, the one recall and the transcript read on. A conversation, turn
//! or message the actor may not read never shows, nor an erased or archived
//! one, and the receipt counts each existing row a read withheld.

use super::read_lane::fold_receipt;
use super::*;

use crate::claim::{
    ClaimReadStatus, PointRead, ReadRow, ScopedRead, ScopedReadReceipt, ScopedReadResult,
};
use crate::conversation::{ConversationBody, ConversationKind, LatestMessage, snippet, turn_text};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::ports::{EntityStoreRead, TombstoneStore};
use crate::registry::ENTITY_TYPE_CONVERSATION;

/// Conversations read through the lane at a time when the list counts them.
const COUNT_CHUNK: usize = 256;

/// Conversations read through the lane at a time while a page fills, however
/// few slots it has left, so rows the reader may not read cost one read per
/// chunk, never one each.
const PAGE_CHUNK: usize = 64;

/// Turns a preview reads through the lane at a time, the preferred first.
const PREVIEW_TURNS_PER_READ: usize = 4;

/// Messages of one turn a preview reads through the lane at a time; only the
/// latest one's text is kept between reads.
const PREVIEW_MESSAGES_PER_READ: usize = 256;

/// Which conversations a list names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConversationListFilter<'f> {
    /// Only conversations of this kind.
    pub kind: Option<ConversationKind>,
    /// Only conversations with this external id.
    pub external_id: Option<&'f str>,
}

impl ConversationListFilter<'_> {
    /// Whether the conversation body `body` is one this filter names. A body
    /// that does not decode is named only by the empty filter.
    fn names(&self, body: &[u8]) -> bool {
        if *self == Self::default() {
            return true;
        }
        ConversationBody::from_bytes(body).is_ok_and(|body| {
            self.kind.is_none_or(|kind| kind == body.kind)
                && self
                    .external_id
                    .is_none_or(|external| body.external_id.as_deref() == Some(external))
        })
    }
}

/// One conversation on a list page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationListRow {
    /// The conversation's row as the lane admitted it.
    pub row: ReadRow,
    /// The latest visible message of the conversation that the reader may
    /// read, clipped to 50 characters; for a turn with no such message, the
    /// turn's own text.
    pub last_message_snippet: Option<String>,
}

/// One page of the conversation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationListPage {
    /// The conversations the reader may read, in index order.
    pub rows: Vec<ConversationListRow>,
    /// The cursor the next page starts after, set only when another
    /// conversation the reader may read follows.
    pub next: Option<EntityId>,
    /// How many conversations the reader may read in all, when asked.
    pub total: Option<u64>,
}

impl Memory<'_> {
    /// Lists up to `limit` conversations after `after` that the bound actor
    /// may read, each with its preview, and with `count` how many it may read
    /// in all. The receipt counts each existing conversation, turn and message
    /// the reads withheld; with `count` it covers every listed conversation,
    /// not only this page's.
    ///
    /// # Errors
    ///
    /// A refused actor binding, or a failed store read.
    pub fn conversation_list(
        &self,
        filter: ConversationListFilter<'_>,
        after: Option<&EntityId>,
        limit: usize,
        count: bool,
    ) -> MemoryResult<ScopedReadResult<ConversationListPage>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let (rows, next, page_receipt) = self.listed_page(&lane, filter, after, limit)?;
        // The count reads every conversation the page reads, so its receipt
        // takes the page's place rather than counting those rows twice.
        let (total, mut receipt) = if count {
            let (total, receipt) = self.listed_total(&lane, filter)?;
            (Some(total), receipt)
        } else {
            (None, page_receipt)
        };
        let mut page = Vec::with_capacity(rows.len());
        for row in rows {
            let last_message_snippet = self.preview(&lane, &row.id, &mut receipt)?;
            page.push(ConversationListRow {
                row,
                last_message_snippet,
            });
        }
        let receipt = match receipt {
            Some(receipt) => receipt,
            None => lane.read_receipt(None, 0)?,
        };
        Ok(ScopedReadResult {
            value: ConversationListPage {
                rows: page,
                next,
                total,
            },
            receipt,
        })
    }

    /// The page's conversation rows, the cursor after them, and the receipt
    /// of their reads. The walk reads one row past the page: the next cursor
    /// is set only when a row the reader may read follows.
    fn listed_page(
        &self,
        lane: &ScopedRead<'_>,
        filter: ConversationListFilter<'_>,
        after: Option<&EntityId>,
        limit: usize,
    ) -> MemoryResult<(Vec<ReadRow>, Option<EntityId>, Option<ScopedReadReceipt>)> {
        let mut rows: Vec<ReadRow> = Vec::new();
        let mut receipt = None;
        if limit == 0 {
            return Ok((rows, None, receipt));
        }
        let mut cursor = after.copied();
        loop {
            let (ids, more) = self.listed_ids(cursor.as_ref(), PAGE_CHUNK)?;
            for row in self
                .read_conversations(lane, filter, &ids, &mut receipt)?
                .into_iter()
                .flatten()
            {
                if rows.len() == limit {
                    let next = rows.last().map(|row| row.id);
                    return Ok((rows, next, receipt));
                }
                rows.push(row);
            }
            match ids.last() {
                Some(last) if more => cursor = Some(*last),
                _ => return Ok((rows, None, receipt)),
            }
        }
    }

    /// How many listed conversations the reader may read, and the receipt of
    /// the reads that counted them.
    fn listed_total(
        &self,
        lane: &ScopedRead<'_>,
        filter: ConversationListFilter<'_>,
    ) -> MemoryResult<(u64, Option<ScopedReadReceipt>)> {
        let mut total = 0_u64;
        let mut receipt = None;
        let mut cursor = None;
        loop {
            let (ids, more) = self.listed_ids(cursor.as_ref(), COUNT_CHUNK)?;
            let read = self.read_conversations(lane, filter, &ids, &mut receipt)?;
            total = total.saturating_add(read.iter().flatten().count() as u64);
            match ids.last() {
                Some(last) if more => cursor = Some(*last),
                _ => return Ok((total, receipt)),
            }
        }
    }

    /// Up to `want` conversation ids after `after` in index order, without
    /// erased ones, and whether the walk stopped at `want`. Only the listing
    /// reads here, and no body: every row the list returns is read again
    /// through the lane, and the filter sees only rows the lane admitted.
    fn listed_ids(
        &self,
        after: Option<&EntityId>,
        want: usize,
    ) -> MemoryResult<(Vec<EntityId>, bool)> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let mut ids = Vec::new();
        for id in
            self.vault
                .port_entity_ids_by_type(&txn, ENTITY_TYPE_CONVERSATION, after.copied())?
        {
            let id = id?;
            if TombstoneStore::port_tombstone_is_deleted(self.vault, &txn, &id)? {
                continue;
            }
            ids.push(id);
            if ids.len() == want {
                return Ok((ids, true));
            }
        }
        Ok((ids, false))
    }

    /// Reads `ids` through the lane: each slot is the conversation's row with
    /// its body, or `None` for a row the reader may not read or the filter
    /// does not name. The filter reads only admitted bodies, so what the
    /// receipt withholds says nothing about a hidden row's fields.
    fn read_conversations(
        &self,
        lane: &ScopedRead<'_>,
        filter: ConversationListFilter<'_>,
        ids: &[EntityId],
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Vec<Option<ReadRow>>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let read = lane.read(&reads, None)?;
        fold_receipt(receipt, read.receipt);
        Ok(read
            .value
            .into_iter()
            .map(|row| {
                row.filter(|row| {
                    row.entity_type == ENTITY_TYPE_CONVERSATION
                        && row.body.as_deref().is_some_and(|body| filter.names(body))
                })
            })
            .collect())
    }

    /// `conversation`'s preview as the reader may read it. The turns a
    /// preview looks at are listed, then read through the lane a few at a
    /// time, the preferred first, each readable one's messages after it in
    /// bounded reads, until one has text. A turn the reader may not read
    /// shows none of its messages.
    fn preview(
        &self,
        lane: &ScopedRead<'_>,
        conversation: &EntityId,
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Option<String>> {
        let turns = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.vault.preview_turns_in(&txn, conversation)?
        };
        for chunk in turns.chunks(PREVIEW_TURNS_PER_READ) {
            let reads: Vec<_> = chunk.iter().copied().map(PointRead::id).collect();
            let read = lane.read(&reads, None)?;
            fold_receipt(receipt, read.receipt);
            for (turn, row) in chunk.iter().zip(read.value) {
                let Some(body) = row.and_then(|row| row.body) else {
                    continue;
                };
                let messages = {
                    let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
                    self.vault.turn_message_ids_in(&txn, turn)?
                };
                let mut latest = LatestMessage::default();
                for ids in messages.chunks(PREVIEW_MESSAGES_PER_READ) {
                    let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
                    let read = lane.read(&reads, None)?;
                    fold_receipt(receipt, read.receipt);
                    for row in read.value.into_iter().flatten() {
                        if let Some(body) = row.body.as_deref() {
                            latest.offer(row.id, body);
                        }
                    }
                }
                if let Some(text) = latest.text().or_else(|| turn_text(&body)) {
                    return Ok(Some(snippet(&text)));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
