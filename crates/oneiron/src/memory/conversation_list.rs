//! The conversation list, read as the bound actor (ARCH-0006a, DEC-0005).
//!
//! The type index names the conversations; every row the list returns, and
//! every turn and message a row's preview quotes, comes through the actor's
//! read lane, the one recall and the transcript read on. A conversation, turn
//! or message the actor may not read never shows, nor an erased or archived
//! one. The receipt counts each listed conversation the reader may not read,
//! and every listed one is read whatever the page asks, so the count never
//! says where a hidden conversation falls. A preview's reads narrow the
//! receipt but add no count: a count of a conversation's hidden turns or
//! messages would say what that conversation holds.

use super::read_lane::fold_receipt;
use super::*;

use crate::claim::{
    ClaimReadStatus, PointRead, ReadRow, ScopedRead, ScopedReadReceipt, ScopedReadResult,
};
use crate::conversation::{
    ConversationBody, ConversationKind, LatestMessage, PreviewCandidates, snippet, turn_text,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::ports::{EntityStoreRead, TombstoneStore};
use crate::registry::ENTITY_TYPE_CONVERSATION;

/// Conversations read through the lane at a time.
const LIST_CHUNK: usize = 256;

/// Turns, or their sessions, a preview reads through the lane at a time. It
/// reads every turn it looks at before it orders any.
const PREVIEW_TURNS_PER_READ: usize = 64;

/// Rows of one turn, the turn and then its messages, a preview reads through
/// the lane at a time; only the latest message's text is kept between reads.
const PREVIEW_ROWS_PER_READ: usize = 256;

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

/// One walk of the whole list.
struct ListWalk {
    /// The page: the first `limit` rows after the cursor the reader may read.
    rows: Vec<ReadRow>,
    /// The page's last row, set only when a row the reader may read follows.
    next: Option<EntityId>,
    /// How many listed conversations the reader may read in all.
    total: u64,
    /// The receipt of every conversation read.
    receipt: Option<ScopedReadReceipt>,
}

impl Memory<'_> {
    /// Lists up to `limit` conversations after `after` that the bound actor
    /// may read, each with its preview, and with `count` how many it may read
    /// in all. The receipt counts each existing conversation the list
    /// withheld, every listed one and not only this page's.
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
        let ListWalk {
            rows,
            next,
            total,
            mut receipt,
        } = self.listed(&lane, filter, after, limit)?;
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
                total: count.then_some(total),
            },
            receipt,
        })
    }

    /// Reads every listed conversation through the lane, from the first.
    /// The whole list is read whatever the page and the count ask, so what
    /// the receipt withholds says nothing about where a hidden conversation
    /// falls beside the page or the cursor.
    fn listed(
        &self,
        lane: &ScopedRead<'_>,
        filter: ConversationListFilter<'_>,
        after: Option<&EntityId>,
        limit: usize,
    ) -> MemoryResult<ListWalk> {
        let mut rows: Vec<ReadRow> = Vec::new();
        let mut next = None;
        let mut total = 0_u64;
        let mut receipt = None;
        let mut cursor = None;
        loop {
            let (ids, more) = self.listed_ids(cursor.as_ref(), LIST_CHUNK)?;
            for row in self
                .read_conversations(lane, filter, &ids, &mut receipt)?
                .into_iter()
                .flatten()
            {
                total = total.saturating_add(1);
                if after.is_some_and(|after| row.id <= *after) {
                    continue;
                }
                if rows.len() < limit {
                    rows.push(row);
                } else if next.is_none() {
                    next = rows.last().map(|row| row.id);
                }
            }
            match ids.last() {
                Some(last) if more => cursor = Some(*last),
                _ => {
                    return Ok(ListWalk {
                        rows,
                        next,
                        total,
                        receipt,
                    });
                }
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

    /// `conversation`'s preview as the reader may read it. The turns it may
    /// look at are listed, the selected path or with no selected HEAD the
    /// ChildOf turns, and all read through the lane before any is ordered.
    /// With no selected HEAD the readable ones are ordered by their own
    /// learned time and proved by themselves, and a turn whose session the
    /// reader may not read is left out, so nothing hidden decides the
    /// preview. Then each readable turn, in order, is read again with its
    /// messages in bounded reads, until one has text.
    fn preview(
        &self,
        lane: &ScopedRead<'_>,
        conversation: &EntityId,
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Option<String>> {
        let candidates = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.vault.preview_candidates_in(&txn, conversation)?
        };
        let order: Vec<EntityId> = match candidates {
            PreviewCandidates::Unresolved => return Ok(None),
            PreviewCandidates::Path(turns) => self
                .admitted(lane, &turns, receipt)?
                .into_iter()
                .map(|(_, id)| id)
                .collect(),
            PreviewCandidates::ChildOf(turns) => {
                let readable = self.admitted(lane, &turns, receipt)?;
                drop(turns);
                let readable = self.in_readable_sessions(lane, readable, receipt)?;
                match self.vault.readable_childof_order(conversation, readable)? {
                    Some(order) => order,
                    None => return Ok(None),
                }
            }
        };
        for turn in order {
            let messages = {
                let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
                self.vault.turn_message_ids_in(&txn, &turn)?
            };
            let mut rows = std::iter::once(turn).chain(messages).peekable();
            let (mut own, mut latest) = (None, LatestMessage::default());
            while rows.peek().is_some() {
                let reads: Vec<_> = rows
                    .by_ref()
                    .take(PREVIEW_ROWS_PER_READ)
                    .map(PointRead::id)
                    .collect();
                let read = lane.read(&reads, None)?;
                fold_scope(receipt, read.receipt);
                for row in read.value.into_iter().flatten() {
                    let Some(body) = row.body.as_deref() else {
                        continue;
                    };
                    if row.id == turn {
                        own = turn_text(body);
                    } else {
                        latest.offer(row.id, body);
                    }
                }
            }
            if let Some(text) = latest.text().or(own) {
                return Ok(Some(snippet(&text)));
            }
        }
        Ok(None)
    }

    /// The rows of `ids` the lane admits, in order, each as its learned time
    /// and id, read a chunk at a time.
    fn admitted(
        &self,
        lane: &ScopedRead<'_>,
        ids: &[EntityId],
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Vec<(u64, EntityId)>> {
        let mut admitted = Vec::new();
        for chunk in ids.chunks(PREVIEW_TURNS_PER_READ) {
            let reads: Vec<_> = chunk.iter().copied().map(PointRead::id).collect();
            let read = lane.read(&reads, None)?;
            fold_scope(receipt, read.receipt);
            admitted.extend(
                read.value
                    .into_iter()
                    .flatten()
                    .filter(|row| row.body.is_some())
                    .map(|row| (row.learned_at, row.id)),
            );
        }
        Ok(admitted)
    }

    /// The `turns` whose session, where they sit in one, the lane admits. A
    /// session's body and edges decide whether its turns may be previewed,
    /// so a turn whose session a reader other than the owner may not read is
    /// left out rather than judged by what it may not read.
    fn in_readable_sessions(
        &self,
        lane: &ScopedRead<'_>,
        turns: Vec<(u64, EntityId)>,
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Vec<(u64, EntityId)>> {
        // The vault owner may inspect every session, a retained shell too, as
        // its own preview does: the proof judges each one.
        if self.inspects_every_session(lane)? {
            return Ok(turns);
        }
        let sessions = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            turns
                .iter()
                .map(|(_, turn)| {
                    crate::compaction::turn_session_membership_in_txn(&self.vault.store, &txn, turn)
                })
                .collect::<crate::error::Result<Vec<_>>>()?
        };
        let mut asked: Vec<EntityId> = sessions.iter().flatten().copied().collect();
        asked.sort_unstable();
        asked.dedup();
        let readable: Vec<EntityId> = self
            .admitted(lane, &asked, receipt)?
            .into_iter()
            .map(|(_, id)| id)
            .collect();
        Ok(turns
            .into_iter()
            .zip(sessions)
            .filter(|(_, session)| {
                session.is_none_or(|session| readable.binary_search(&session).is_ok())
            })
            .map(|(turn, _)| turn)
            .collect())
    }

    /// Whether the reader is the vault owner reading all of its vault: as
    /// itself, or with its own live, full owner-grade credential. A narrower
    /// credential, the owner's too, reads only what it grants.
    fn inspects_every_session(&self, lane: &ScopedRead<'_>) -> MemoryResult<bool> {
        if lane.actor_key().vault_owner_ref().is_some() {
            return Ok(true);
        }
        let Some(proof) = &self.read_proof else {
            return Ok(false);
        };
        if !proof.is_full_vault_owner_grade()
            || proof.claims().holder_ref != self.actor.to_hex()
            || proof.claims().actor_class.as_deref()
                != Some(crate::EdgeActorClass::Human.gate_actor_class())
        {
            return Ok(false);
        }
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        Ok(self.vault.capability_slip_is_live_in_txn(&txn, proof)?
            && self.is_vault_owner_in_txn(&txn)?)
    }
}

/// Folds a preview read's narrowing into the list's receipt without its
/// count, nor the row axis derived from that count: either would say what a
/// listed conversation's turns and messages hold.
fn fold_scope(receipt: &mut Option<ScopedReadReceipt>, mut read: ScopedReadReceipt) {
    read.suppressed_count = 0;
    read.narrowed_axes.retain(|axis| axis != "row_authority");
    read.record_axes();
    fold_receipt(receipt, read);
}

#[cfg(test)]
mod tests;
