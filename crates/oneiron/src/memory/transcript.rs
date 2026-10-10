//! One conversation's transcript, read as the bound actor: its turns in order,
//! each with the messages it holds that the actor may read.
//!
//! Every row comes through the actor's read lane, the one recall reads on, so
//! the transcript shows exactly the turns and messages the actor may read:
//! a message outside its disclosure, an erased one or an archived one never
//! comes back. Turns are ordered by when they occurred and then by id, the
//! order a room's adoption of the DAG gives its legacy turns; messages by
//! their order inside the turn.

use serde::Serialize;

use super::read_lane::ReadTargetSlot;
use super::*;

use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadReceipt, ScopedReadResult};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::ReadMode;

/// The most turns one transcript page returns.
pub const MAX_TRANSCRIPT_PAGE_TURNS: usize = 200;

/// How many times a page is listed and read before a conversation whose turns
/// keep moving in time is refused.
const TRANSCRIPT_READ_ATTEMPTS: usize = 3;

/// One page of a conversation's transcript.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TranscriptPage {
    /// 32-hex conversation id.
    pub conversation: String,
    /// Turns in order, each with at least one message the reader may read.
    pub turns: Vec<TranscriptTurn>,
    /// The cursor the next page starts after; `None` on the last page.
    pub next: Option<String>,
}

/// One turn of a transcript.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TranscriptTurn {
    /// 32-hex turn id.
    pub id: String,
    /// Occurred interval start (Unix seconds).
    pub occurred_start: u64,
    /// Occurred interval end (Unix seconds).
    pub occurred_end: u64,
    /// The turn's visible messages the reader may read, in order.
    pub messages: Vec<TranscriptMessage>,
}

/// One message of a transcript turn.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TranscriptMessage {
    /// 32-hex message id.
    pub id: String,
    /// The short ref recall cites the message by, when it has one.
    pub short_id: Option<String>,
    /// Who wrote it: `user`, `companion` or `system`.
    pub role: String,
    /// The message type its writer gave it.
    pub message_type: Option<String>,
    /// When it occurred (Unix seconds).
    pub occurred: u64,
    /// What it says.
    pub text: String,
    /// The metadata its writer gave it (an imported message's provenance).
    pub metadata: Option<serde_json::Value>,
}

/// Where a transcript page starts: after the turn with this time and id.
type TurnKey = (u64, EntityId);

fn cursor(key: &TurnKey) -> String {
    format!("{}:{}", key.0, key.1.to_hex())
}

fn parse_cursor(cursor: &str) -> MemoryResult<TurnKey> {
    cursor
        .split_once(':')
        .and_then(|(at, id)| Some((at.parse().ok()?, EntityId::from_hex(id).ok()?)))
        .ok_or_else(|| {
            MemoryError::bad_request_with(
                "invalid transcript cursor",
                &["Pass back the `next` value of the previous page."],
            )
        })
}

fn sort_key(key: &TurnKey) -> (u64, [u8; 16]) {
    (key.0, *key.1.as_bytes())
}

/// A readable MESSAGE view as a transcript message; `None` for one that is
/// hidden or holds no text.
fn transcript_message(view: &EntityView) -> Option<(u64, TranscriptMessage)> {
    let body = view.body.as_ref()?;
    let field = |name: &str| body.get(name).and_then(serde_json::Value::as_str);
    let text = field("content").unwrap_or_default();
    if body.get("is_visible").and_then(serde_json::Value::as_bool) != Some(true) || text.is_empty()
    {
        return None;
    }
    let order = body
        .get("order")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    Some((
        order,
        TranscriptMessage {
            id: view.id_hex.clone(),
            short_id: view.short_ref.clone(),
            role: field("author").unwrap_or("system").to_owned(),
            message_type: field("type").map(str::to_owned),
            occurred: view.occurred_start,
            text: text.to_owned(),
            metadata: body
                .get("metadata")
                .filter(|value| !value.is_null())
                .cloned(),
        },
    ))
}

impl Memory<'_> {
    /// Reads one page of `conversation`'s transcript as the bound actor: up
    /// to `limit` turns (at most [`MAX_TRANSCRIPT_PAGE_TURNS`]) after the
    /// `after` cursor, each with its visible messages the actor may read. A
    /// turn the actor may not read, or with no such message, is left out.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` when the actor may not read the conversation or it is not
    /// one; `BAD_REQUEST` for a zero limit or a cursor this read did not give;
    /// `INVALID_STATE` when the conversation's turns kept moving in time
    /// while the page was read.
    pub fn conversation_transcript(
        &self,
        conversation: &EntityId,
        after: Option<&str>,
        limit: usize,
    ) -> MemoryResult<ScopedReadResult<TranscriptPage>> {
        self.conversation_transcript_listed(conversation, after, limit, || {})
    }

    /// [`Self::conversation_transcript`], running `listed` after each listing
    /// of the turns and before they are read: a test seam for a write between
    /// the two. Production callers pass an empty callback.
    pub(super) fn conversation_transcript_listed(
        &self,
        conversation: &EntityId,
        after: Option<&str>,
        limit: usize,
        mut listed: impl FnMut(),
    ) -> MemoryResult<ScopedReadResult<TranscriptPage>> {
        if limit == 0 {
            return Err(MemoryError::bad_request(
                "transcript limit must be at least 1",
            ));
        }
        let limit = limit.min(MAX_TRANSCRIPT_PAGE_TURNS);
        let after = after.map(parse_cursor).transpose()?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let ScopedReadResult {
            value: row,
            receipt,
        } = lane.read(&[PointRead::id(*conversation)], None)?.single();
        if row.is_none_or(|row| row.entity_type != ENTITY_TYPE_CONVERSATION || row.body.is_none()) {
            return Err(MemoryError::not_found("conversation not found").with_read_receipt(receipt));
        }
        // The turns are listed, then read through the lane. A listed turn
        // whose time moved in between is listed again where it now is, so a
        // page stays in order, its cursor names a time it served, and no turn
        // is passed over.
        let mut read = receipt.clone();
        for _ in 0..TRANSCRIPT_READ_ATTEMPTS {
            let turns = self.transcript_turns(conversation, after)?;
            listed();
            read = receipt.clone();
            if let Some((turns, next)) = self.transcript_page(&lane, &turns, limit, &mut read)? {
                return Ok(ScopedReadResult {
                    value: TranscriptPage {
                        conversation: conversation.to_hex(),
                        turns,
                        next,
                    },
                    receipt: read,
                });
            }
        }
        // The refusal says what the last attempt's reads withheld.
        Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the conversation's turns kept moving while the page was read",
            &["Read the page again."],
        )
        .with_read_receipt(read))
    }

    /// Up to `limit` readable turns of `turns`, in order, and the cursor of
    /// the page after them; `None` when a listed turn's time no longer is
    /// what the listing saw. `receipt` takes each read's narrowing.
    fn transcript_page(
        &self,
        lane: &ScopedRead<'_>,
        turns: &[TurnKey],
        limit: usize,
        receipt: &mut ScopedReadReceipt,
    ) -> MemoryResult<Option<(Vec<TranscriptTurn>, Option<String>)>> {
        let mut page = Vec::new();
        let mut last = None;
        for chunk in turns.chunks(limit) {
            let members = self.transcript_members(chunk)?;
            let targets: Vec<ReadTargetSlot> = chunk
                .iter()
                .map(|(_, turn)| turn)
                .chain(members.iter().flatten())
                .map(|id| Some((*id, ReadMode::Live)))
                .collect();
            let ScopedReadResult {
                value: views,
                receipt: read,
            } = self.read_views(lane, &targets)?;
            receipt.restrict_with(&read);
            let (turn_views, mut message_views) = views.split_at(chunk.len());
            for ((key, ids), turn_view) in chunk.iter().zip(&members).zip(turn_views) {
                let (own, rest) = message_views.split_at(ids.len());
                message_views = rest;
                let Some(turn) = turn_view else {
                    continue;
                };
                if turn.occurred_start != key.0 {
                    return Ok(None);
                }
                let mut messages: Vec<_> = own
                    .iter()
                    .flatten()
                    .filter_map(transcript_message)
                    .collect();
                if messages.is_empty() {
                    continue;
                }
                if page.len() == limit {
                    return Ok(Some((page, last.as_ref().map(cursor))));
                }
                messages.sort_by(|(left, a), (right, b)| left.cmp(right).then(a.id.cmp(&b.id)));
                page.push(TranscriptTurn {
                    id: turn.id_hex.clone(),
                    occurred_start: turn.occurred_start,
                    occurred_end: turn.occurred_end,
                    messages: messages.into_iter().map(|(_, message)| message).collect(),
                });
                last = Some(*key);
            }
        }
        Ok(Some((page, None)))
    }

    /// The conversation's turns after `after`, in transcript order, each by
    /// the time it occurred. Only row headers are read here; every row the
    /// transcript returns is read again through the lane.
    fn transcript_turns(
        &self,
        conversation: &EntityId,
        after: Option<TurnKey>,
    ) -> MemoryResult<Vec<TurnKey>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let mut turns = Vec::new();
        for (id, header) in self.sources_in(&txn, conversation, EdgeKind::ChildOf)? {
            if header.entity_type == ENTITY_TYPE_TURN {
                turns.push((header.occurred_start, id));
            }
        }
        turns.sort_by_key(sort_key);
        if let Some(after) = after {
            turns.retain(|key| sort_key(key) > sort_key(&after));
        }
        Ok(turns)
    }

    /// Each turn's MESSAGE ids, read again through the lane by the caller.
    fn transcript_members(&self, turns: &[TurnKey]) -> MemoryResult<Vec<Vec<EntityId>>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        turns
            .iter()
            .map(|(_, turn)| {
                Ok(self
                    .sources_in(&txn, turn, EdgeKind::PartOf)?
                    .into_iter()
                    .filter(|(_, header)| header.entity_type == ENTITY_TYPE_MESSAGE)
                    .map(|(id, _)| id)
                    .collect())
            })
            .collect()
    }

    /// Every row with a `kind` edge to `target`, with its header. The whole
    /// adjacency is walked: rows this reader may not read must not change
    /// what it gets, so no cap on them may end the read.
    fn sources_in(
        &self,
        txn: &heed::RoTxn<'_>,
        target: &EntityId,
        kind: EdgeKind,
    ) -> MemoryResult<Vec<(EntityId, EntityMetadataHeader)>> {
        let mut rows = Vec::new();
        for edge in self
            .vault
            .store
            .port_edges(txn, target, EdgeDirection::In, Some(kind), None)?
        {
            let id = edge?.target;
            let raw = self
                .vault
                .store
                .entities
                .get(txn, id.as_bytes())
                .map_err(Error::from)?;
            if let Some(header) = raw.as_deref().and_then(EntityMetadataHeader::parse) {
                rows.push((id, header));
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests;
