//! Reply strips by quoted MESSAGE over one selected thread chain, or, for a
//! room turn, over the room's own index of its threads (OF-460): each room
//! thread's quotes, unquoted replies among them, join its own strips.
//!
//! A strip hydrates from its pinned version, never the latest body and
//! never a copied MESSAGE. Missing, edited and erased targets follow the
//! [`super::ReplyStrip`] rules: a strip never shows replacement text as
//! the historical quotation, and an erased message shows none.

use super::graph::{conversation_of, edge_ids, invalid, require_type};
use super::quote::{
    QuoteAnchor, field, message_fields, owning_turn_in, read_pointer, scalar_slice,
};
use super::thread_projection::selected_thread_in_txn;
use crate::edge::EdgeKind;
use crate::entity_doc::CursorResolution;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::RoTxn;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const PAGE_LIMIT: usize = 256;

/// One page of a thread's quote replies, grouped by the MESSAGE they quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplyStripsRequest {
    /// Room (conversation) holding the thread.
    pub room_ref: String,
    /// Trunk record whose selected thread is read, as `Vault::thread` selects it.
    pub thread_ref: String,
    /// Last reply turn of a preceding page.
    #[serde(default)]
    pub after: Option<String>,
    /// Strips per page, 1..=256 (absent: 256).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// How a strip's quote stands against its message now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStripStatus {
    /// The message is still at the pinned version.
    Live,
    /// The message changed since the pin; the quoted span still reads the same.
    Edited,
    /// The span no longer maps, or this vault holds no pinned text for it.
    Drifted,
    /// The message has been erased; no text is shown.
    Redacted,
}

/// One reply quoting a span of the group's message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteReplyStrip {
    /// The replying TURN.
    pub reply_turn: String,
    /// The reply's first MESSAGE when it holds any the reader may read; a
    /// first-party append is its own record.
    pub reply_message: Option<String>,
    /// The anchor the strip resolves through: `<message>:<citation>` names a
    /// document citation pin, `<message>#<body hash>` an atomic message's
    /// immutable text by its BLAKE3 hash.
    pub pin_ref: String,
    /// The quoted text at the pinned version; `None` when redacted or not held.
    pub excerpt: Option<String>,
    pub status: QuoteStripStatus,
}

/// The strips quoting one MESSAGE, in chronological reply order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteReplyGroup {
    pub message_ref: String,
    pub strips: Vec<QuoteReplyStrip>,
}

/// Groups in order of their first strip on the page. A group may continue
/// on the next page under the same `message_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyStripsPage {
    pub groups: Vec<QuoteReplyGroup>,
    /// Explicit end marker: `None` means the thread has no further strip.
    pub next_after: Option<String>,
}

/// One quote reply on the selected chain, before the reader's clamp.
struct QuoteFact {
    reply: EntityId,
    reply_message: Option<EntityId>,
    /// The quoted message's TURN, the reply pointer's target.
    turn: EntityId,
    anchor: QuoteAnchor,
    /// The quoted message and its TURN are live rows, so the reader must be
    /// admitted to them; an erased one shows only its redaction.
    target_live: bool,
    /// When the reply was spoken: its room turn's time, or its TURN's
    /// valid-time start.
    at: u64,
}

/// A handle's quote replies and how they are read. `room` is `None` for a
/// DAG chain, read under the caller's own read; for a room turn it is the
/// thread its selection reads under, `Some(None)` for a trunk's every thread.
struct QuoteSelection {
    facts: Vec<QuoteFact>,
    room: Option<Option<EntityId>>,
}

/// Every quote reply `trunk` selects, in one snapshot. A DAG record's are
/// those on its selected chain, root-first. A room turn's are those of every
/// reply of every thread the room's index selects for it, with each native
/// DAG append on the chain that has no room row, by `(at, reply id)`.
fn quote_facts(vault: &Vault, room: EntityId, trunk: EntityId) -> Result<QuoteSelection> {
    let txn = vault.store.env.read_txn()?;
    if conversation_of(&vault.store, &txn, &trunk)? != room {
        return Err(invalid("thread is outside the room"));
    }
    let chain = selected_thread_in_txn(vault, &txn, trunk)?
        .map(|selected| selected.replies)
        .unwrap_or_default();
    let Some(indexed) =
        crate::workspace_roster::room_thread_turns_in_txn(vault, &txn, room, trunk)?
    else {
        let mut facts = Vec::new();
        for reply in chain {
            facts.extend(dag_fact_in(vault, &txn, reply)?);
        }
        return Ok(QuoteSelection { facts, room: None });
    };
    let mut facts = Vec::new();
    let mut selected = BTreeSet::new();
    for turn in &indexed.turns {
        let reply = EntityId::from_hex(&turn.turn_id)?;
        selected.insert(reply);
        // A trunk turn's quote is kept in its room row; a thread reply's in
        // its TURN's reply pointer.
        let pointer = match turn.quote {
            Some(quote) => Some((quote.target_turn, quote.anchor)),
            None => match live_entity_row_in_txn(&vault.store, &txn, &reply)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_TURN,
                    body,
                } => read_pointer(&body)?,
                _ => None,
            },
        };
        facts.extend(fact_in(vault, &txn, reply, pointer, turn.at)?);
    }
    // A native append lands no room row, so only the DAG chain holds it.
    for reply in chain {
        if !selected.contains(&reply)
            && crate::workspace_roster::replicated_turn_in(vault, &txn, reply)?.is_none()
        {
            facts.extend(dag_fact_in(vault, &txn, reply)?);
        }
    }
    facts.sort_by_key(|fact| (fact.at, fact.reply));
    Ok(QuoteSelection {
        facts,
        room: Some(indexed.root),
    })
}

/// [`fact_in`] for a DAG reply: its TURN's reply pointer, at its valid-time
/// start.
fn dag_fact_in(vault: &Vault, txn: &RoTxn<'_>, reply: EntityId) -> Result<Option<QuoteFact>> {
    let body = require_type(&vault.store, txn, &reply, ENTITY_TYPE_TURN)?;
    let at = vault
        .store
        .port_entity_record(txn, &reply)?
        .ok_or(Error::EntityNotFound)?
        .occurred
        .start;
    fact_in(vault, txn, reply, read_pointer(&body)?, at)
}

/// The quote fact of `reply`, whose quote `pointer` names: `None` when it
/// quotes nothing, or when its live target is no TURN its message is part of.
fn fact_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    reply: EntityId,
    pointer: Option<(EntityId, QuoteAnchor)>,
    at: u64,
) -> Result<Option<QuoteFact>> {
    let Some((turn, anchor)) = pointer else {
        return Ok(None);
    };
    let message = anchor.message();
    let target_live = live_entity_row_in_txn(&vault.store, txn, &message)?.is_live()
        && live_entity_row_in_txn(&vault.store, txn, &turn)?.is_live();
    // A live quote names the TURN its message is part of; a pointer that
    // does not is no quote of that turn.
    if target_live && owning_turn_in(&vault.store, txn, &message)? != turn {
        return Ok(None);
    }
    let mut messages = Vec::new();
    for child in edge_ids(
        &vault.store,
        txn,
        &reply,
        EdgeKind::PartOf,
        true,
        crate::limits::MAX_ANCESTOR_DEPTH,
    )? {
        if matches!(
            live_entity_row_in_txn(&vault.store, txn, &child)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_MESSAGE,
                ..
            }
        ) {
            messages.push(child);
        }
    }
    Ok(Some(QuoteFact {
        reply,
        reply_message: messages.into_iter().min(),
        turn,
        anchor,
        target_live,
        at,
    }))
}

/// The strip's status and pinned excerpt.
fn hydrate(vault: &Vault, anchor: &QuoteAnchor) -> Result<(QuoteStripStatus, Option<String>)> {
    let txn = vault.store.env.read_txn()?;
    let message = anchor.message();
    let row = live_entity_row_in_txn(&vault.store, &txn, &message)?;
    if matches!(row, LiveEntityRow::DeletedShell)
        || vault.local_hard_delete_marker_exists_in_txn(&txn, &message)?
    {
        return Ok((QuoteStripStatus::Redacted, None));
    }
    let body = match row {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE,
            body,
        } => body,
        LiveEntityRow::Live { .. } => return Err(invalid("quoted record is not a MESSAGE")),
        // Not received here yet: nothing to show, nothing erased.
        _ => return Ok((QuoteStripStatus::Drifted, None)),
    };
    match *anchor {
        QuoteAnchor::Document { message, citation } => {
            let Some(pin) = vault.message_quote_pin_in_txn(&txn, &message, &citation)? else {
                return Ok((QuoteStripStatus::Drifted, None));
            };
            drop(txn);
            // The pin's quote was proven against the pinned version.
            let excerpt = Some(pin.anchor.quote().to_owned());
            let status = if vault.entity_text_frontier(&message)? == pin.anchor.frontier() {
                QuoteStripStatus::Live
            } else {
                match vault.resolve_entity_text_cursor(&message, &pin.anchor)? {
                    CursorResolution::Live { .. } => QuoteStripStatus::Edited,
                    CursorResolution::Drifted { .. } => QuoteStripStatus::Drifted,
                }
            };
            Ok((status, excerpt))
        }
        QuoteAnchor::Body {
            body_hash,
            start,
            end,
            quote_hash,
            ..
        } => {
            // An atomic body is the pinned version until the message gains a
            // document; a hash-proven span reads the same text either way.
            let body = crate::entity_doc::resolve_record_body(&vault.store, &txn, &message, &body)?;
            let fields = message_fields(&body)?;
            let text = field(&fields, "content")
                .and_then(Value::as_str)
                .ok_or(Error::CorruptedIndex("message canonical content"))?;
            let span = (
                usize::try_from(start).map_err(|_| invalid("quote span overflow"))?,
                usize::try_from(end).map_err(|_| invalid("quote span overflow"))?,
            );
            let excerpt = scalar_slice(text, span.0, span.1)
                .filter(|quoted| blake3::hash(quoted.as_bytes()).as_bytes() == &quote_hash);
            let status = match (
                blake3::hash(text.as_bytes()).as_bytes() == &body_hash,
                &excerpt,
            ) {
                (true, Some(_)) => QuoteStripStatus::Live,
                (false, Some(_)) => QuoteStripStatus::Edited,
                (_, None) => QuoteStripStatus::Drifted,
            };
            Ok((status, excerpt))
        }
    }
}

impl Memory<'_> {
    /// One page of a thread's quote replies, grouped by the MESSAGE they
    /// quote, in chronological reply order on the selected chain. Every row
    /// passes the reader's own read lane (inside a room turn, the room's):
    /// the trunk, each reply, and each quoted message and its TURN while they
    /// are live. A withheld reply never fills a slot or becomes the cursor.
    /// A room turn's strips read its room's threads (OF-460) under the
    /// room's reader for a trunk's every thread, or one thread's own reader
    /// for that thread, as a room history read does.
    pub fn rooms_reply_strips(
        &self,
        request: &ReplyStripsRequest,
    ) -> MemoryResult<ReplyStripsPage> {
        let room = EntityId::from_hex(&request.room_ref)?;
        let trunk = EntityId::from_hex(&request.thread_ref)?;
        let after = request
            .after
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let limit = request.limit.unwrap_or(PAGE_LIMIT);
        if limit == 0 || limit > PAGE_LIMIT {
            return Err(MemoryError::bad_request_with(
                "reply strip limit must be 1..=256",
                &[],
            ));
        }
        if self.room_turn().is_some_and(|turn| turn.room != room) {
            return Err(MemoryError::bad_request_with(
                "room differs from the bound room turn",
                &[],
            ));
        }
        let QuoteSelection {
            facts,
            room: selection,
        } = quote_facts(self.vault(), room, trunk)?;
        let mut ids = BTreeSet::from([trunk]);
        for fact in &facts {
            ids.insert(fact.reply);
            ids.extend(fact.reply_message);
            if fact.target_live {
                ids.extend([fact.turn, fact.anchor.message()]);
            }
        }
        let ids: Vec<_> = ids.into_iter().collect();
        let reader = selection
            .map(|root| self.room_selection_reader(room, root))
            .transpose()?;
        let lane = match &reader {
            Some(reader) => reader
                .memory()
                .read_lane(crate::claim::ClaimReadStatus::Recorded)?,
            None => self.read_lane(crate::claim::ClaimReadStatus::Recorded)?,
        };
        let mut admitted = BTreeSet::new();
        for chunk in ids.chunks(128) {
            let reads: Vec<_> = chunk
                .iter()
                .copied()
                .map(crate::claim::PointRead::id)
                .collect();
            let rows = lane.read(&reads, None)?.value;
            admitted.extend(
                chunk
                    .iter()
                    .zip(rows)
                    .filter_map(|(id, row)| row.map(|_| *id)),
            );
        }
        if !admitted.contains(&trunk) {
            return Err(MemoryError::bad_request_with(
                "thread is outside the reader's scope",
                &[],
            ));
        }
        let facts: Vec<_> = facts
            .into_iter()
            .filter(|fact| {
                admitted.contains(&fact.reply)
                    && (!fact.target_live
                        || (admitted.contains(&fact.turn)
                            && admitted.contains(&fact.anchor.message())))
            })
            .collect();
        let start = match after {
            Some(after) => {
                facts
                    .iter()
                    .position(|fact| fact.reply == after)
                    .ok_or_else(|| {
                        MemoryError::bad_request_with(
                            "cursor is not a quote reply on this thread",
                            &[],
                        )
                    })?
                    + 1
            }
            None => 0,
        };
        let end = start.saturating_add(limit).min(facts.len());
        let mut groups: Vec<QuoteReplyGroup> = Vec::new();
        for fact in &facts[start..end] {
            let (status, excerpt) = hydrate(self.vault(), &fact.anchor)?;
            let strip = QuoteReplyStrip {
                reply_turn: fact.reply.to_hex(),
                reply_message: fact
                    .reply_message
                    .filter(|id| admitted.contains(id))
                    .map(|id| id.to_hex()),
                pin_ref: fact.anchor.reference(),
                excerpt,
                status,
            };
            let message_ref = fact.anchor.message().to_hex();
            match groups
                .iter_mut()
                .find(|group| group.message_ref == message_ref)
            {
                Some(group) => group.strips.push(strip),
                None => groups.push(QuoteReplyGroup {
                    message_ref,
                    strips: vec![strip],
                }),
            }
        }
        Ok(ReplyStripsPage {
            groups,
            next_after: (end < facts.len()).then(|| facts[end - 1].reply.to_hex()),
        })
    }
}
