//! The read-only text of one TURN as a consolidation branch sees it.
//!
//! A TURN that carries `txt|text` is read exactly as stored, even when that
//! string is empty. A TURN without it (a witnessed turn) takes its text from
//! its MESSAGE children: the visible rows of the TURN's own author bucket,
//! ordered by `(order, id)` and joined with exactly `"\n"`, never trimmed.
//! `system` interleave and hidden rows never enter it, and a non-system row of
//! another bucket refuses the turn instead of being read as its speaker.
//!
//! Every child the text depends on is read through the actor's ScopedRead in
//! the caller's snapshot and pinned at its exact logical version (plus its
//! document frontier when one exists). Later doors re-collect and compare
//! against that pin; they never reinterpret frozen offsets against new text.
//! An incomplete or unreadable child set refuses; a partial transcript is
//! never assembled.

use std::collections::BTreeMap;

use super::SwarmEvidenceRef;
use super::resources::document_version;
use super::support::invalid_consolidation;
use super::watermark::decode_turn_body;
use crate::claim::{PointRead, ScopedRead, ScopedReadActorKey, ScopedReadResult};
use crate::dreamer_runner::{DreamerTurnRole, dreamer_turn_role};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::gate::{WITNESS_AUTHOR_COMPANION, WITNESS_AUTHOR_SYSTEM, WITNESS_AUTHOR_USER};
use crate::llm::{Scope, ScopeResource};
use crate::ports::EdgeDirection;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};

type SourceRow = (u8, u64, Vec<u8>);
type BranchRead = (Vec<Option<SourceRow>>, BTreeMap<EntityId, TurnText>);

/// One MESSAGE child at the exact logical revision the projection read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MessagePin {
    id: EntityId,
    learned_at: u64,
    version: ScopeResource,
    frontier: Option<Vec<u8>>,
}

/// The frozen text of one TURN and every MESSAGE it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TurnText {
    text: Option<String>,
    /// `None` when the TURN carries its own text; otherwise the exact live
    /// MESSAGE child set, sorted by id (possibly empty).
    messages: Option<Vec<MessagePin>>,
}

impl TurnText {
    pub(super) fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// The exact MESSAGE versions this text depends on; none for inline text.
    pub(super) fn versions(&self) -> impl Iterator<Item = (EntityId, &ScopeResource)> {
        self.messages
            .iter()
            .flatten()
            .map(|pin| (pin.id, &pin.version))
    }

    /// A supplied scope is authority, not a request: it must already read
    /// every dependency. Returns the frozen text.
    pub(super) fn readable_text(&self, scope: &Scope) -> Result<Option<&str>> {
        if !self
            .versions()
            .all(|(_, version)| scope.allows_read(version))
        {
            return Err(invalid_consolidation("witnessed turn message read refused"));
        }
        Ok(self.text())
    }

    /// [`Self::readable_text`] plus a live re-collection in one fresh
    /// snapshot, so drift refuses here exactly as a changed TURN does.
    pub(super) fn recheck(
        &self,
        scope: &Scope,
        read: &ScopedRead<'_>,
        turn: &EntityId,
    ) -> Result<Option<String>> {
        let text = self.readable_text(scope)?.map(str::to_owned);
        if self.messages.is_some() {
            let txn = read.vault().store.env.read_txn()?;
            self.check_live_in(read, &txn, turn)?;
        }
        Ok(text)
    }

    /// Re-collect the same TURN under `read` in `txn` and refuse any change to
    /// the child set, a binding, a version, a frontier or the text. Inline
    /// text depends only on the TURN body, which every caller pins itself.
    pub(super) fn check_live_in(
        &self,
        read: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        turn: &EntityId,
    ) -> Result<()> {
        if self.messages.is_none() {
            return Ok(());
        }
        let Some((_, _, body)) = read
            .get_entities_parts_in_txn(txn, std::slice::from_ref(turn))?
            .pop()
            .flatten()
        else {
            return Err(invalid_consolidation("witnessed turn is not readable"));
        };
        if collect_in(read, txn, turn, &body, &mut 0)? != *self {
            return Err(invalid_consolidation("witnessed turn messages changed"));
        }
        Ok(())
    }
}

/// Collect one TURN's text in the caller's snapshot. Existing children the
/// reader may not see are added to `withheld` before the turn refuses.
pub(super) fn collect_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    turn_body: &[u8],
    withheld: &mut usize,
) -> Result<TurnText> {
    let vault = read.vault();
    let facts = decode_turn_body(turn_body);
    if facts.text.is_some() {
        return Ok(TurnText {
            text: facts.text,
            messages: None,
        });
    }
    let bucket = match dreamer_turn_role(
        facts.speaker.as_deref(),
        &vault.config.assistant_display_names,
    ) {
        DreamerTurnRole::User => WITNESS_AUTHOR_USER,
        DreamerTurnRole::Assistant => WITNESS_AUTHOR_COMPANION,
        // Branch admission refuses every other role; no child is its text.
        _ => {
            return Ok(TurnText {
                text: None,
                messages: None,
            });
        }
    };
    let parents = peers(
        vault,
        txn,
        turn,
        EdgeDirection::Out,
        EdgeKind::ChildOf,
        None,
    )?;
    let [conversation] = parents.as_slice() else {
        return Err(invalid_consolidation(
            "witnessed turn has no single conversation",
        ));
    };
    let mut ids = Vec::new();
    for id in peers(
        vault,
        txn,
        turn,
        EdgeDirection::In,
        EdgeKind::PartOf,
        Some(ENTITY_TYPE_MESSAGE),
    )? {
        // A deleted MESSAGE is no longer transcript; its removal still
        // changes this set, which every later door compares.
        if crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live() {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    let rows = read.get_entities_parts_in_txn(txn, &ids)?;
    let unreadable = rows.iter().filter(|row| row.is_none()).count();
    if unreadable != 0 {
        *withheld += unreadable;
        return Err(invalid_consolidation(
            "witnessed turn message is not readable",
        ));
    }
    let mut messages = Vec::with_capacity(ids.len());
    let mut children = Vec::with_capacity(ids.len());
    for (id, (entity_type, learned_at, body)) in ids.into_iter().zip(rows.into_iter().flatten()) {
        if entity_type != ENTITY_TYPE_MESSAGE
            || peers(vault, txn, &id, EdgeDirection::Out, EdgeKind::PartOf, None)? != [*turn]
            || peers(
                vault,
                txn,
                &id,
                EdgeDirection::Out,
                EdgeKind::BelongsTo,
                None,
            )? != [*conversation]
        {
            return Err(invalid_consolidation(
                "witnessed turn message binding changed",
            ));
        }
        #[cfg(feature = "sync")]
        let frontier = crate::entity_doc::source_frontier_in_txn(&vault.store, txn, &id)?;
        #[cfg(not(feature = "sync"))]
        let frontier = None;
        messages.push(MessagePin {
            id,
            learned_at,
            version: document_version(id, &body),
            frontier,
        });
        children.push((id, body));
    }
    Ok(TurnText {
        text: project(bucket, &children)?,
        messages: Some(messages),
    })
}

/// Branch sources read in ONE snapshot, together with the text of every
/// TURN among them. This is the unprepared branch's single read.
pub(super) fn read_sources(
    read: &ScopedRead<'_>,
    ids: &[EntityId],
) -> Result<ScopedReadResult<BranchRead>> {
    let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
    read.read_projected(&reads, None, |txn, rows| {
        let rows: Vec<_> = rows
            .into_iter()
            .map(|row| {
                row.and_then(|row| row.body.map(|body| (row.entity_type, row.learned_at, body)))
            })
            .collect();
        let mut texts = BTreeMap::new();
        for (id, row) in ids.iter().zip(&rows) {
            if let Some((ENTITY_TYPE_TURN, _, body)) = row {
                texts.insert(*id, collect_in(read, txn, id, body, &mut 0)?);
            }
        }
        Ok::<_, Error>((rows, texts))
    })
}

/// The projected text of one stored TURN in a caller's transaction, read as
/// `reader`. The attachment door calls it after the branch fence proved the
/// dependency set unchanged in this same transaction.
pub(crate) fn live_turn_text_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: WriteActor,
    turn: &EntityId,
    turn_body: &[u8],
) -> Result<Option<String>> {
    let read = vault.scoped_read(reader_key(reader)?);
    Ok(collect_in(&read, txn, turn, turn_body, &mut 0)?.text)
}

/// The text of one TURN for the Dreamer's read-only side doors (gap scan,
/// retrieval shadow). Inline text keeps its existing reader; the MESSAGE
/// fallback reads as the Dreamer, in one snapshot.
pub(super) fn read_turn_text(vault: &Vault, id: &EntityId) -> Result<Option<String>> {
    let facts = super::watermark::read_turn_facts(vault, id)?;
    if facts.text.is_some() {
        return Ok(facts.text);
    }
    let reader = WriteActor::new(
        crate::dreamer_runner::authority::dreamer_actor_id()?,
        EdgeActorClass::System,
    );
    let read = vault.scoped_read(reader_key(reader)?);
    let txn = vault.store.env.read_txn()?;
    // A TURN the Dreamer may not read has no text here, like an absent one.
    let Some((_, _, body)) = read
        .get_entities_parts_in_txn(&txn, std::slice::from_ref(id))?
        .pop()
        .flatten()
    else {
        return Ok(None);
    };
    Ok(collect_in(&read, &txn, id, &body, &mut 0)?.text)
}

/// A byte range is measured over the exact UTF-8 turn text the child saw in
/// the transcript (the projection above), never over MessagePack framing.
/// Whole TURNs keep their body-hash identity; CLAIM ids name the stored body.
pub(crate) fn cited_evidence_bytes(
    locator: SwarmEvidenceRef,
    body: &[u8],
    text: Option<&str>,
) -> Result<Vec<u8>> {
    let Some((start, end)) = locator.byte_range else {
        return Ok(body.to_vec());
    };
    let text = text.ok_or_else(|| invalid_consolidation("cited turn has no text"))?;
    if start >= end {
        return Err(invalid_consolidation("empty evidence byte range"));
    }
    let bytes = text
        .as_bytes()
        .get(start..end)
        .ok_or_else(|| invalid_consolidation("invalid evidence byte range"))?;
    std::str::from_utf8(bytes)
        .map_err(|_| invalid_consolidation("evidence range splits UTF-8 text"))?;
    Ok(bytes.to_vec())
}

/// The pure projection over already-read children. `bucket` is the TURN's
/// own MESSAGE author string.
pub(super) fn project(bucket: &str, children: &[(EntityId, Vec<u8>)]) -> Result<Option<String>> {
    let mut visible = Vec::new();
    for (id, body) in children {
        let message = decode_message(body)
            .ok_or_else(|| invalid_consolidation("witnessed message body is malformed"))?;
        if message.author == WITNESS_AUTHOR_SYSTEM {
            continue;
        }
        if message.author != bucket {
            return Err(invalid_consolidation("witnessed turn mixes author buckets"));
        }
        if message.is_visible {
            visible.push((message.order, *id, message.content));
        }
    }
    if visible.is_empty() {
        return Ok(None);
    }
    visible.sort_unstable_by_key(|(order, id, _)| (*order, *id));
    let lines: Vec<_> = visible.into_iter().map(|(_, _, content)| content).collect();
    Ok(Some(lines.join("\n")))
}

struct MessageText {
    author: String,
    content: String,
    is_visible: bool,
    order: u64,
}

/// Strict reader of the four fields the projection uses. The logical body of
/// a document-backed row carries `content` last, so key order is not checked;
/// a duplicate, missing or mistyped field is malformed.
fn decode_message(body: &[u8]) -> Option<MessageText> {
    let mut cursor = body;
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    if !cursor.is_empty() {
        return None;
    }
    let (mut author, mut content, mut is_visible, mut order) = (None, None, None, None);
    for (key, value) in entries {
        let fresh = match key.as_str() {
            Some("author") => author.replace(value.as_str()?.to_owned()).is_none(),
            Some("content") => content.replace(value.as_str()?.to_owned()).is_none(),
            Some("is_visible") => is_visible.replace(value.as_bool()?).is_none(),
            Some("order") => order.replace(value.as_u64()?).is_none(),
            _ => true,
        };
        if !fresh {
            return None;
        }
    }
    Some(MessageText {
        author: author?,
        content: content?,
        is_visible: is_visible?,
        order: order?,
    })
}

fn peers(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    direction: EdgeDirection,
    kind: EdgeKind,
    peer_type: Option<u8>,
) -> Result<Vec<EntityId>> {
    vault
        .filtered_edge_peers(
            txn,
            direction,
            id,
            kind,
            peer_type,
            "witnessed turn message scan",
        )
        .map_err(|error| match error {
            Error::IndexOverflow(_) => {
                invalid_consolidation("witnessed turn message graph limit exceeded")
            }
            error => error,
        })
}

fn reader_key(reader: WriteActor) -> Result<ScopedReadActorKey> {
    ScopedReadActorKey::with_actor_class(
        reader.entity_ref().to_hex(),
        reader.actor_class().gate_actor_class(),
    )
    .ok_or_else(|| invalid_consolidation("invalid turn text reader"))
}
