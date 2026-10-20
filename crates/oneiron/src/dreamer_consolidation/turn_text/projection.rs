//! The exact projection a consolidation branch read of one witnessed TURN
//! (FIX 5755).
//!
//! A range a round cited over a witnessed TURN's text is measured over the
//! words of the MESSAGEs that text joined, in the order the branch read them.
//! A retained alternative keeps that projection content-free: the ordered
//! MESSAGE ids, nothing of their words. When the TURN as the Dreamer reads
//! it now no longer binds such a citation, a Keep rebuilds exactly that
//! projection from the same MESSAGEs, read as the Dreamer in the caller's
//! snapshot under the same gates, bindings and finality a branch reads by.
//! A MESSAGE gone, withheld, rebound, hidden, unfinished or of another
//! speaker refuses; it never reads fewer words.

use super::{MESSAGES_NOT_RESIDENT, MessagePin, TurnText, decode_message, message_reader, peers};
use crate::claim::ScopedRead;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_consolidation::watermark::decode_turn_body;
use crate::dreamer_runner::{DreamerTurnRole, dreamer_turn_role};
use crate::edge::EdgeKind;
use crate::gate::{WITNESS_AUTHOR_COMPANION, WITNESS_AUTHOR_SYSTEM, WITNESS_AUTHOR_USER};
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::{EntityId, Error, Result};

impl TurnText {
    /// The MESSAGEs this text joins, in projection order: what a retained
    /// alternative keeps of it, content-free. None for inline text.
    pub(in crate::dreamer_consolidation) fn projection(&self) -> Vec<EntityId> {
        self.layout.iter().map(|(id, _, _)| *id).collect()
    }
}

fn changed() -> Error {
    invalid_consolidation("the projection a retained citation was read from changed")
}

/// Rebuilds the text of `turn` from exactly the MESSAGEs of `projection`, in
/// that order and joined as a branch joins them, read as `read` in `txn`.
/// Each must still be live, readable, bound to this TURN and its one
/// conversation with its byline, of the TURN's own speaker, visible, final
/// and not words another speaker said in an import.
pub(in crate::dreamer_consolidation) fn rebuild_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    turn_body: &[u8],
    projection: &[EntityId],
) -> Result<TurnText> {
    let vault = read.vault();
    if projection.is_empty()
        || !crate::ports::body_readable_in_txn(
            &vault.store,
            txn,
            turn,
            turn_body,
            crate::ports::BodyStale::Withdrawn,
        )?
    {
        return Err(changed());
    }
    let facts = decode_turn_body(turn_body);
    if facts.text.is_some() {
        return Err(changed());
    }
    let bucket = match dreamer_turn_role(
        facts.speaker.as_deref(),
        &vault.config.assistant_display_names,
    ) {
        DreamerTurnRole::User => WITNESS_AUTHOR_USER,
        DreamerTurnRole::Assistant => WITNESS_AUTHOR_COMPANION,
        _ => return Err(changed()),
    };
    if crate::tagging::tagged_messages_absent_in_txn(&vault.store, txn, turn)? {
        return Err(invalid_consolidation(MESSAGES_NOT_RESIDENT));
    }
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
    let rows = message_reader(read)?.get_entities_parts_in_txn(txn, projection)?;
    let mut messages = Vec::with_capacity(projection.len());
    let mut text = String::new();
    let mut layout = Vec::with_capacity(projection.len());
    for (index, (id, row)) in projection.iter().zip(rows).enumerate() {
        let Some((entity_type, learned_at, body)) = row else {
            return Err(invalid_consolidation(
                "witnessed turn message is not readable",
            ));
        };
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live() {
            return Err(changed());
        }
        let message = decode_message(&body)
            .ok_or_else(|| invalid_consolidation("witnessed message body is malformed"))?;
        let out = |kind| peers(vault, txn, id, EdgeDirection::Out, kind, None);
        let mut authors = out(EdgeKind::AuthoredBy)?;
        authors.sort_unstable();
        let bylines = usize::from(message.author != WITNESS_AUTHOR_SYSTEM && !facts.imported);
        if entity_type != ENTITY_TYPE_MESSAGE
            || out(EdgeKind::PartOf)? != [*turn]
            || out(EdgeKind::BelongsTo)? != [*conversation]
            || authors.len() != bylines
        {
            return Err(invalid_consolidation(
                "witnessed turn message binding changed",
            ));
        }
        let words = !crate::memory::message_completion_in_txn(vault, txn, id)?.incomplete;
        if message.author != bucket
            || !message.is_visible
            || !words
            || (facts.imported && message.not_the_owners)
        {
            return Err(changed());
        }
        #[cfg(feature = "sync")]
        let frontier = crate::entity_doc::source_frontier_in_txn(&vault.store, txn, id)?;
        #[cfg(not(feature = "sync"))]
        let frontier = None;
        let stream = crate::memory::message_stream_finality_in_txn(vault, txn, id)?;
        messages.push(MessagePin {
            id: *id,
            learned_at,
            version: crate::dreamer_consolidation::resources::document_version(*id, &body),
            revision: crate::dreamer_consolidation::swarm_evidence_content_hash(&body),
            authors,
            frontier,
            stream,
        });
        if index != 0 {
            text.push('\n');
        }
        layout.push((*id, text.len(), message.content.len()));
        text.push_str(&message.content);
    }
    Ok(TurnText {
        text: Some(text),
        messages: Some(messages),
        layout,
    })
}
