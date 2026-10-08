//! Which stored records are embedded, and what the embedder receives for each.

use super::PendingEmbeddingPayload;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

/// The payload the embedding worker sends for a stored record, or `None` when
/// the record is not embedded at all.
///
/// [`embeddable_payload`] for every record but a TURN, whose text is not in
/// its own body: a TURN embeds its messages' text ([`turn_text_in_txn`]).
/// Every door that queues or leases embedding work asks this.
pub(crate) fn embeddable_payload_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<Option<PendingEmbeddingPayload>> {
    if entity_type == ENTITY_TYPE_TURN {
        return Ok(turn_text_in_txn(vault, txn, id)?.map(PendingEmbeddingPayload::TurnText));
    }
    Ok(embeddable_payload(entity_type, body))
}

/// A TURN's canonical text: its visible MESSAGE children's text in message
/// order, one per line, read as edited. `None` for a turn that is gone or
/// archived, or whose messages hold nothing to embed.
///
/// ARCH-0004 makes the turn, not the message, the embedding unit: a short
/// message ("ok", "thanks") embeds poorly alone, and the turn is the run of
/// messages one speaker sent before the other answered.
pub(crate) fn turn_text_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<String>> {
    readable_turn_text_in_txn(vault, txn, turn, |_| Ok(true))
}

/// [`turn_text_in_txn`] over only the messages `readable` admits: the turn as
/// one reader is shown it. A reader who may read a turn but not one of its
/// messages never reads that message's words through the turn.
pub(crate) fn readable_turn_text_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    mut readable: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<Option<String>> {
    let Some(messages) = crate::tagging::turn_messages_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    let mut lines = Vec::with_capacity(messages.len());
    for message in messages {
        if readable(&EntityId::from_hex(&message.id)?)? {
            lines.push(message.text);
        }
    }
    let text = lines.join("\n");
    Ok(has_content(&text).then_some(text))
}

/// The payload the embedding worker sends for a stored record whose text is
/// its own body, or `None` when the record is not embedded at all.
///
/// One rule for every door that queues or leases embedding work — the
/// embedding-space swap, cold attach and the worker — so no door queues work
/// the worker can only fail on:
/// - a CLAIM whose body decodes, except a lexical query hint: that record is
///   lexical-only by construction, the write door never marks it and the
///   vector door refuses it;
/// - an epoch SUMMARY, strictly decoded. An ordinary SUMMARY shares the type
///   byte and is not one;
/// - and of those, only a text with something in it. Whitespace and control
///   characters alone leave nothing to embed, and no provider can return a
///   truthful vector for them.
pub(crate) fn embeddable_payload(entity_type: u8, body: &[u8]) -> Option<PendingEmbeddingPayload> {
    match entity_type {
        crate::registry::ENTITY_TYPE_CLAIM => {
            let claim = crate::claim::decode_claim_body(body, true).ok()?;
            (claim.predicate != crate::claim::PREDICATE_LEXICAL_QUERY_HINT
                && has_content(&super::claim_text(&claim)))
            .then(|| PendingEmbeddingPayload::ClaimBody(body.to_vec()))
        }
        crate::registry::ENTITY_TYPE_SUMMARY => {
            let text = crate::compaction::decode_epoch_summary_body(body)
                .ok()?
                .text;
            has_content(&text).then_some(PendingEmbeddingPayload::SummaryText(text))
        }
        _ => None,
    }
}

/// What idle publication embeds for a text revision, or `None` when it has
/// nothing to embed and publishes with no vector.
///
/// A CLAIM by the rule above, so a claim never gets a vector at idle that the
/// worker would not give it. Never a MESSAGE or a TURN: a message is not
/// embedded (ARCH-0004), and a turn's text is its messages', which the worker
/// embeds once the publication marks the turn again. Any other record as its
/// text fields joined by newlines, all of them: one field with something in
/// it — a title beside an empty body — is enough.
pub(crate) fn indexed_payload(
    entity_type: u8,
    body: &[u8],
    fields: &[(String, String)],
) -> Option<PendingEmbeddingPayload> {
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        return embeddable_payload(entity_type, body);
    }
    if matches!(entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_TURN) {
        return None;
    }
    let text = fields
        .iter()
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    has_content(&text).then_some(PendingEmbeddingPayload::SummaryText(text))
}

fn has_content(text: &str) -> bool {
    text.chars().any(|c| !c.is_whitespace() && !c.is_control())
}
