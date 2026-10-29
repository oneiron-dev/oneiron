//! Body-anchored quotes that reach this vault after their MESSAGE's document
//! was born here (FIX 8942). A document's birth pins the body-anchored quotes
//! it finds at its birth frontier
//! ([`super::pin_body_quotes_at_message_birth_in_txn`]); a quote that arrives
//! later by sync, in a TURN row or a room's turn row, gets the same pin here
//! when its hashes prove the birth's text
//! ([`crate::entity_doc::pin_body_quote_at_birth_in_txn`]), so its strip
//! reads the quoted text rather than drifting. A quote the birth does not
//! prove keeps its body anchor and reads as it does now. Nothing here fails
//! the write it rides in, and no anchor is rewritten.
use super::{
    MESSAGE_REPLY_KEY, QuoteAnchor, field, message_fields, read_pointer, witness_turn_quotes,
};
use crate::EntityId;
use crate::store::ManifestDbs;
use rmpv::Value;
use std::collections::BTreeSet;

/// Pins each body-anchored quote of `anchors`, by its citer, at its
/// MESSAGE's local document birth. The MESSAGEs that gained a pin; a pin
/// that could not be written warns and leaves the quote as it was.
pub(crate) fn pin_arrived_body_quotes_in_txn(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    anchors: Vec<(EntityId, QuoteAnchor)>,
) -> BTreeSet<EntityId> {
    let mut pinned = BTreeSet::new();
    for (citation, anchor) in anchors {
        let QuoteAnchor::Body {
            message,
            body_hash,
            start,
            end,
            quote_hash,
        } = anchor
        else {
            continue;
        };
        let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
            continue;
        };
        match crate::entity_doc::pin_body_quote_at_birth_in_txn(
            store,
            txn,
            (message, citation),
            (start, end),
            (body_hash, quote_hash),
        ) {
            Ok(true) => {
                pinned.insert(message);
            }
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "an arrived quote was not pinned at its birth");
            }
        }
    }
    pinned
}

/// The quotes the TURN row `body` of `turn` keeps, by citer, as a birth
/// reads them: a typed record's reply pointer, cited by the TURN, or an
/// ordinary room TURN's quotes, by citing MESSAGE. A body that keeps none,
/// or does not decode, names none.
pub(crate) fn turn_body_quotes(turn: EntityId, body: &[u8]) -> Vec<(EntityId, QuoteAnchor)> {
    match super::super::topology::record_kind(body) {
        Ok(Some(_)) => read_pointer(body)
            .ok()
            .flatten()
            .map(|(_, anchor)| (turn, anchor))
            .into_iter()
            .collect(),
        Ok(None) => witness_turn_quotes(body)
            .unwrap_or_default()
            .into_iter()
            .map(|(citer, quote)| (citer, quote.anchor))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The quote a door-added MESSAGE's `body` keeps (FIX 11084): its metadata's
/// door-owned pointer with a quote, the quoted TURN and anchor. `None` for a
/// body that keeps none, or does not decode.
pub(crate) fn message_body_quotes(body: &[u8]) -> Option<(EntityId, QuoteAnchor)> {
    let fields = message_fields(body).ok()?;
    let Value::Map(metadata) = field(&fields, "metadata")? else {
        return None;
    };
    let pointer = field(metadata, MESSAGE_REPLY_KEY)?;
    let Value::Map(pointer) = pointer else {
        return None;
    };
    let quote = field(pointer, "quote")?;
    let record = field(pointer, "record")?.as_str()?;
    Some((
        EntityId::from_hex(record).ok()?,
        QuoteAnchor::from_value(quote).ok()?,
    ))
}
