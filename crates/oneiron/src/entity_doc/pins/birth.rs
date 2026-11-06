//! A MESSAGE quote anchored to the atomic text a document's local birth took
//! (FIX 8942). A document born here pins the body-anchored quotes it finds at
//! its birth frontier. A quote that reaches this vault later, by sync, was
//! still taken of that atomic text, so it gets the same pin when its hashes
//! prove the birth's text: cursors at the birth frontier, never at today's
//! edited span. A document carried from another machine, or rebuilt, names
//! no local birth, and a birth its history no longer retains proves nothing:
//! that quote stays as it reads now, and no text is guessed.
use super::*;

/// Pins `citation`'s body-anchored quote of `message`, the scalar span
/// `start..end`, at the frontier of the document's local birth, when no pin
/// of `citation` stands there yet and the birth text is the text the anchor
/// binds: its BLAKE3 hash is `body_hash` and the span's is `quote_hash`.
/// Whether it wrote the pin; a quote the birth does not prove writes none.
///
/// # Errors
///
/// Storage errors, and a head or document that does not decode.
pub(crate) fn pin_body_quote_at_birth_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    (message, citation): (EntityId, EntityId),
    (start, end): (usize, usize),
    (body_hash, quote_hash): ([u8; 32], [u8; 32]),
) -> Result<bool> {
    let key = HexPair(HexId(message), HexId(citation));
    if start >= end
        || !storage::has_record_head(store, txn, &message)?
        || ENTITY_DOC_PIN.contains(store, txn, &key)?
    {
        return Ok(false);
    }
    let head = storage::head(store, txn, &message)?;
    if head.field != crate::entity_doc::TextField::MapField("content".to_owned()) {
        return Ok(false);
    }
    let Some(birth) = head.birth_frontier.as_deref() else {
        return Ok(false);
    };
    let doc = storage::load(store, txn, &head)?;
    let Ok(born) = doc.fork(birth) else {
        return Ok(false);
    };
    let text = born.text();
    let quote: String = text.chars().skip(start).take(end - start).collect();
    if blake3::hash(text.as_bytes()).as_bytes() != &body_hash
        || quote.chars().count() != end - start
        || blake3::hash(quote.as_bytes()).as_bytes() != &quote_hash
    {
        return Ok(false);
    }
    let anchor = super::super::verbs::make_anchor(&born, message, start, end)?;
    // The pin names the birth's actor, its stamp token resolved (FIX 11964).
    let actor = doc.birth().actor.token_actor_in(store, txn)?;
    let pin = CitationPin {
        citation: citation.to_hex(),
        entity: message.to_hex(),
        document: head.document,
        anchor,
        actor,
    };
    ENTITY_DOC_PIN.put(store, txn, &key, &pin)?;
    Ok(true)
}
