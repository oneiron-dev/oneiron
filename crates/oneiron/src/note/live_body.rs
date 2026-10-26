//! Live NOTE read projection without rewriting the immutable birth record.

use std::borrow::Cow;

use crate::{EntityId, Result};

/// Project only after the caller has admitted the entity. The birth row and
/// document are read under the same transaction; raw storage/sync readers do
/// not call this function and therefore cannot mirror a projection as truth.
pub(crate) fn live_body_in_txn<'b>(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &'b [u8],
) -> Result<Cow<'b, [u8]>> {
    live_body_from_in_txn(store, store, txn, id, entity_type, body)
}

/// [`live_body_in_txn`] with the NOTE's kind and document read through
/// `content`, the content the caller reads, a room's view included (FIX
/// 9763). The pending-erasure fence stays the vault's (`base`).
pub(crate) fn live_body_from_in_txn<'b>(
    base: &crate::store::Store,
    content: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &'b [u8],
) -> Result<Cow<'b, [u8]>> {
    if entity_type != crate::registry::ENTITY_TYPE_NOTE || body.is_empty() {
        return Ok(Cow::Borrowed(body));
    }
    super::ensure_citations_ready(base, txn, *id)?;
    // A migrated record keeps the EntityDoc codec; its head is not a NOTE document.
    #[cfg(feature = "sync")]
    if crate::entity_doc::has_record_head(content, txn, id)? {
        return Ok(Cow::Borrowed(body));
    }
    let note = super::decode_note_body_in_txn(content, txn, body)?;
    let slot = crate::ports::DocumentSlot::of(*id);
    if crate::ports::DocumentRowStore::port_document_present(content, txn, slot)? {
        let doc = super::storage::load_seeded(content, txn, *id, || {
            Ok(super::document::NoteDocument::birth_by(*id, &note.markdown, note.author_ref)?.doc)
        })?;
        let mut note = note;
        note.markdown = super::document::NoteDocument::from_loro(*id, doc)?
            .view()?
            .markdown;
        return super::encode_note_body(&note).map(Cow::Owned);
    }
    Ok(Cow::Borrowed(body))
}
