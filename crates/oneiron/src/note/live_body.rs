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
    if entity_type != crate::registry::ENTITY_TYPE_NOTE || body.is_empty() {
        return Ok(Cow::Borrowed(body));
    }
    super::ensure_citations_ready(store, txn, *id)?;
    // A migrated record keeps the EntityDoc codec; its head is not a NOTE document.
    #[cfg(feature = "sync")]
    if crate::entity_doc::has_record_head(store, txn, id)? {
        return Ok(Cow::Borrowed(body));
    }
    let note = super::decode_note_body_in_txn(store, txn, body)?;
    let has_snapshot = store
        .sync_state
        .get(txn, &super::document_store::key(*id))?
        .is_some();
    let has_updates = store
        .sync_state
        .prefix_iter(txn, &format!("u:e:{}:", id.to_hex()))?
        .next()
        .transpose()?
        .is_some();
    if has_snapshot || has_updates {
        let doc = super::storage::load_seeded(store, txn, *id, || {
            Ok(super::document::NoteDocument::birth(
                *id,
                &note.markdown,
                &crate::WriteActor::new(note.author_ref, crate::EdgeActorClass::Agent),
            )?
            .doc)
        })?;
        let mut note = note;
        note.markdown = super::document::NoteDocument::from_loro(*id, doc)?
            .view()?
            .markdown;
        return super::encode_note_body(&note).map(Cow::Owned);
    }
    Ok(Cow::Borrowed(body))
}
