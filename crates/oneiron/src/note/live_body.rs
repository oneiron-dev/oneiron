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
    let note = super::decode_note_body(body)?;
    #[cfg(feature = "sync")]
    if let Some(snapshot) = store
        .sync_state
        .get(txn, &super::document_store::key(*id))?
    {
        let mut note = note;
        let doc = super::document::NoteDocument::load(*id, &snapshot)?;
        note.markdown = doc.view()?.markdown;
        return super::encode_note_body(&note).map(Cow::Owned);
    }
    #[cfg(not(feature = "sync"))]
    let _ = (store, txn, id, note);
    Ok(Cow::Borrowed(body))
}
