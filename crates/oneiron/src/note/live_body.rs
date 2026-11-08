//! Live NOTE read projection: the stored core and its head document's text.

use std::borrow::Cow;

use crate::{EntityId, Result};

/// Project only after the caller has admitted the entity. The core row and
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
    let note = live_note_from_in_txn(base, content, txn, id, body)?;
    super::encode_note_body(&note).map(Cow::Owned)
}

/// The logical NOTE of the stored core `core`: that core and the text of the
/// NOTE's head document, read through `content` in the same transaction
/// (FIX 7783). The row holds no text, so there is no other copy to fall back
/// to: a head with no stored document is refused.
pub(crate) fn live_note_from_in_txn(
    base: &crate::store::Store,
    content: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    core: &[u8],
) -> Result<super::NoteBody> {
    super::ensure_citations_ready(base, txn, *id)?;
    let core = super::decode_note_core_in_txn(content, txn, core)?;
    let doc = super::storage::load_stored(content, txn, *id)?;
    let markdown = super::document::NoteDocument::from_loro(*id, doc)?
        .view()?
        .markdown;
    Ok(core.with_markdown(markdown))
}

/// The projection of a read that selected a retained revision (Indexed or
/// Pinned) of the row `body`: a NOTE's one row revision is its birth, so a
/// NOTE reads as its core and the text its document was born with, never
/// its head's text (FIX 7783). A NOTE whose document no longer holds its
/// birth version, or holds no document here, is served as its stored row.
/// Any other row is served as it is. The birth text is what the row held
/// before FIX 7783, so this read keeps the gates that row's read kept.
pub(crate) fn birth_body_from_in_txn<'b>(
    content: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &'b [u8],
) -> Result<Cow<'b, [u8]>> {
    if entity_type != crate::registry::ENTITY_TYPE_NOTE || body.is_empty() {
        return Ok(Cow::Borrowed(body));
    }
    let Ok(core) = super::decode_note_core_in_txn(content, txn, body) else {
        return Ok(Cow::Borrowed(body));
    };
    let Some(markdown) = super::storage::stored_in(content, txn, *id)?
        .and_then(|doc| super::document::birth_text(*id, &doc))
    else {
        return Ok(Cow::Borrowed(body));
    };
    super::encode_note_body(&core.with_markdown(markdown)).map(Cow::Owned)
}
