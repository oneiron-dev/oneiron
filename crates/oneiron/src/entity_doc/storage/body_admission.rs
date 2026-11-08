//! Admitted final UTF-8 output from a record document.

use super::{ENTITY_DOC_HEAD, TextField, body_with_document, load, require_live};
use crate::EntityId;
use crate::side_table::HexId;
use heed::RoTxn;

/// Resolves a record body, admitting an ASSET's final UTF-8 output before
/// converting its document text. Native snapshot, update, value-cache and
/// decoded-state allocations remain outside this output admission.
pub(crate) fn resolve_record_body_with_utf8_admission<G, E>(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    body: &[u8],
    admit: impl FnOnce(u64) -> std::result::Result<G, E>,
) -> std::result::Result<(Vec<u8>, Option<G>), crate::ports::BodyReadError<E>> {
    let Some(h) = ENTITY_DOC_HEAD.get(store, txn, &HexId(*entity))? else {
        return Ok((body.to_vec(), None));
    };
    require_live(store, txn, entity)?;
    let doc = load(store, txn, &h)?;
    match &h.field {
        TextField::Utf8Body => {
            let text = doc.doc.get_text(super::super::document::BODY);
            let guard =
                admit(text.len_utf8() as u64).map_err(crate::ports::BodyReadError::Admission)?;
            Ok((text.to_string().into_bytes(), Some(guard)))
        }
        TextField::MapField(_) => Ok((body_with_document(&h.field, body, &doc)?, None)),
    }
}
