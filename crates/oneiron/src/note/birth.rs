//! Deterministic NOTE birth on the shared document registry's first load.
use super::document::NoteDocument;
use crate::{EntityId, Result, Vault};

pub(crate) fn document_birth_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<loro::LoroDoc>> {
    let Some(raw) = vault.get_raw_in(txn, &id)? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| super::document::invalid("NOTE entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_NOTE {
        return Ok(None);
    }
    let (_, body) = super::verbs::note_core(vault, txn, id)?;
    // The birth records its stored author, live or erased (FIX 6072): the
    // seed is the same on every replica, and no writer is made from it.
    Ok(Some(NoteDocument::birth_by(id, &body.markdown, body.author_ref)?.doc))
}
