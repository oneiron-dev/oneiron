//! Deterministic NOTE birth on the shared document registry's first load.
use super::document::NoteDocument;
use crate::{EdgeActorClass, EntityId, Result, Vault, WriteActor};

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
    let class = if vault.get_entity_type_in_txn(txn, &body.author_ref)?
        == Some(crate::registry::ENTITY_TYPE_PERSON)
    {
        EdgeActorClass::Human
    } else {
        EdgeActorClass::Agent
    };
    Ok(Some(
        NoteDocument::birth(id, &body.markdown, &WriteActor::new(body.author_ref, class))?.doc,
    ))
}
