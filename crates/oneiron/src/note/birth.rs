//! Deterministic NOTE birth on the shared document registry's first load.
use super::document::NoteDocument;
use crate::store::ManifestDbs;
use crate::{EntityId, Result, Vault};

pub(crate) fn document_birth_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<loro::LoroDoc>> {
    document_birth_in(vault, &vault.store, txn, id)
}

/// [`document_birth_in_txn`] of the NOTE row `store` holds: the vault's own,
/// or a room's view of it (FIX 4280).
pub(crate) fn document_birth_in(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<loro::LoroDoc>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| super::document::invalid("NOTE entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_NOTE {
        return Ok(None);
    }
    let (_, body) = super::verbs::note_core_in(vault, store, txn, id)?;
    // The birth records its stored author, live or erased (FIX 6072): the
    // seed is the same on every replica, and no writer is made from it.
    Ok(Some(
        NoteDocument::birth_by(id, &body.markdown, body.author_ref)?.doc,
    ))
}

/// The NOTE document a room stages beside a NOTE it births (FIX 4280), as
/// the rows it stages: the deterministic birth of the row the room holds.
pub(crate) struct RoomBirthDocument {
    /// The document's snapshot row (`d:e:`).
    pub(crate) snapshot: Vec<u8>,
    /// Its state vector row (`sv:e:`).
    pub(crate) state_vector: Vec<u8>,
    /// Its body's UTF-8 bytes, which `EngineScan::NoteDocumentBytes` counts.
    pub(crate) body_bytes: usize,
}

/// [`RoomBirthDocument`] of `id` as `view`'s room holds it, read in the
/// segment's transaction `txn`; `None` when the room holds no NOTE `id`.
///
/// # Errors
///
/// A stored NOTE body that does not decode; a document that does not
/// export.
pub(crate) fn room_birth_document_in_txn(
    vault: &Vault,
    view: &crate::store::SessionStoreView<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<RoomBirthDocument>> {
    let Some(doc) = document_birth_in(vault, view, txn, id)? else {
        return Ok(None);
    };
    let snapshot = doc
        .export(loro::ExportMode::Snapshot)
        .map_err(|_| super::document::invalid("NOTE birth snapshot"))?;
    Ok(Some(RoomBirthDocument {
        snapshot,
        state_vector: doc.oplog_vv().encode(),
        body_bytes: super::document::document_sizes(&doc)[0],
    }))
}
