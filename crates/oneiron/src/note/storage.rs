//! Canonical entity-document carriers shared by local NOTE edits and sync.
use super::documents::invalid;
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, UpdateSeq};
use crate::{EntityId, Result, Vault};
use loro::{ExportMode, LoroDoc};

pub(crate) fn load(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<LoroDoc> {
    super::ensure_citations_ready(&vault.store, txn, id)?;
    load_for_erasure(vault, txn, id)
}

pub(crate) fn load_for_erasure(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<LoroDoc> {
    load_seeded(&vault.store, txn, id, || {
        Ok(super::document_birth_in_txn(vault, txn, id)?.unwrap_or_default())
    })
}

pub(super) fn load_seeded(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    birth: impl FnOnce() -> Result<LoroDoc>,
) -> Result<LoroDoc> {
    // A NOTE's text plane is its head's document.
    let slot = super::documents::head_in(store, txn, id)?.0;
    let doc = match store.port_document_row(txn, DocumentSlot::of(slot), DocumentRow::Snapshot)? {
        Some(bytes) => {
            let doc = LoroDoc::new();
            import_complete(&doc, &bytes)?;
            doc
        }
        None if slot == id => birth()?,
        None => return Err(invalid("NOTE head document missing")),
    };
    for update in store.port_document_updates(txn, DocumentSlot::of(slot))? {
        if !matches!(update.seq, Some(UpdateSeq::Sequence(_))) {
            return Err(invalid("invalid canonical document update key"));
        }
        import_complete(&doc, &update.bytes)?;
    }
    Ok(doc)
}

pub(crate) fn import_complete(doc: &LoroDoc, bytes: &[u8]) -> Result<()> {
    let status = doc
        .import(bytes)
        .map_err(|_| invalid("invalid canonical document bytes"))?;
    if status.pending.is_some() {
        return Err(invalid("canonical document has pending dependencies"));
    }
    Ok(())
}

pub(crate) fn snapshot(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    doc: &LoroDoc,
    shallow: bool,
) -> Result<()> {
    let document = DocumentSlot::of(slot(vault, txn, id)?);
    let bytes = if shallow {
        state_copy(doc)?
    } else {
        doc.export(ExportMode::Snapshot)
            .map_err(|_| invalid("canonical document snapshot"))?
    };
    let store = &vault.store;
    store.port_document_snapshot_put(txn, document, &bytes)?;
    store.port_document_state_vector_put(txn, document, &doc.oplog_vv().encode())?;
    if shallow {
        store.port_document_shallow_since_put(txn, document, &doc.oplog_vv().encode())?;
    }
    store.port_document_updates_delete(txn, document)
}

/// The document slot of `id`: its head's document for a NOTE, else its own.
pub(crate) fn slot(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<EntityId> {
    Ok(super::documents::head_in(&vault.store, txn, id)?.0)
}

pub(crate) fn state_copy(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::StateOnly(None))
        .map_err(|_| invalid("canonical document state"))
}

/// Current NOTE text-plane identity for an impact preview. Read the canonical
/// head and its complete Loro frontier in the SAME owner-authorized snapshot
/// (and again in the committing writer); the entity envelope does not move
/// when someone edits NOTE prose or citations.
pub(crate) fn delete_preview_fingerprint(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<Option<[u8; 32]>> {
    let header = crate::batch::EntityMetadataHeader::parse(raw)
        .ok_or(crate::Error::CorruptedIndex("entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_NOTE {
        return Ok(None);
    }
    // UserDelete intentionally retains the 25-byte envelope shell while
    // erasing its entire text plane. A fresh preview of that valid shell is
    // the entry to explicit purge or a retry after failed publication; it
    // has no NOTE document to fingerprint. Nonempty NOTE bodies still load
    // the canonical document and fail closed if that live state is invalid.
    if raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    let head = super::documents::head_in(&vault.store, txn, id)?.0;
    let doc = load_for_erasure(vault, txn, id)?;
    let mut hash = blake3::Hasher::new_derive_key("oneiron/delete-preview-note/v1");
    hash.update(head.as_bytes());
    hash.update(&doc.oplog_vv().encode());
    hash.update(&doc.state_frontiers().encode());
    Ok(Some(*hash.finalize().as_bytes()))
}
