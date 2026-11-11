//! Canonical entity-document carriers shared by local NOTE edits and sync.
use super::documents::invalid;
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, UpdateSeq};
use crate::scan_check::PendingScanChecks;
use crate::store::ManifestDbs;
use crate::{EntityId, Result, Vault};
use loro::{ExportMode, LoroDoc};

pub(crate) fn load(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<LoroDoc> {
    super::ensure_citations_ready(&vault.store, txn, id)?;
    load_for_erasure(vault, txn, id)
}

/// [`load`] with the NOTE and its document read through `store`, a room's
/// view included (FIX 4280); its sizes are measured into `pending`.
pub(crate) fn load_in(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    pending: &PendingScanChecks,
) -> Result<LoroDoc> {
    super::ensure_citations_ready(&vault.store, txn, id)?;
    load_stored_to(store, txn, id, pending)
}

pub(crate) fn load_for_erasure(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<LoroDoc> {
    load_stored(&vault.store, txn, id)
}

/// The NOTE's head document as `store` holds it. A NOTE's document is born
/// in its birth's transaction (FIX 7783), so a head with no stored document
/// is refused, never rebuilt from the row.
pub(super) fn load_stored<S: ManifestDbs>(
    store: &S,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<LoroDoc> {
    load_stored_to(store, txn, id, store.pending_scan_checks())
}

/// [`load_stored`], the loaded document's sizes measured into `pending`
/// (rule 5: `note::scan` raises a check past a threshold row and the load
/// serves; no size refuses it).
fn load_stored_to(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    pending: &PendingScanChecks,
) -> Result<LoroDoc> {
    stored_to(store, txn, id, pending)?.ok_or_else(|| invalid("NOTE head document missing"))
}

/// The head document this vault holds of NOTE `id`, or `None` while it holds
/// none: a replica whose authority has not sent the NOTE's document yet. Only
/// the sync doors that ask for that document, and recovery, read this.
pub(crate) fn stored_document(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<LoroDoc>> {
    super::ensure_citations_ready(&vault.store, txn, id)?;
    stored_to(&vault.store, txn, id, &vault.store.pending_scan_checks)
}

/// The head document `store` holds of NOTE `id`, or `None` while it holds
/// none, its sizes measured into the store's own pending checks.
pub(super) fn stored_in<S: ManifestDbs>(
    store: &S,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<LoroDoc>> {
    stored_to(store, txn, id, store.pending_scan_checks())
}

fn stored_to(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    pending: &PendingScanChecks,
) -> Result<Option<LoroDoc>> {
    // A NOTE's text plane is its head's document.
    let slot = DocumentSlot::of(super::documents::head_in(store, txn, id)?.0);
    let updates = store.port_document_updates(txn, slot)?;
    let doc = match store.port_document_row(txn, slot, DocumentRow::Snapshot)? {
        Some(bytes) => {
            let doc = LoroDoc::new();
            import_complete(&doc, &bytes)?;
            doc
        }
        None if updates.is_empty() => return Ok(None),
        None => return Err(invalid("NOTE head document missing")),
    };
    for update in updates {
        if !matches!(update.seq, Some(UpdateSeq::Sequence(_))) {
            return Err(invalid("invalid canonical document update key"));
        }
        import_complete(&doc, &update.bytes)?;
    }
    super::scan::measure_document(store, txn, id, &doc, pending)?;
    Ok(Some(doc))
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
    // The stamp tokens its changes past the stored version name, for the
    // hold check (FIX 11965); with no stored version, every change's.
    let stored = vault
        .store
        .port_document_row(txn, document, DocumentRow::StateVector)?;
    let since = stored.and_then(|bytes| loro::VersionVector::decode(&bytes).ok());
    super::token_uses::record_token_uses_in_txn(vault, txn, id, doc, since.as_ref())?;
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
