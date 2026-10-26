//! The sweep's entity documents (FIX 10159): the slot each retained head
//! names, and the owner's own compaction of one document. An entity
//! document's updates are keyed at its head's generation, which the NOTE and
//! text-plane loader does not read, so the sweep hands every headed document
//! here first; a malformed head or history fails here and never falls
//! through to that loader.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use super::EntityDoc;
use super::pins;
use super::storage::{self, ENTITY_DOC_HEAD};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::ports::{DocumentRowStore, DocumentSlot};
use crate::side_table::HexId;
use crate::store::ManifestDbs;

/// Each slot a retained head names, with that head's entity. A slot two
/// heads name is left out: no one owner compacts it.
pub(crate) fn entity_doc_slots_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<BTreeMap<String, EntityId>> {
    let mut slots = BTreeMap::new();
    let mut shared = BTreeSet::new();
    for (HexId(entity), head) in ENTITY_DOC_HEAD.scan_from(store, txn, &[])? {
        if head.entity != entity.to_hex() {
            continue;
        }
        if slots.insert(head.document.clone(), entity).is_some() {
            shared.insert(head.document);
        }
    }
    slots.retain(|slot, _| !shared.contains(slot));
    Ok(slots)
}

/// Compacts `entity`'s document for the sweep, as its owner keeps it.
/// `false`, with nothing read past the head, when no head of `entity`
/// stands: the NOTE and text-plane path compacts it as before. Otherwise its
/// cached document is held out while one writer checks the head and any
/// legal hold again (OF-470): an erased entity's document goes through the
/// erase door, and a live one's history is cut to the floor its pins,
/// citation floors, receipts and pending forks leave, its text, version,
/// generation and state vector kept. An unerased NOTE is the NOTE purge
/// door's, left as it is.
pub(crate) fn compact_entity_doc_for_sweep(
    vault: &Vault,
    entity: &EntityId,
    erased: bool,
) -> Result<bool> {
    {
        let rtxn = vault.store.env.read_txn()?;
        if !storage::has_record_head(&vault.store, &rtxn, entity)? {
            return Ok(false);
        }
    }
    let mut registry = vault
        .entity_docs
        .lock()
        .map_err(|_| super::invalid("document registry poisoned"))?;
    vault.with_write_txn_grouped(|txn| compact_in_txn(vault, txn, entity, erased))?;
    registry.remove(entity);
    Ok(true)
}

/// [`compact_entity_doc_for_sweep`]'s writer.
fn compact_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    erased: bool,
) -> Result<()> {
    let store = &vault.store;
    // A head gone since the read leaves nothing of this document to compact.
    let Some(mut head) = ENTITY_DOC_HEAD.get(store, txn, &HexId(*entity))? else {
        return Ok(());
    };
    if head.entity != entity.to_hex() {
        return Err(Error::CorruptedIndex("document head entity mismatch"));
    }
    if !erased
        && vault.get_entity_type_in_txn(txn, entity)? == Some(crate::registry::ENTITY_TYPE_NOTE)
    {
        return Ok(());
    }
    // A held document keeps its bytes and its history (FIX 10160).
    store.reject_legal_holds_in_txn(
        txn,
        &[*entity],
        &crate::store::legal_hold::HoldActor::TIMER,
    )?;
    if erased {
        return storage::erase_in_txn(store, txn, entity);
    }
    let doc = storage::load(store, txn, &head)?;
    let Some(shallow) = cut(vault, txn, entity, &head.incarnation, &doc)? else {
        tracing::warn!("sweep: an entity document's retention holds its history — kept whole");
        return Ok(());
    };
    let slot = DocumentSlot::from_hex(&head.document)?;
    store.port_document_snapshot_put(txn, slot, &shallow.export_snapshot()?)?;
    store.port_document_updates_delete(txn, slot)?;
    store.port_document_state_vector_put(txn, slot, &shallow.doc.oplog_vv().encode())?;
    store.port_document_shallow_since_put(txn, slot, &shallow.doc.shallow_since_vv().encode())?;
    head.pending = 0;
    ENTITY_DOC_HEAD.put(store, txn, &HexId(*entity), &head)
}

/// `doc` cut as far as its owner's retention lets it go: to its own
/// frontier, held back by every pin, live citation floor, settlement
/// receipt, pending fork base and earlier purge. `None` where that retention
/// refuses any cut (a pin at or before the history it keeps, or a cut that
/// would change a pinned version): no more of it may go, and it stays whole.
fn cut(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    incarnation: &str,
    doc: &EntityDoc,
) -> Result<Option<EntityDoc>> {
    let held = |error: &Error| {
        matches!(
            error,
            Error::Artifact(ArtifactError::InvalidEditManifest(_)) | Error::InvariantViolation(_)
        )
    };
    let applied = match pins::floor(vault, txn, entity, incarnation, doc, &doc.frontier()) {
        Ok(applied) => applied,
        Err(error) if held(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    match pins::shallow_at(vault, txn, entity, incarnation, doc, &applied) {
        Ok(shallow) => Ok(Some(shallow)),
        Err(error) if held(&error) => Ok(None),
        Err(error) => Err(error),
    }
}
