//! Transactional erasure of a NOTE's own carriers and outgoing pin indexes.

use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot};
use crate::side_table::HexId;
use crate::store::Store;
use crate::{EntityId, Result};

use super::documents::{NOTE_HEAD, NOTE_HEAD_DOC};
use super::sync_rows::{
    NOTE_RECEIPT_BY_REQUEST, SYNC_AD_E, SYNC_DS_E, SYNC_NC_E, SYNC_QD_E, SYNC_QN_E,
};

// Byte-level cleanup runs featureless too. Incoming source/claim dependencies
// stay indexed until hard erasure scrubs their citing documents. Soft deletion
// is ordinary drift and must not silently discard the saved quotes.
pub(crate) fn delete_document_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let own = DocumentSlot::of(*id);
    store.port_document_rows_delete(txn, own, &DocumentRow::ALL)?;
    SYNC_DS_E.delete(store, txn, &HexId(*id))?;
    let heads = NOTE_HEAD_DOC.scan_keys(store, txn, id.as_bytes())?;
    for (note, head) in heads {
        let slot = DocumentSlot::of(head);
        store.port_document_rows_delete(txn, slot, &DocumentRow::ALL)?;
        store.port_document_updates_delete(txn, slot)?;
        NOTE_HEAD_DOC.delete(store, txn, &(note, head))?;
    }
    NOTE_HEAD.delete(store, txn, id)?;
    store.port_document_updates_delete(txn, own)?;
    let key_prefix = format!("{}:", id.to_hex()).into_bytes();
    SYNC_QD_E.delete_from(store, txn, &key_prefix)?;
    SYNC_AD_E.delete_from(store, txn, &key_prefix)?;
    SYNC_QN_E.delete_from(store, txn, &key_prefix)?;
    NOTE_RECEIPT_BY_REQUEST.delete_from(store, txn, &key_prefix)?;
    SYNC_NC_E.delete_from(store, txn, &key_prefix)?;
    super::pin_index::remove_citing(store, txn, *id)?;
    super::pin_index::remove_citing_requests(store, txn, *id)?;
    super::citation_erase::NOTE_ERASE_PENDING.delete_from(store, txn, &key_prefix)?;
    Ok(())
}
