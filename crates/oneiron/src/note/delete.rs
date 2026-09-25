//! Transactional erasure of a NOTE's own carriers and outgoing pin indexes.

use crate::side_table::HexId;
use crate::store::Store;
use crate::{EntityId, Result};

use super::documents::{NOTE_HEAD, NOTE_HEAD_DOC};
use super::sync_rows::{
    NOTE_RECEIPT_BY_REQUEST, SYNC_AD_E, SYNC_DS_E, SYNC_NC_E, SYNC_QD_E, SYNC_QN_E,
};

pub(super) fn delete_sync_prefix(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    prefix: &str,
) -> Result<()> {
    let keys = store
        .sync_state
        .prefix_iter(txn, prefix)?
        .map(|row| row.map(|(key, _)| key.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        store.sync_state.delete(txn, &key)?;
    }
    Ok(())
}

// Byte-level cleanup runs featureless too. Incoming source/claim dependencies
// stay indexed until hard erasure scrubs their citing documents. Soft deletion
// is ordinary drift and must not silently discard the saved quotes.
pub(crate) fn delete_document_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let hex = id.to_hex();
    // ARCH-0023b document families: not ours, left exactly as they were.
    for prefix in ["d:e:", "sv:e:", "ssv:e:", "m:u_seq:e:"] {
        store.sync_state.delete(txn, &format!("{prefix}{hex}"))?;
    }
    SYNC_DS_E.delete(store, txn, &HexId(*id))?;
    let heads = NOTE_HEAD_DOC.scan_keys(store, txn, id.as_bytes())?;
    for (note, head) in heads {
        let head_hex = head.to_hex();
        // ARCH-0023b document families: not ours, left exactly as they were.
        for prefix in ["d:e:", "sv:e:", "ssv:e:", "m:u_seq:e:"] {
            store
                .sync_state
                .delete(txn, &format!("{prefix}{head_hex}"))?;
        }
        delete_sync_prefix(store, txn, &format!("u:e:{head_hex}:"))?;
        NOTE_HEAD_DOC.delete(store, txn, &(note, head))?;
    }
    NOTE_HEAD.delete(store, txn, id)?;
    // ARCH-0023b document family: not ours, left exactly as it was.
    delete_sync_prefix(store, txn, &format!("u:e:{hex}:"))?;
    let key_prefix = format!("{hex}:").into_bytes();
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
