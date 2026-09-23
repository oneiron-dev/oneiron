//! Transactional erasure of a NOTE's own carriers and outgoing pin indexes.

use crate::store::Store;
use crate::{EntityId, Result};

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
    for prefix in ["d:e:", "sv:e:", "ssv:e:", "m:u_seq:e:", "ds:e:"] {
        store.sync_state.delete(txn, &format!("{prefix}{hex}"))?;
    }
    let heads_prefix = super::documents::head_doc_prefix(*id);
    let heads = store
        .vault_meta
        .prefix_iter(txn, &heads_prefix)?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in heads {
        let head = key
            .get(heads_prefix.len()..)
            .and_then(|bytes| bytes.try_into().ok())
            .and_then(|bytes| EntityId::from_bytes(bytes).ok())
            .ok_or(super::documents::invalid("NOTE head document index"))?
            .to_hex();
        for prefix in ["d:e:", "sv:e:", "ssv:e:", "m:u_seq:e:"] {
            store.sync_state.delete(txn, &format!("{prefix}{head}"))?;
        }
        delete_sync_prefix(store, txn, &format!("u:e:{head}:"))?;
        store.vault_meta.delete(txn, &key)?;
    }
    store
        .vault_meta
        .delete(txn, &super::documents::head_key(*id))?;
    for prefix in ["u:e:", "qd:e:", "ad:e:", "qn:e:", "nr:e:", "nc:e:"] {
        delete_sync_prefix(store, txn, &format!("{prefix}{hex}:"))?;
    }
    super::pin_index::remove_citing(store, txn, *id)?;
    super::pin_index::remove_citing_requests(store, txn, *id)?;
    let prefix = super::citation_erase::pending_prefix(*id);
    let keys = store
        .vault_meta
        .prefix_iter(txn, prefix.as_bytes())?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}
