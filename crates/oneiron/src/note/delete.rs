//! Transactional erasure of NOTE document carriers and reverse-pin metadata.

use crate::store::Store;
use crate::{EntityId, Result};

// Byte-level cleanup also runs featureless against a sync-edited vault. No
// decoder or full-vault scan is needed to find this document's own carriers.
pub(crate) fn delete_document_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let hex = id.to_hex();
    store.sync_state.delete(txn, &format!("e:note:{hex}"))?;
    let mut keys = Vec::new();
    let source_prefix = format!("note.pin/source/{hex}:");
    for row in store
        .vault_meta
        .prefix_iter(txn, source_prefix.as_bytes())?
    {
        let (key, _) = row?;
        let suffix = std::str::from_utf8(&key[source_prefix.len()..])
            .map_err(|_| crate::Error::CorruptedIndex("NOTE reverse pin key"))?;
        let (citing, hash) = suffix
            .split_once(':')
            .ok_or(crate::Error::CorruptedIndex("NOTE reverse pin key"))?;
        keys.push(format!("note.pin/citing/{citing}:{hex}:{hash}").into_bytes());
        keys.push(key.to_vec());
    }
    for row in store
        .vault_meta
        .prefix_iter(txn, format!("note.pin/citing/{hex}:").as_bytes())?
    {
        let (key, source_key) = row?;
        keys.push(source_key.to_vec());
        keys.push(key.to_vec());
    }
    for key in keys {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}
