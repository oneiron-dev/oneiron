//! Transactional graph-version metadata.

use crate::error::{Error, Result};
use crate::ports::{IndexMetaKey, RetrievalIndexInventory};
use crate::store::{GRAPH_VERSION_KEY, ManifestDbs, Store};
use heed::{RoTxn, RwTxn};

pub(crate) fn increment_graph_version(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let current = read_graph_version(store, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("ppr graph version"))?;
    store
        .hnsw_meta
        .put(wtxn, GRAPH_VERSION_KEY, &next.to_le_bytes())?;
    Ok(())
}
pub(crate) fn read_graph_version(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    Ok(store
        .port_index_meta_with_raw(txn, IndexMetaKey::GraphVersion, |raw| {
            decode_u64(raw, "ppr graph version")
        })?
        .unwrap_or(0))
}
pub(crate) fn decode_u64(raw: &[u8], context: &'static str) -> Result<u64> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::CorruptedIndex(context))?;
    Ok(u64::from_le_bytes(bytes))
}
