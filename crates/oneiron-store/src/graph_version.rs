//! The graph version counter in `hnsw_meta`, which PPR caches are keyed and
//! validated by, and its little-endian u64 row codec.

use heed::{RoTxn, RwTxn};
use oneiron_contracts::error::{Error, Result};

use crate::overlay_db::OverlayDb;

/// The `hnsw_meta` key of the graph version counter.
pub const GRAPH_VERSION_KEY: &[u8] = b"graph_version";

/// Bumps the graph version counter in `wtxn`.
pub fn increment_graph_version(hnsw_meta: &OverlayDb, wtxn: &mut RwTxn<'_>) -> Result<()> {
    let current = read_graph_version(hnsw_meta, &*wtxn)?;
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("ppr graph version"))?;
    hnsw_meta.put(wtxn, GRAPH_VERSION_KEY, &next.to_le_bytes())?;
    Ok(())
}

/// The graph version counter in `txn`; zero when unset.
pub fn read_graph_version(hnsw_meta: &OverlayDb, txn: &RoTxn<'_>) -> Result<u64> {
    Ok(hnsw_meta
        .get(txn, GRAPH_VERSION_KEY)?
        .map(|raw| decode_u64(&raw, "ppr graph version"))
        .transpose()?
        .unwrap_or(0))
}

/// One little-endian u64 row; `context` names the row in the corruption
/// error.
pub fn decode_u64(raw: &[u8], context: &'static str) -> Result<u64> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| Error::CorruptedIndex(context))?;
    Ok(u64::from_le_bytes(bytes))
}
