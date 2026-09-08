//! SLIM derived-shape drop producer.

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};

use super::keys::{
    COUNT_KEY, DROPPED_REBUILDABLE_ENABLED, DROPPED_REBUILDABLE_KEY, ENTRY_POINT_KEY,
    ERR_COUNT_OVERFLOW, ERR_DROPPED_MARKER_BYTES,
};
use super::one_way::clear_one_way_exceptions;

/// Whether the derived graph shape is currently dropped by a SLIM shed.
///
/// Fail-closed like [`read_link_discipline`]: a present-but-malformed marker
/// is [`Error::CorruptedIndex`], never a silent "not dropped".
pub(crate) fn hnsw_is_dropped(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<bool> {
    match store.hnsw_meta().get(txn, DROPPED_REBUILDABLE_KEY)? {
        None => Ok(false),
        Some(raw) if *raw == [DROPPED_REBUILDABLE_ENABLED] => Ok(true),
        Some(_) => Err(Error::CorruptedIndex(ERR_DROPPED_MARKER_BYTES)),
    }
}

/// SLIM (ONE-1933 / OF-447) concrete HNSW drop producer: clears the derived
/// graph shape inside the caller's write transaction and stamps
/// [`DROPPED_REBUILDABLE_KEY`], preserving every source row.
///
/// Deleted: `hnsw_neighbors`, [`COUNT_KEY`], the entry point, and the `ow1:`
/// one-way-exception keyspace. Preserved: `vectors`, the vector version, the
/// embedding model id, the symmetric-links marker, the rebuild counters, and
/// every other `hnsw_meta` key.
///
/// The caller commits; on any error the transaction aborts and the derived
/// rows are unchanged. Re-running while already dropped is safe and re-parks
/// whatever lazy use re-inflated since the previous shed.
pub(crate) fn drop_rebuildable_hnsw(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
) -> Result<crate::slim::HeapDropReport> {
    // Read the marker FIRST so a malformed one fails closed before any
    // mutation, exactly like every other decode on this module's write paths.
    let was_dropped = hnsw_is_dropped(store, &*wtxn)?;

    let mut hnsw_nodes = 0_u64;
    let mut estimated_reclaimed_bytes = 0_u64;
    for entry in store.hnsw_neighbors().iter(&*wtxn)? {
        let (key, neighbors) = entry?;
        hnsw_nodes = hnsw_nodes
            .checked_add(1)
            .ok_or(Error::IndexOverflow(ERR_COUNT_OVERFLOW))?;
        estimated_reclaimed_bytes =
            estimated_reclaimed_bytes.saturating_add((key.len() + neighbors.len()) as u64);
    }

    store.hnsw_neighbors().clear(wtxn)?;
    store.hnsw_meta().delete(wtxn, COUNT_KEY)?;
    store.hnsw_meta().delete(wtxn, ENTRY_POINT_KEY)?;
    clear_one_way_exceptions(store, wtxn)?;
    store.hnsw_meta().put(
        wtxn,
        DROPPED_REBUILDABLE_KEY,
        &[DROPPED_REBUILDABLE_ENABLED],
    )?;

    tracing::debug!(
        was_dropped,
        hnsw_nodes,
        estimated_reclaimed_bytes,
        "slim: dropped the rebuildable hnsw graph shape"
    );
    Ok(crate::slim::HeapDropReport {
        hnsw_nodes,
        estimated_reclaimed_bytes,
        ..crate::slim::HeapDropReport::default()
    })
}
