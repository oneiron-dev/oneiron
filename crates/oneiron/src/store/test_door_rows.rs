//! Raw core-table rows for the test doors (`--cfg oneiron_test_support`
//! only; never API). A door that pins how a reader meets a stored row
//! plants that row byte for byte, malformed rows included: a short entity
//! value, a key of the wrong width, an edge key with an unknown kind byte.
//! No typed writer writes those, so a door puts them through these
//! functions, in the store that owns `entities`, `edges_out` and
//! `edges_in`, and never with a raw `.put(` of its own (the raw_core_writes
//! ratchet, T48).

use heed::RwTxn;

use crate::error::Result;
use crate::store::Store;

/// Puts `value` under `key` in `entities` as given: no type-index row, and
/// no check that either decodes.
pub(crate) fn put_entity_row_bytes_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    store.entities.put(txn, key, value)?;
    Ok(())
}

/// Puts `value` under `key` in `edges_out` as given: no `edges_in` mirror,
/// and no check that either decodes.
pub(crate) fn put_edge_out_row_bytes_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    store.edges_out.put(txn, key, value)?;
    Ok(())
}

/// Puts `value` under `key` in `edges_in` as given: no `edges_out` mirror,
/// and no check that either decodes.
pub(crate) fn put_edge_in_row_bytes_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    store.edges_in.put(txn, key, value)?;
    Ok(())
}
