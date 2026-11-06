//! Transactional graph-version metadata, defined in
//! `oneiron_store::graph_version`: the counter is read and bumped through the
//! store's own `hnsw_meta` table.

use crate::error::Result;
use crate::store::{ManifestDbs, Store};
use heed::{RoTxn, RwTxn};

pub(crate) use oneiron_store::graph_version::decode_u64;

pub(crate) fn increment_graph_version(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    oneiron_store::graph_version::increment_graph_version(&store.hnsw_meta, wtxn)
}
pub(crate) fn read_graph_version(store: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<u64> {
    oneiron_store::graph_version::read_graph_version(store.hnsw_meta(), txn)
}
