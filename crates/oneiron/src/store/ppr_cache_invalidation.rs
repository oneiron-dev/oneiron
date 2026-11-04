//! Transaction-local invalidation of a retrieval cache after stored graph writes.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use heed::RwTxn;

pub(crate) trait PprCacheInvalidation: Send + Sync {
    fn invalidate_for_edge(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        source: &EntityId,
        target: &EntityId,
    ) -> Result<()>;

    fn invalidate_for_delete(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        neighbors: &[EntityId],
    ) -> Result<()>;

    fn purge_for_erase(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        neighbors: &[EntityId],
    ) -> Result<()>;
}

pub(crate) fn invalidate_ppr_for_edge(
    store: &Store,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
    target: &EntityId,
) -> Result<()> {
    store.ppr_cache_invalidation.invalidate_for_edge(store, txn, source, target)
}

pub(crate) fn invalidate_ppr_for_delete(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    neighbors: &[EntityId],
) -> Result<()> {
    store.ppr_cache_invalidation.invalidate_for_delete(store, txn, id, neighbors)
}

pub(crate) fn purge_ppr_for_erase_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    neighbors: &[EntityId],
) -> Result<()> {
    store.ppr_cache_invalidation.purge_for_erase(store, txn, id, neighbors)
}
