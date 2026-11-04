//! PPR's implementation of the store's transaction-local invalidation contract.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::ppr_cache_invalidation::PprCacheInvalidation;
use heed::RwTxn;

pub(crate) struct PprCacheInvalidator;

impl PprCacheInvalidation for PprCacheInvalidator {
    fn invalidate_for_edge(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        source: &EntityId,
        target: &EntityId,
    ) -> Result<()> {
        super::invalidate_ppr_for_edge(store, txn, source, target)
    }

    fn invalidate_for_delete(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        neighbors: &[EntityId],
    ) -> Result<()> {
        super::invalidate_ppr_for_delete(store, txn, id, neighbors)
    }

    fn purge_for_erase(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        neighbors: &[EntityId],
    ) -> Result<()> {
        super::purge_ppr_for_erase_in_txn(store, txn, id, neighbors)
    }
}
