//! Core half of `deletion::erase::scope_probes`: its store-layer items live in `oneiron_store::deletion::erase::scope_probes` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::deletion::erase::scope_probes::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;

impl Vault {
    /// Scans the decision ledger once in `txn`, the batch's own transaction,
    /// for every id of `ids`, and holds which of them it proved clear until
    /// the returned batch drops: each of their missing-id probes reads that
    /// answer instead of scanning again. An id it did not prove clear scans
    /// on its own, as before. Each item applies only its own id's decisions,
    /// so a clear answer stays true across the batch.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn batch_tombstone_scope_probes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        ids: impl IntoIterator<Item = EntityId>,
    ) -> Result<TombstoneScopeProbeBatch<'_>> {
        let ids: BTreeSet<EntityId> = ids.into_iter().collect();
        let claims = ids.iter().map(|id| *id.as_bytes()).collect();
        let unerased = self
            .store
            .claims_with_unerased_decisions_by_scan_in_txn(txn, &claims)?;
        let clear = ids
            .into_iter()
            .filter(|id| !unerased.contains(id.as_bytes()))
            .collect();
        let slot = &self.store.tombstone_scope_probes;
        *lock(&slot.0) = Some(ClearIds {
            thread: std::thread::current().id(),
            clear,
        });
        Ok(TombstoneScopeProbeBatch { slot })
    }

    /// Whether the batch applying on this thread proved `id` clear of every
    /// unredacted decision.
    pub(super) fn tombstone_ledger_clear(&self, id: &EntityId) -> bool {
        lock(&self.store.tombstone_scope_probes.0)
            .as_ref()
            .is_some_and(|ids| ids.thread == std::thread::current().id() && ids.clear.contains(id))
    }
}
