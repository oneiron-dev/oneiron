//! One decision-ledger scan for a tombstone batch's missing-id probes (SCAN
//! C049). A hard tombstone for an id with nothing else here still proves,
//! against the whole ledger, that no unredacted decision binds or cites it.
//! A batch of them shares one such scan in its own transaction, so a peer's
//! many unknown ids cost one walk of the ledger, not one each.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The ids one batch's scan proved clear: no unredacted decision binds or
/// cites them. Read only on the thread holding the batch's transaction.
struct ClearIds {
    thread: ThreadId,
    clear: BTreeSet<EntityId>,
}

/// Where a tombstone batch's scan answer is held while the batch applies.
#[derive(Default)]
pub(crate) struct TombstoneScopeProbes(Mutex<Option<ClearIds>>);

/// A tombstone batch's scan answer, held until the batch's last item applied:
/// dropping it withdraws the answer.
#[must_use = "a batch's scan answers its probes only while it is held"]
pub(crate) struct TombstoneScopeProbeBatch<'v> {
    slot: &'v TombstoneScopeProbes,
}

impl Drop for TombstoneScopeProbeBatch<'_> {
    fn drop(&mut self) {
        *lock(&self.slot.0) = None;
    }
}

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

/// The answer changes in one step, so a holder that panicked left it whole:
/// a poisoned lock is still true.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
