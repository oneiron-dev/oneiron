//! One decision-ledger scan for a tombstone batch's missing-id probes (SCAN
//! C049). A hard tombstone for an id with nothing else here still proves,
//! against the whole ledger, that no unredacted decision binds or cites it.
//! A batch of them shares one such scan in its own transaction, so a peer's
//! many unknown ids cost one walk of the ledger, not one each.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The ids one batch's scan proved clear: no unredacted decision binds or
/// cites them. Read only on the thread holding the batch's transaction.
pub struct ClearIds {
    pub thread: ThreadId,
    pub clear: BTreeSet<EntityId>,
}

/// Where a tombstone batch's scan answer is held while the batch applies.
#[derive(Default)]
pub struct TombstoneScopeProbes(pub Mutex<Option<ClearIds>>);

/// A tombstone batch's scan answer, held until the batch's last item applied:
/// dropping it withdraws the answer.
#[must_use = "a batch's scan answers its probes only while it is held"]
pub struct TombstoneScopeProbeBatch<'v> {
    pub slot: &'v TombstoneScopeProbes,
}

impl Drop for TombstoneScopeProbeBatch<'_> {
    fn drop(&mut self) {
        *lock(&self.slot.0) = None;
    }
}

/// The answer changes in one step, so a holder that panicked left it whole:
/// a poisoned lock is still true.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
