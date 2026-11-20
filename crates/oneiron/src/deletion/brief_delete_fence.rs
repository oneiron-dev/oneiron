//! The user deletes in flight that hold their target's brief delete
//! reservation.
//!
//! A user delete reserves its target ([`crate::share::reserve_brief_delete`])
//! in its own transaction before it linearizes, so no brief share of the
//! target is admitted while the delete runs. The reservation stays once a
//! delete of the id linearizes: its soft scrub commits, or its tombstone
//! publication commits or changes the live window document. A delete refused
//! before that point committed nothing destructive, so it releases the
//! reservation, but only a row its own flight created, and only when no other
//! delete of the id is in flight and none linearized: a refused delete never
//! takes away a fence an earlier delete left, and of two racing deletes the
//! refused one never strands the one that goes on. The set belongs to the
//! vault's store and is never persisted: a crash keeps every row it held, the
//! fail-closed direction.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

#[cfg(test)]
mod tests;

/// The deletes in flight that reserved one id.
struct Holders {
    /// How many of them still hold it.
    deletes: usize,
    /// The first of them created the row, and no delete of the id has
    /// linearized since.
    releasable: bool,
}

/// The reserved ids of this vault's user deletes in flight.
#[derive(Default)]
pub(crate) struct BriefDeleteFences {
    held: Mutex<BTreeMap<EntityId, Holders>>,
}

impl BriefDeleteFences {
    /// Reserves `id` in `txn`, the delete's reservation writer, commits it,
    /// and returns the delete's hold. The set stays locked from the row's read
    /// through the commit; every taker of both holds the writer first.
    pub(crate) fn reserve(
        &self,
        store: &Store,
        mut txn: heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<BriefDeleteFence<'_>> {
        let mut held = self.held();
        let created = crate::share::reserve_brief_delete(store, &mut txn, id)?;
        txn.commit()?;
        held.entry(*id)
            .and_modify(|holders| holders.deletes += 1)
            .or_insert(Holders {
                deletes: 1,
                releasable: created,
            });
        Ok(BriefDeleteFence {
            fences: self,
            id: *id,
            held: true,
        })
    }

    /// A delete of `id` linearized: its reservation stays. Called after the
    /// commit or publication that linearizes any delete, reserved or not.
    pub(crate) fn settle(&self, id: &EntityId) {
        if let Some(holders) = self.held().get_mut(id) {
            holders.releasable = false;
        }
    }

    /// Drops one hold on `id`, keeping the row.
    fn leave(&self, id: &EntityId) {
        let mut held = self.held();
        if let Some(holders) = held.get_mut(id) {
            holders.deletes = holders.deletes.saturating_sub(1);
            if holders.deletes == 0 {
                held.remove(id);
            }
        }
    }

    /// Drops one hold on `id`; the last hold on a releasable row removes the
    /// row under the writer. A failed release keeps the row, as a crash would.
    fn release(&self, store: &Store, id: &EntityId) {
        let sole_releasable = self
            .held()
            .get(id)
            .is_some_and(|holders| holders.deletes == 1 && holders.releasable);
        if !sole_releasable {
            self.leave(id);
            return;
        }
        // The writer first, then the set, as `reserve` takes them; the set is
        // read again, since a delete may have joined or linearized meanwhile.
        let Ok(mut txn) = store.env.write_txn() else {
            self.leave(id);
            return;
        };
        let mut held = self.held();
        let Some(holders) = held.get_mut(id) else {
            return;
        };
        holders.deletes = holders.deletes.saturating_sub(1);
        if holders.deletes > 0 {
            return;
        }
        let releasable = holders.releasable;
        held.remove(id);
        if releasable {
            crate::share::release_brief_delete(store, &mut txn, id)
                .and_then(|()| txn.commit().map_err(Into::into))
                .ok();
        }
    }

    fn held(&self) -> MutexGuard<'_, BTreeMap<EntityId, Holders>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One user delete's hold on its target's reservation, from the reservation
/// to the delete's return. [`conclude_brief_delete`] ends it with the
/// delete's outcome; a hold dropped unconcluded (a panic) keeps the row.
pub(crate) struct BriefDeleteFence<'a> {
    fences: &'a BriefDeleteFences,
    id: EntityId,
    held: bool,
}

impl Drop for BriefDeleteFence<'_> {
    fn drop(&mut self) {
        if self.held {
            self.fences.settle(&self.id);
            self.fences.leave(&self.id);
        }
    }
}

/// Ends a delete's hold on its target's reservation with the delete's
/// `outcome`, and returns it. An `Ok` keeps the reservation. An error releases
/// it, unless the row predates this flight, another delete of the id is still
/// in flight, or a delete of the id linearized.
pub(crate) fn conclude_brief_delete<T>(
    fence: Option<BriefDeleteFence<'_>>,
    store: &Store,
    outcome: Result<T>,
) -> Result<T> {
    let Some(mut fence) = fence else {
        return outcome;
    };
    fence.held = false;
    if outcome.is_ok() {
        fence.fences.settle(&fence.id);
        fence.fences.leave(&fence.id);
    } else {
        fence.fences.release(store, &fence.id);
    }
    outcome
}
