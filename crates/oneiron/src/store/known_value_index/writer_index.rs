//! One known-value index per write (FIX 12210): the index a write the group
//! commit runs loads is kept, on the thread that runs it, for that write's
//! later passes, and checked against the writer before each.
//!
//! An index is built from the custody binding, the master's generation,
//! each holder's committed slots and each holder's handle, and from the
//! custody entries at those slots. No entry at a slot changes while the
//! writer is held: custody never writes a slot twice, a value is published
//! at a new slot past every slot its holder's custody holds, and a
//! retirement leaves its marker and waits for the writer. So a later pass
//! whose writer reads the same binding, generation, slots and handles is
//! given the kept index; any other reads custody again, as every pass did
//! before. That covers a value remembered or erased in the write, and a
//! nested transaction that dropped its rows.
//!
//! The kept index lives only while its write's scope does
//! ([`KnownIndexScope`]) and is wiped when that scope ends, before the
//! writer commits: it never outlives the writer it was read in. A load
//! outside any scope reads custody, as before.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use heed::{RoTxn, RwTxn};

use super::KnownValues;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::ShortIdStoreRead;
use crate::store::{KnownHistoryIds, Store};

thread_local! {
    /// How many write scopes this thread is inside.
    static SCOPES: Cell<usize> = const { Cell::new(0) };
    /// The index this thread's write loaded, with what it was read from.
    static KEPT: RefCell<Option<KeptIndex>> = const { RefCell::new(None) };
}

/// One loaded index and what it was built from. The index wipes itself
/// when the last holder drops it.
struct KeptIndex {
    ids: KnownHistoryIds,
    /// Each holder the index asked a handle of, in the order it asked, with
    /// the handle it got.
    handles: Vec<(EntityId, Option<String>)>,
    known: Arc<KnownValues>,
}

/// One write on this thread, run by the group commit: while it lives, an
/// index a pass loads is kept for the write's later passes. Dropping it
/// wipes what is kept.
#[must_use]
pub(crate) struct KnownIndexScope(());

/// Opens a write's scope (FIX 12210). The group commit opens one around
/// each write's transaction.
pub(crate) fn known_index_scope() -> KnownIndexScope {
    SCOPES.with(|scopes| scopes.set(scopes.get().saturating_add(1)));
    KnownIndexScope(())
}

impl Drop for KnownIndexScope {
    fn drop(&mut self) {
        let depth = SCOPES.with(|scopes| {
            let depth = scopes.get().saturating_sub(1);
            scopes.set(depth);
            depth
        });
        // The outermost write's scope ends: what it kept goes. An inner scope
        // leaves the outer write's index kept; every reuse checks it against
        // the writer, so an inner write's change reloads it.
        if depth == 0 {
            forget_kept();
        }
    }
}

/// Drops the index this thread keeps, wiping it.
pub(super) fn forget_kept() {
    let kept = KEPT.with(|kept| kept.borrow_mut().take());
    drop(kept);
}

impl KnownValues {
    /// [`Self::load_in_writer`], shared across one write's passes (FIX
    /// 12210): inside a write's scope, the index an earlier pass loaded is
    /// given again when the writer `wtxn` reads the same history ids and
    /// handles it was built from; otherwise it is read from custody and
    /// kept. Outside a scope, every call reads custody.
    pub(crate) fn shared_in_writer(store: &Store, wtxn: &RwTxn<'_>) -> Result<Option<Arc<Self>>> {
        if SCOPES.with(Cell::get) == 0 {
            return Ok(Self::load_in_writer(store, wtxn)?.map(Arc::new));
        }
        let txn: &RoTxn<'_> = wtxn;
        let kept = KEPT.with(|kept| kept.borrow_mut().take());
        if let Some(kept) = kept {
            let Some(ids) = store.known_history_ids_in_txn(txn)? else {
                return Ok(None);
            };
            if kept.ids.names_same_history(&ids) && handles_read_same(store, txn, &kept.handles)? {
                let known = Arc::clone(&kept.known);
                KEPT.with(|slot| *slot.borrow_mut() = Some(kept));
                return Ok(Some(known));
            }
        }
        // Read as `load_in_writer` reads it, with the ids and handles it was
        // built from.
        let Some((history, ids)) = store.known_history_with_ids_in_writer(wtxn)? else {
            return Ok(None);
        };
        let handles = RefCell::new(Vec::new());
        let known = Self::of(&history, |custody| {
            let handle = store
                .port_short_id_reference(txn, custody)?
                .map(|(handle, _)| handle);
            handles.borrow_mut().push((*custody, handle.clone()));
            Ok(handle)
        })?;
        drop(history);
        let Some(known) = known.map(Arc::new) else {
            return Ok(None);
        };
        let kept = KeptIndex {
            ids,
            handles: handles.into_inner(),
            known: Arc::clone(&known),
        };
        KEPT.with(|slot| *slot.borrow_mut() = Some(kept));
        Ok(Some(known))
    }
}

/// Whether each holder in `handles` has, as `txn` reads it, the handle it
/// had when the kept index was built.
fn handles_read_same(
    store: &Store,
    txn: &RoTxn<'_>,
    handles: &[(EntityId, Option<String>)],
) -> Result<bool> {
    for (holder, held) in handles {
        let handle = store
            .port_short_id_reference(txn, holder)?
            .map(|(handle, _)| handle);
        if handle != *held {
            return Ok(false);
        }
    }
    Ok(true)
}
