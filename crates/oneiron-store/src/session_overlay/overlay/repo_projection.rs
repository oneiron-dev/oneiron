//! Room-staged media vectors a later mark makes stale (FIX 7608 S3F, FIX
//! 10407): the room's cached vectors of a record whose bytes a mask change
//! reaches are dropped, rows and journal entries both, so neither a
//! composed read nor a promotion serves a vector of an older copy. They are
//! a recomputable cache: the room's next media pass embeds the copy anew.
//!
//! A delete or erase of a record drops them the same way (FIX 9398): a
//! promotion keeps the room's copies of the vectors it replayed, byte-equal
//! to base's, and base's go with the record, so the room's must go too.
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::batch_op::BatchOp;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, Result};

use super::super::journal::JournalEntry;
use super::super::keyspace::{
    KeyspaceState, OverlayKeyspace, OverlayMutation, OverlayState, OverlayValue, drop_overlay_row,
};
use super::ACTIVE_SEGMENT;
use super::lifecycle::{OverlayLifecycleState, SessionOverlay};

impl SessionOverlay {
    /// Drops the room's cached media vectors of `ids`: the vault-meta rows
    /// at `keys` (their vector and device rows in every declared space) and
    /// every `MediaVector` journal entry of one of `ids`. Puts, texts, edges,
    /// turn ownership and every other entry stay.
    ///
    /// It runs inside the writer that changed the marks, or that deletes or
    /// erases one of `ids` (FIX 9398), before that writer commits, as a
    /// conservative invalidation: an aborted writer costs a refill, never
    /// content, and a dropped copy of a promoted record reads through to
    /// base's own. A room that holds none of them is left untouched: its
    /// state is not copied and its charge not recomputed. A segment this
    /// thread has installed on the overlay loses the same staged rows and
    /// entries; another thread's segment, whose base write committed before
    /// this writer began, is published first, so an older commit cannot
    /// bring a dropped row back. It never refuses the writer: an overlay
    /// already gone is left as it is.
    ///
    /// # Errors
    /// Only a poisoned overlay lock.
    pub fn invalidate_repo_media_copies(
        self: &Arc<Self>,
        keys: &BTreeSet<Vec<u8>>,
        ids: &BTreeSet<EntityId>,
    ) -> Result<()> {
        let stale = |entry: &JournalEntry| matches!(&entry.op, BatchOp::MediaVector { id, .. } if ids.contains(id));
        let same_thread = ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(segment) = slot
                .as_mut()
                .filter(|segment| Arc::ptr_eq(&segment.overlay, self))
            else {
                return false;
            };
            segment
                .mutations
                .retain(|mutation| !stages_row(mutation, keys));
            segment.journal.retain(|entry| !stale(entry));
            segment.journal_bytes = segment
                .journal
                .iter()
                .map(JournalEntry::byte_size)
                .fold(0_usize, usize::saturating_add);
            let mut preview = segment.preview.as_ref().clone();
            drop_rows(&mut preview, keys, &stale);
            segment.preview = Arc::new(preview);
            true
        });
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        // Base writer -> segment permit is the order every writer keeps; a
        // segment holder has released the base writer and only publishes.
        while !same_thread
            && lifecycle.segment_active
            && lifecycle.state != OverlayLifecycleState::Gone
        {
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        if lifecycle.state == OverlayLifecycleState::Gone {
            return Ok(());
        }
        let current = self.state.load_full();
        if !same_thread && !holds_rows(&current, keys, &stale) {
            return Ok(());
        }
        let mut next = current.as_ref().clone();
        drop_rows(&mut next, keys, &stale);
        self.state.store(Arc::new(next));
        drop(lifecycle);
        // A room stretch's charge follows what its overlay retains, this
        // thread's segment included (FIX 5991, 10104).
        self.charge_now();
        Ok(())
    }
}

/// Whether `state` stages a vault-meta row or a bookkeeping mark at one of
/// `keys`, or holds a `stale` journal entry: what [`drop_rows`] would drop.
fn holds_rows(
    state: &OverlayState,
    keys: &BTreeSet<Vec<u8>>,
    stale: &impl Fn(&JournalEntry) -> bool,
) -> bool {
    let slot = OverlayKeyspace::VaultMeta.slot();
    let staged = match state.keyspaces[slot].as_ref() {
        KeyspaceState::Single { rows, .. } => keys
            .iter()
            .any(|key| matches!(rows.get(key.as_slice()), Some(OverlayValue::Present(_)))),
        KeyspaceState::DupSort { .. } => false,
    };
    staged
        || state
            .bookkeeping
            .get(&slot)
            .is_some_and(|marked| keys.iter().any(|key| marked.contains(key)))
        || state.journal.iter().any(|entry| stale(&**entry))
}

/// Drops the vault-meta rows at `keys`, their bookkeeping marks and every
/// `stale` journal entry from `state`.
fn drop_rows(
    state: &mut OverlayState,
    keys: &BTreeSet<Vec<u8>>,
    stale: &impl Fn(&JournalEntry) -> bool,
) {
    for key in keys {
        drop_overlay_row(state, OverlayKeyspace::VaultMeta, key);
    }
    if let Some(marked) =
        Arc::make_mut(&mut state.bookkeeping).get_mut(&OverlayKeyspace::VaultMeta.slot())
    {
        marked.retain(|key| !keys.contains(key));
    }
    Arc::make_mut(&mut state.journal).retain(|entry| !stale(&**entry));
    state.recalculate_bytes();
}

/// Whether `mutation` stages (or marks as bookkeeping) a vault-meta row at
/// one of `keys`.
fn stages_row(mutation: &OverlayMutation, keys: &BTreeSet<Vec<u8>>) -> bool {
    match mutation {
        OverlayMutation::Put {
            keyspace: OverlayKeyspace::VaultMeta,
            key,
            ..
        }
        | OverlayMutation::Bookkeeping {
            keyspace: OverlayKeyspace::VaultMeta,
            key,
        } => keys.contains(key),
        _ => false,
    }
}
