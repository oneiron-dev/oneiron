//! Room-staged media vectors a later mark makes stale (FIX 7608 S3F, FIX
//! 10407): the room's cached vectors of a record whose bytes a mask change
//! reaches are dropped, rows and journal entries both, so neither a
//! composed read nor a promotion serves a vector of an older copy. They are
//! a recomputable cache: the room's next media pass embeds the copy anew.
//!
//! A delete or erase of a record drops them the same way (FIX 9398): a
//! promotion keeps the room's copies of the vectors it replayed, byte-equal
//! to base's, and base's go with the record, so the room's must go too. The
//! copies are found by what the room stages, in every space, so a space
//! retired since cannot keep one.
use std::collections::BTreeSet;
use std::ops::Bound;
use std::sync::Arc;

use crate::batch_op::BatchOp;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, Result};

use crate::side_table::key::SideKey;

use super::super::journal::JournalEntry;
use super::super::keyspace::{
    KeyspaceState, OverlayKeyspace, OverlayMutation, OverlayState, OverlayValue, drop_overlay_row,
};
use super::ACTIVE_SEGMENT;
use super::lifecycle::{OverlayLifecycleState, SessionOverlay};

impl SessionOverlay {
    /// Drops the room's cached media vectors of `ids`: every vault-meta row
    /// it stages under one of `prefixes` as a copy of one of `ids` (a row key
    /// is a prefix, then a `([u8; 16], EntityId)` side-table key: the space
    /// key and the record), in any space, declared or retired since, with its
    /// bookkeeping mark, and every `MediaVector` journal entry of one of
    /// `ids`. Puts, texts, edges, turn ownership and every other entry stay.
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
        prefixes: &[&[u8]],
        ids: &BTreeSet<EntityId>,
    ) -> Result<()> {
        let stale = |entry: &JournalEntry| matches!(&entry.op, BatchOp::MediaVector { id, .. } if ids.contains(id));
        let key_match = |key: &[u8]| copy_of(key, prefixes, ids);
        self.invalidate_matching(prefixes, &key_match, &stale)
    }

    /// Drops staged media rows and journal entries for a retired space.
    /// Rows use `space_key`; journal entries use `space_id`. Other spaces stay.
    /// Run inside the retiring writer, before commit, as with record invalidation.
    ///
    /// # Errors
    /// Only a poisoned overlay lock.
    pub fn invalidate_repo_media_space_copies(
        self: &Arc<Self>,
        prefixes: &[&[u8]],
        space_key: &[u8; 16],
        space_id: &str,
    ) -> Result<()> {
        let key_match = |key: &[u8]| space_copy_of(key, prefixes, space_key);
        let stale = |entry: &JournalEntry| matches!(&entry.op, BatchOp::MediaVector { space, .. } if space.as_str() == space_id);
        self.invalidate_matching(prefixes, &key_match, &stale)
    }

    fn invalidate_matching(
        self: &Arc<Self>,
        prefixes: &[&[u8]],
        key_match: &impl Fn(&[u8]) -> bool,
        stale: &impl Fn(&JournalEntry) -> bool,
    ) -> Result<()> {
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
                .retain(|mutation| !stages_copy(mutation, key_match));
            segment.journal.retain(|entry| !stale(entry));
            segment.journal_bytes = segment
                .journal
                .iter()
                .map(JournalEntry::byte_size)
                .fold(0_usize, usize::saturating_add);
            let keys = staged_copies(&segment.preview, prefixes, key_match);
            let mut preview = segment.preview.as_ref().clone();
            drop_rows(&mut preview, &keys, stale);
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
        let keys = staged_copies(&current, prefixes, key_match);
        if !same_thread && keys.is_empty() && !current.journal.iter().any(|entry| stale(&**entry)) {
            return Ok(());
        }
        let mut next = current.as_ref().clone();
        drop_rows(&mut next, &keys, stale);
        self.state.store(Arc::new(next));
        drop(lifecycle);
        // A room stretch's charge follows what its overlay retains, this
        // thread's segment included (FIX 5991, 10104).
        self.charge_now();
        Ok(())
    }
}

/// Whether `key` is a copy of one of `ids`: one of `prefixes`, then a
/// `([u8; 16], EntityId)` side-table key naming one of them.
fn copy_of(key: &[u8], prefixes: &[&[u8]], ids: &BTreeSet<EntityId>) -> bool {
    prefixes.iter().any(|prefix| {
        key.strip_prefix(*prefix)
            .and_then(<([u8; 16], EntityId) as SideKey>::decode_key)
            .is_some_and(|(_, id)| ids.contains(&id))
    })
}

/// Whether a media row belongs to `space_key`, regardless of its record.
fn space_copy_of(key: &[u8], prefixes: &[&[u8]], space_key: &[u8; 16]) -> bool {
    prefixes.iter().any(|prefix| {
        key.strip_prefix(*prefix)
            .and_then(<([u8; 16], EntityId) as SideKey>::decode_key)
            .is_some_and(|(key, _)| &key == space_key)
    })
}

/// The key of every vault-meta row `state` stages, or marks as bookkeeping,
/// matching `key_match` under one of `prefixes`.
fn staged_copies(
    state: &OverlayState,
    prefixes: &[&[u8]],
    key_match: &impl Fn(&[u8]) -> bool,
) -> BTreeSet<Vec<u8>> {
    let slot = OverlayKeyspace::VaultMeta.slot();
    let mut keys = BTreeSet::new();
    for prefix in prefixes {
        let from = (Bound::Included(*prefix), Bound::Unbounded);
        if let KeyspaceState::Single { rows, .. } = state.keyspaces[slot].as_ref() {
            keys.extend(
                rows.range::<[u8], _>(from)
                    .take_while(|(key, _)| key.starts_with(prefix))
                    .filter(|(key, value)| {
                        matches!(value, OverlayValue::Present(_)) && key_match(key)
                    })
                    .map(|(key, _)| key.clone()),
            );
        }
        if let Some(marked) = state.bookkeeping.get(&slot) {
            keys.extend(
                marked
                    .range::<[u8], _>(from)
                    .take_while(|key| key.starts_with(prefix))
                    .filter(|key| key_match(key))
                    .cloned(),
            );
        }
    }
    keys
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

/// Whether `mutation` stages (or marks as bookkeeping) a vault-meta row
/// matching `key_match`.
fn stages_copy(mutation: &OverlayMutation, key_match: &impl Fn(&[u8]) -> bool) -> bool {
    match mutation {
        OverlayMutation::Put {
            keyspace: OverlayKeyspace::VaultMeta,
            key,
            ..
        }
        | OverlayMutation::Bookkeeping {
            keyspace: OverlayKeyspace::VaultMeta,
            key,
        } => key_match(key),
        _ => false,
    }
}
