//! A room's copies of a deleted or erased record's own retrieval rows (FIX
//! 17382). A promotion keeps the rows its replay wrote byte-equal to base's,
//! the record's text index rows and its vector among them. A delete or erase
//! of the record takes base's own; the room's copies of the rows that hold
//! the record's words, source fields and embedding go in the same writer,
//! beside its media copies ([`super::repo_projection`], FIX 9398).
//!
//! What goes, for each record the room holds no entity row of (a room that
//! staged one of its own keeps it all: that copy is the room's):
//! - its forward record (its words), document meta, field lengths, vector
//!   and phonetic codes, each keyed by its id;
//! - its vault-meta rows the engine names ([`RecordMetaRows`], FIX 19094):
//!   its index source fields, its revision state, its revision history
//!   document (every revision's raw row), each pinned frontier and each
//!   revision identity that names it, its pending index inputs and phonetic
//!   codes, and its embedding device mark;
//! - its duplicate, and its mask, in every term's postings, the term's
//!   other documents kept;
//! - its `Text`, `Vector` and `Phonetic` journal entries, so no later
//!   promotion indexes it again.
//!
//! A row of these the room no longer holds reads through to base's, which
//! is the record's truth while the room holds no entity row of it. The one
//! exception is a revision the room staged and never saved (a put a later
//! put replaced before a selected save): its frontier and its part of the
//! history document are the room's alone. They go too, since they hold the
//! record's body bytes; an aborted writer costs the room them, as it costs
//! the room the record's pending journal entries.
//!
//! What stays: the room's staged totals (each field's document count and
//! length, the document total), its HNSW rows and its phonetic postings. The
//! totals are room-scoped snapshots its scoring already reads as approximate
//! beside base, and the HNSW rows and phonetic postings hold ids only, each
//! posting the ids of every record with one code. A room's vector recall
//! walks base's graph and scores the vectors the room stages; its own graph
//! serves only its writes, whose walk skips a neighbour without its vector,
//! and whose insert, when no other node loads one, counts the vectorless
//! nodes it keeps (`hnsw::insert::start_room_graph`). Rewriting the totals,
//! the graph or a posting before the writer commits would leave them wrong
//! if it aborts.
use std::collections::BTreeSet;
use std::ops::Bound;
use std::sync::Arc;

use zeroize::Zeroize;

use crate::batch_op::BatchOp;
use oneiron_contracts::entity_id::{ENTITY_ID_LEN, EntityId};
use oneiron_contracts::error::{Error, Result};

use super::super::journal::JournalEntry;
use super::super::keyspace::{
    KeyspaceState, OverlayKeyspace, OverlayMutation, OverlayState, OverlayValue, drop_overlay_row,
};
use super::ACTIVE_SEGMENT;
use super::lifecycle::{OverlayLifecycleState, SessionOverlay};

/// The keyspaces whose row of a record is keyed by its id alone.
const RECORD_ROWS: [OverlayKeyspace; 5] = [
    OverlayKeyspace::TextForward,
    OverlayKeyspace::TextMeta,
    OverlayKeyspace::TextDocFieldLengths,
    OverlayKeyspace::Vectors,
    OverlayKeyspace::PhoneticForward,
];

/// The vault-meta rows the engine keeps of one record, by side-table prefix
/// (FIX 19094). This crate does not declare the engine's side tables, so the
/// engine names them, as it names its media rows
/// ([`SessionOverlay::invalidate_repo_media_copies`]).
#[derive(Clone, Copy, Debug)]
pub struct RecordMetaRows<'p> {
    /// Rows keyed by the record's id alone: the prefix, then its 16 bytes.
    pub keyed: &'p [&'p [u8]],
    /// Rows keyed by the record's id and more: the prefix, its 16 bytes,
    /// then the rest of the key.
    pub scoped: &'p [&'p [u8]],
    /// Rows that name the record in their value: the prefix and any key,
    /// the value its 16 bytes.
    pub reverse: &'p [&'p [u8]],
}

impl<'p> RecordMetaRows<'p> {
    /// Every prefix it names.
    fn prefixes(self) -> impl Iterator<Item = &'p [u8]> {
        self.keyed
            .iter()
            .chain(self.scoped)
            .chain(self.reverse)
            .copied()
    }
}

impl SessionOverlay {
    /// Drops the room's copies of the own retrieval rows of `ids`, and of
    /// their vault-meta rows `meta` names (module docs). It runs inside the
    /// writer that deletes or erases one of `ids`, before that writer
    /// commits, as the media drop does: an aborted writer costs the room a
    /// read through to base's rows, which it still holds (a posting the room
    /// masked shows again), and the pending `Text`, `Vector` or `Phonetic`
    /// entry of a record and the revisions of it the room alone holds (module
    /// docs), never a shared row. A room that holds none
    /// of them is left untouched. A segment this thread has installed on the
    /// overlay loses the same rows and entries,
    /// and a record that segment stages an entity row of is kept in both;
    /// another thread's segment, whose base write committed before this
    /// writer began, is published first. It never refuses the writer: an
    /// overlay already gone is left as it is.
    ///
    /// # Errors
    /// Only a poisoned overlay lock.
    pub fn invalidate_retrieval_copies(
        self: &Arc<Self>,
        meta: RecordMetaRows<'_>,
        ids: &BTreeSet<EntityId>,
    ) -> Result<()> {
        let segment = ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let segment = slot
                .as_mut()
                .filter(|segment| Arc::ptr_eq(&segment.overlay, self))?;
            let private = staged_entities(&segment.preview, ids);
            let scrub = Scrub::of(&segment.preview, meta, ids, &private);
            let pending = segment
                .mutations
                .iter()
                .any(|mutation| scrub.writes(mutation))
                || segment.journal.iter().any(|entry| scrub.stale(entry));
            if pending || scrub.held_by(&segment.preview) {
                segment.mutations.retain(|mutation| !scrub.writes(mutation));
                segment.journal.retain(|entry| !scrub.stale(entry));
                segment.journal_bytes = segment
                    .journal
                    .iter()
                    .map(JournalEntry::byte_size)
                    .fold(0_usize, usize::saturating_add);
                let mut preview = segment.preview.as_ref().clone();
                scrub.apply(&mut preview);
                segment.preview = Arc::new(preview);
            }
            Some(private)
        });
        let same_thread = segment.is_some();
        let private = segment.unwrap_or_default();
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
        let scrub = Scrub::of(&current, meta, ids, &private);
        let held = scrub.held_by(&current);
        if !same_thread && !held {
            return Ok(());
        }
        if held {
            let mut next = current.as_ref().clone();
            scrub.apply(&mut next);
            self.state.store(Arc::new(next));
        }
        drop(lifecycle);
        // A room stretch's charge follows what its overlay retains, this
        // thread's segment included (FIX 5991, 10104).
        self.charge_now();
        Ok(())
    }
}

/// The records of `ids` `state` stages an entity row of: the room's own.
fn staged_entities(state: &OverlayState, ids: &BTreeSet<EntityId>) -> BTreeSet<EntityId> {
    ids.iter()
        .filter(|id| present(state, OverlayKeyspace::Entities, id.as_bytes()).is_some())
        .copied()
        .collect()
}

/// The records whose copies one room state gives up.
struct Scrub<'p> {
    /// Their id bytes.
    ids: BTreeSet<[u8; ENTITY_ID_LEN]>,
    /// The vault-meta rows the engine keeps of a record.
    meta: RecordMetaRows<'p>,
}

impl<'p> Scrub<'p> {
    /// The records of `ids` neither `state` nor `private` stages an entity
    /// row of.
    fn of(
        state: &OverlayState,
        meta: RecordMetaRows<'p>,
        ids: &BTreeSet<EntityId>,
        private: &BTreeSet<EntityId>,
    ) -> Self {
        let own = staged_entities(state, ids);
        Self {
            ids: ids
                .iter()
                .filter(|id| !own.contains(id) && !private.contains(id))
                .map(|id| *id.as_bytes())
                .collect(),
            meta,
        }
    }

    fn names(&self, id: &[u8]) -> bool {
        <[u8; ENTITY_ID_LEN]>::try_from(id).is_ok_and(|id| self.ids.contains(&id))
    }

    /// Whether the vault-meta row at `key`, holding `value`, is one of the
    /// records' own rows [`RecordMetaRows`] names.
    fn meta_row(&self, key: &[u8], value: &[u8]) -> bool {
        self.meta
            .keyed
            .iter()
            .any(|prefix| key.strip_prefix(*prefix).is_some_and(|id| self.names(id)))
            || self.meta.scoped.iter().any(|prefix| {
                key.strip_prefix(*prefix)
                    .and_then(|rest| rest.get(..ENTITY_ID_LEN))
                    .is_some_and(|id| self.names(id))
            })
            || self
                .meta
                .reverse
                .iter()
                .any(|prefix| key.starts_with(prefix) && self.names(value))
    }

    /// The key of every one of the records' own vault-meta rows `state`
    /// stages.
    fn meta_keys(&self, state: &OverlayState) -> BTreeSet<Vec<u8>> {
        let mut keys = BTreeSet::new();
        if self.ids.is_empty() {
            return keys;
        }
        let KeyspaceState::Single { rows, .. } =
            state.keyspaces[OverlayKeyspace::VaultMeta.slot()].as_ref()
        else {
            return keys;
        };
        for prefix in self.meta.prefixes() {
            keys.extend(
                rows.range::<[u8], _>((Bound::Included(prefix), Bound::Unbounded))
                    .take_while(|(key, _)| key.starts_with(prefix))
                    .filter_map(|(key, value)| match value {
                        OverlayValue::Present(value) if self.meta_row(key, value) => {
                            Some(key.clone())
                        }
                        OverlayValue::Present(_) | OverlayValue::Tombstone => None,
                    }),
            );
        }
        keys
    }

    /// Whether `entry` indexes one of the records again on promotion.
    fn stale(&self, entry: &JournalEntry) -> bool {
        indexed(entry).is_some_and(|id| self.names(id.as_bytes()))
    }

    /// Whether `state` holds any copy this takes out.
    fn held_by(&self, state: &OverlayState) -> bool {
        if self.ids.is_empty() {
            return false;
        }
        let rows = self.ids.iter().any(|id| {
            RECORD_ROWS
                .iter()
                .any(|keyspace| present(state, *keyspace, id).is_some())
        }) || !self.meta_keys(state).is_empty();
        let postings = match state.keyspaces[OverlayKeyspace::TextPostings.slot()].as_ref() {
            KeyspaceState::DupSort { rows, .. } => rows.values().any(|delta| {
                delta.present.keys().any(|identity| self.names(identity))
                    || delta
                        .deleted
                        .iter()
                        .any(|value| self.names(identity_of(value)))
            }),
            KeyspaceState::Single { .. } => false,
        };
        rows || postings || state.journal.iter().any(|entry| self.stale(entry))
    }

    /// Takes the records' own rows, posting duplicates and masks, and journal
    /// entries out of `state`.
    fn apply(&self, state: &mut OverlayState) {
        for id in &self.ids {
            for keyspace in RECORD_ROWS {
                drop_overlay_row(state, keyspace, id);
            }
        }
        self.drop_meta_rows(state);
        self.drop_postings(state);
        Arc::make_mut(&mut state.journal).retain(|entry| !self.stale(entry));
        state.recalculate_bytes();
    }

    /// Removes the records' own vault-meta rows, and any bookkeeping mark a
    /// write left on one.
    fn drop_meta_rows(&self, state: &mut OverlayState) {
        let keys = self.meta_keys(state);
        if keys.is_empty() {
            return;
        }
        let slot = OverlayKeyspace::VaultMeta.slot();
        if state
            .bookkeeping
            .get(&slot)
            .is_some_and(|marked| keys.iter().any(|key| marked.contains(key)))
            && let Some(marked) = Arc::make_mut(&mut state.bookkeeping).get_mut(&slot)
        {
            marked.retain(|key| !keys.contains(key));
        }
        for mut key in keys {
            drop_overlay_row(state, OverlayKeyspace::VaultMeta, &key);
            key.zeroize();
        }
    }

    /// Removes each record's duplicate and mask from every term's postings; a
    /// term left with nothing of its own goes.
    fn drop_postings(&self, state: &mut OverlayState) {
        let KeyspaceState::DupSort { rows, .. } =
            Arc::make_mut(&mut state.keyspaces[OverlayKeyspace::TextPostings.slot()])
        else {
            return;
        };
        let mut emptied = Vec::new();
        for (term, delta) in &mut *rows {
            let gone: Vec<Vec<u8>> = delta
                .present
                .keys()
                .filter(|identity| self.names(identity))
                .cloned()
                .collect();
            for mut identity in gone {
                if let Some((mut key, mut value)) = delta.present.remove_entry(&identity) {
                    key.zeroize();
                    value.zeroize();
                }
                identity.zeroize();
            }
            let masks: Vec<Vec<u8>> = delta
                .deleted
                .iter()
                .filter(|value| self.names(identity_of(value)))
                .cloned()
                .collect();
            for mut mask in masks {
                if let Some(mut value) = delta.deleted.take(&mask) {
                    value.zeroize();
                }
                mask.zeroize();
            }
            if delta.present.is_empty() && delta.deleted.is_empty() && !delta.delete_base {
                emptied.push(term.clone());
            }
        }
        for mut term in emptied {
            if let Some((mut key, delta)) = rows.remove_entry(&term) {
                key.zeroize();
                drop(delta);
            }
            term.zeroize();
        }
    }

    /// Whether a pending write of this thread's segment writes one of the
    /// records' own rows, or its posting duplicate or mask.
    fn writes(&self, mutation: &OverlayMutation) -> bool {
        match mutation {
            OverlayMutation::Put {
                keyspace: OverlayKeyspace::TextPostings,
                value,
                ..
            }
            | OverlayMutation::DeleteDuplicate {
                keyspace: OverlayKeyspace::TextPostings,
                value,
                ..
            } => self.names(identity_of(value)),
            OverlayMutation::Put {
                keyspace: OverlayKeyspace::VaultMeta,
                key,
                value,
            } => self.meta_row(key, value),
            OverlayMutation::Bookkeeping {
                keyspace: OverlayKeyspace::VaultMeta,
                key,
            } => self.meta_row(key, &[]),
            OverlayMutation::Put { keyspace, key, .. } => {
                RECORD_ROWS.contains(keyspace) && self.names(key)
            }
            _ => false,
        }
    }
}

/// The record a posting duplicate belongs to: its leading id bytes.
fn identity_of(value: &[u8]) -> &[u8] {
    value.get(..ENTITY_ID_LEN).unwrap_or_default()
}

/// The record whose text, vector or phonetic codes `entry` indexes, when it
/// indexes one.
fn indexed(entry: &JournalEntry) -> Option<&EntityId> {
    match &entry.op {
        BatchOp::Text { id, .. } | BatchOp::Vector { id, .. } | BatchOp::Phonetic { id, .. } => {
            Some(id)
        }
        _ => None,
    }
}

/// The row `state` stages at `key` of `keyspace`, when it stages one.
fn present<'s>(state: &'s OverlayState, keyspace: OverlayKeyspace, key: &[u8]) -> Option<&'s [u8]> {
    match state.keyspaces[keyspace.slot()].as_ref() {
        KeyspaceState::Single { rows, .. } => match rows.get(key) {
            Some(OverlayValue::Present(value)) => Some(value.as_slice()),
            Some(OverlayValue::Tombstone) | None => None,
        },
        KeyspaceState::DupSort { .. } => None,
    }
}
