//! A room's copies of a deleted or erased record's retrieval rows (FIX
//! 17382). A promotion keeps the rows its replay wrote byte-equal to base's:
//! the record's text index rows (postings, forward record, document meta,
//! field lengths, index source), its vector and its HNSW node, and the
//! room-scoped totals that count them. A delete or erase of the record takes
//! base's own; the room's copies go in the same writer, beside its media
//! copies ([`super::repo_projection`], FIX 9398), so no room keeps the
//! record's words, source fields or embedding until it closes.
//!
//! What goes, for each record the room holds no entity row of (a room that
//! staged one of its own keeps it all: that copy is the room's):
//! - every row keyed by the record: forward record, document meta, field
//!   lengths, vector, HNSW node, index source and one-way exception record;
//! - its duplicate in every term's postings, the term's others kept;
//! - its share of the room's totals, taken out once, by what its own rows
//!   counted: each field's document count and length, the document total and
//!   the graph's node count;
//! - its id in every other node's neighbour list and exception record, and
//!   as the room's entry point, which passes to another node the room holds
//!   with its vector, or else back to base's;
//! - its `Text` and `Vector` journal entries, so no later promotion indexes
//!   it again.
//!
//! The room's totals are absolute snapshots, so a total the room stages
//! loses the record's share and a total it reads from base is left alone:
//! base's erase already took its share there.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use zeroize::Zeroize;

use crate::batch_op::BatchOp;
use crate::text_index::codec::decode_field_lengths;
use crate::text_index::{FIELD_STATS_LEN, TOTAL_DOCS_KEY};
use crate::vector_index::keys::{COUNT_KEY, ENTRY_POINT_KEY, ONE_WAY_EXCEPTION_PREFIX};
use oneiron_contracts::entity_id::{ENTITY_ID_LEN, EntityId};
use oneiron_contracts::error::{Error, Result};

use super::super::journal::JournalEntry;
use super::super::keyspace::{
    KeyspaceState, OverlayKeyspace, OverlayMutation, OverlayState, OverlayValue, drop_overlay_row,
};
use super::ACTIVE_SEGMENT;
use super::lifecycle::{OverlayLifecycleState, SessionOverlay};

/// The vault-meta prefix of a record's index source fields.
const INDEX_SOURCE_TEXT_PREFIX: &[u8] = b"index_source:text:v1:";

/// The keyspaces whose row of a record is keyed by its id alone.
const RECORD_ROWS: [OverlayKeyspace; 5] = [
    OverlayKeyspace::TextForward,
    OverlayKeyspace::TextMeta,
    OverlayKeyspace::TextDocFieldLengths,
    OverlayKeyspace::Vectors,
    OverlayKeyspace::HnswNeighbors,
];

impl SessionOverlay {
    /// Drops the room's copies of the retrieval rows of `ids` and their share
    /// of its totals (module docs). It runs inside the writer that deletes or
    /// erases one of `ids`, before that writer commits, as the media drop
    /// does: an aborted writer costs the room a read through to base, never
    /// content. A room that holds none of them is left untouched. A segment
    /// this thread has installed on the overlay loses the same rows and its
    /// pending totals the same share; another thread's segment, whose base
    /// write committed before this writer began, is published first. It never
    /// refuses the writer: an overlay already gone is left as it is.
    ///
    /// # Errors
    /// Only a poisoned overlay lock.
    pub fn invalidate_retrieval_copies(self: &Arc<Self>, ids: &BTreeSet<EntityId>) -> Result<()> {
        let same_thread = ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(segment) = slot
                .as_mut()
                .filter(|segment| Arc::ptr_eq(&segment.overlay, self))
            else {
                return false;
            };
            let scrub = Scrub::of(&segment.preview, ids);
            if scrub.is_empty() {
                return true;
            }
            segment
                .mutations
                .retain_mut(|mutation| scrub.keeps_mutation(mutation));
            segment.journal.retain(|entry| !scrub.stale(entry));
            segment.journal_bytes = segment
                .journal
                .iter()
                .map(JournalEntry::byte_size)
                .fold(0_usize, usize::saturating_add);
            let mut preview = segment.preview.as_ref().clone();
            scrub.apply(&mut preview);
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
        let scrub = Scrub::of(&current, ids);
        if !same_thread && scrub.is_empty() {
            return Ok(());
        }
        if !scrub.is_empty() {
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

/// What one room state gives up for a set of records.
#[derive(Default)]
struct Scrub {
    /// The records whose copies go, by their id bytes.
    ids: BTreeSet<[u8; ENTITY_ID_LEN]>,
    /// Each field's documents and length the room's totals take back.
    fields: BTreeMap<u16, (u32, u64)>,
    /// The documents the room's document total takes back.
    docs: u32,
    /// The nodes the room's graph count takes back.
    nodes: u64,
}

impl Scrub {
    /// The records of `ids` whose copies `state` holds and no entity row of,
    /// with their share of its totals, read from their own rows.
    fn of(state: &OverlayState, ids: &BTreeSet<EntityId>) -> Self {
        let mut scrub = Self::default();
        for id in ids {
            let key = *id.as_bytes();
            if present(state, OverlayKeyspace::Entities, &key).is_some()
                || !holds_copy(state, id)
            {
                continue;
            }
            scrub.ids.insert(key);
            if let Some(lengths) = present(state, OverlayKeyspace::TextDocFieldLengths, &key)
                .and_then(|raw| decode_field_lengths(raw).ok())
            {
                for (field, length) in lengths {
                    let share = scrub.fields.entry(field).or_default();
                    share.0 = share.0.saturating_add(1);
                    share.1 = share.1.saturating_add(u64::from(length));
                }
            }
            if present(state, OverlayKeyspace::TextMeta, &key).is_some() {
                scrub.docs = scrub.docs.saturating_add(1);
            }
            if present(state, OverlayKeyspace::HnswNeighbors, &key).is_some() {
                scrub.nodes = scrub.nodes.saturating_add(1);
            }
        }
        scrub
    }

    fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    fn names(&self, id: &[u8]) -> bool {
        <[u8; ENTITY_ID_LEN]>::try_from(id).is_ok_and(|id| self.ids.contains(&id))
    }

    /// Whether `entry` indexes one of the records again on promotion.
    fn stale(&self, entry: &JournalEntry) -> bool {
        indexed(entry).is_some_and(|id| self.names(id.as_bytes()))
    }

    /// Takes the records' rows, duplicates, journal entries and share of the
    /// totals out of `state`.
    fn apply(&self, state: &mut OverlayState) {
        for id in &self.ids {
            for keyspace in RECORD_ROWS {
                drop_overlay_row(state, keyspace, id);
            }
            drop_overlay_row(state, OverlayKeyspace::VaultMeta, &source_key(id));
            drop_overlay_row(state, OverlayKeyspace::HnswMeta, &exception_key(id));
        }
        self.drop_postings(state);
        for field in self.fields.keys() {
            let key = field.to_be_bytes();
            self.rewrite(state, OverlayKeyspace::TextBm25FieldStats, &key);
        }
        self.rewrite(state, OverlayKeyspace::TextMeta, &TOTAL_DOCS_KEY);
        self.rewrite(state, OverlayKeyspace::HnswMeta, COUNT_KEY);
        for key in listed_keys(state, OverlayKeyspace::HnswNeighbors) {
            self.rewrite(state, OverlayKeyspace::HnswNeighbors, &key);
        }
        let exceptions = listed_keys(state, OverlayKeyspace::HnswMeta)
            .into_iter()
            .filter(|key| key.starts_with(ONE_WAY_EXCEPTION_PREFIX));
        for key in exceptions {
            self.rewrite(state, OverlayKeyspace::HnswMeta, &key);
        }
        self.repair_entry_point(state);
        Arc::make_mut(&mut state.journal).retain(|entry| !self.stale(entry));
        state.recalculate_bytes();
    }

    /// Removes each record's duplicate from every term's postings; a term left
    /// with nothing of its own goes.
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
            for identity in gone {
                if let Some((mut identity, mut value)) = delta.present.remove_entry(&identity) {
                    identity.zeroize();
                    value.zeroize();
                }
            }
            if delta.present.is_empty() && delta.deleted.is_empty() && !delta.delete_base {
                emptied.push(term.clone());
            }
        }
        for term in emptied {
            if let Some((mut term, delta)) = rows.remove_entry(&term) {
                term.zeroize();
                drop(delta);
            }
        }
    }

    /// Writes back the row at `key` with the records taken out of it, when
    /// the room stages it and it names them or counts them.
    fn rewrite(&self, state: &mut OverlayState, keyspace: OverlayKeyspace, key: &[u8]) {
        let Some(value) = present(state, keyspace, key) else {
            return;
        };
        let Some(next) = self.rewritten(keyspace, key, value) else {
            return;
        };
        put_row(state, keyspace, key, next);
    }

    /// The value of the shared row `key` with the records taken out: their
    /// share of a total, or their id out of a neighbour or holder list.
    /// `None` when the row names and counts none of them, or does not read.
    fn rewritten(&self, keyspace: OverlayKeyspace, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        match keyspace {
            OverlayKeyspace::TextBm25FieldStats => {
                let field = u16::from_be_bytes(key.try_into().ok()?);
                let (docs, length) = *self.fields.get(&field)?;
                let stats: [u8; FIELD_STATS_LEN] = value.try_into().ok()?;
                let count = u32::from_le_bytes(stats[..4].try_into().ok()?);
                let total = u64::from_le_bytes(stats[4..].try_into().ok()?);
                let mut next = Vec::with_capacity(FIELD_STATS_LEN);
                next.extend_from_slice(&count.saturating_sub(docs).to_le_bytes());
                next.extend_from_slice(&total.saturating_sub(length).to_le_bytes());
                Some(next)
            }
            OverlayKeyspace::TextMeta if key == TOTAL_DOCS_KEY && self.docs > 0 => {
                let total = u32::from_le_bytes(value.try_into().ok()?);
                Some(total.saturating_sub(self.docs).to_le_bytes().to_vec())
            }
            OverlayKeyspace::HnswMeta if key == COUNT_KEY && self.nodes > 0 => {
                let count = u64::from_le_bytes(value.try_into().ok()?);
                Some(count.saturating_sub(self.nodes).to_le_bytes().to_vec())
            }
            OverlayKeyspace::HnswNeighbors if !self.names(key) => self.without_ids(value),
            OverlayKeyspace::HnswMeta
                if key
                    .strip_prefix(ONE_WAY_EXCEPTION_PREFIX)
                    .is_some_and(|target| target.len() == ENTITY_ID_LEN && !self.names(target)) =>
            {
                self.without_ids(value)
            }
            _ => None,
        }
    }

    /// `list`, a run of ids, without the records; `None` when it names none
    /// of them or is no run of ids.
    fn without_ids(&self, list: &[u8]) -> Option<Vec<u8>> {
        let (ids, rest) = list.as_chunks::<ENTITY_ID_LEN>();
        if !rest.is_empty() || !ids.iter().any(|id| self.ids.contains(id)) {
            return None;
        }
        Some(
            ids.iter()
                .filter(|id| !self.ids.contains(*id))
                .flatten()
                .copied()
                .collect(),
        )
    }

    /// The room's entry point, when it names one of the records, passes to
    /// another node the room holds with its vector, or else back to base's.
    fn repair_entry_point(&self, state: &mut OverlayState) {
        let Some(entry) = present(state, OverlayKeyspace::HnswMeta, ENTRY_POINT_KEY) else {
            return;
        };
        if !self.names(entry) {
            return;
        }
        let next = listed_keys(state, OverlayKeyspace::HnswNeighbors)
            .into_iter()
            .find(|node| {
                !self.names(node) && present(state, OverlayKeyspace::Vectors, node).is_some()
            });
        match next {
            Some(node) => put_row(state, OverlayKeyspace::HnswMeta, ENTRY_POINT_KEY, node),
            None => drop_overlay_row(state, OverlayKeyspace::HnswMeta, ENTRY_POINT_KEY),
        }
    }

    /// Whether a pending write of this thread's segment stays: one that
    /// writes a record's own row or duplicate goes, and one that writes a
    /// shared row writes it with the records taken out.
    fn keeps_mutation(&self, mutation: &mut OverlayMutation) -> bool {
        let OverlayMutation::Put {
            keyspace,
            key,
            value,
        } = mutation
        else {
            return true;
        };
        let keyspace = *keyspace;
        let own = match keyspace {
            OverlayKeyspace::TextPostings => {
                self.names(value.get(..ENTITY_ID_LEN).unwrap_or_default())
            }
            OverlayKeyspace::VaultMeta => key
                .strip_prefix(INDEX_SOURCE_TEXT_PREFIX)
                .is_some_and(|id| self.names(id)),
            OverlayKeyspace::HnswMeta if key.as_slice() == ENTRY_POINT_KEY => self.names(value),
            OverlayKeyspace::HnswMeta => key
                .strip_prefix(ONE_WAY_EXCEPTION_PREFIX)
                .is_some_and(|target| self.names(target)),
            _ => RECORD_ROWS.contains(&keyspace) && self.names(key),
        };
        if own {
            return false;
        }
        if let Some(mut next) = self.rewritten(keyspace, key, value) {
            std::mem::swap(value, &mut next);
            next.zeroize();
        }
        true
    }
}

/// The record whose text or vector `entry` indexes, when it indexes one.
fn indexed(entry: &JournalEntry) -> Option<&EntityId> {
    match &entry.op {
        BatchOp::Text { id, .. } | BatchOp::Vector { id, .. } => Some(id),
        _ => None,
    }
}

/// Whether `state` holds any copy of `id`'s retrieval rows.
fn holds_copy(state: &OverlayState, id: &EntityId) -> bool {
    let key = id.as_bytes();
    RECORD_ROWS
        .iter()
        .any(|keyspace| present(state, *keyspace, key).is_some())
        || present(state, OverlayKeyspace::VaultMeta, &source_key(key)).is_some()
        || present(state, OverlayKeyspace::HnswMeta, &exception_key(key)).is_some()
        || state.journal.iter().any(|entry| indexed(entry) == Some(id))
        || match state.keyspaces[OverlayKeyspace::TextPostings.slot()].as_ref() {
            KeyspaceState::DupSort { rows, .. } => rows
                .values()
                .any(|delta| delta.present.contains_key(key.as_slice())),
            KeyspaceState::Single { .. } => false,
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

/// Stages `value` at `key` of the single-valued `keyspace`; the old body
/// scrubs on drop.
fn put_row(state: &mut OverlayState, keyspace: OverlayKeyspace, key: &[u8], value: Vec<u8>) {
    if let KeyspaceState::Single { rows, .. } = Arc::make_mut(&mut state.keyspaces[keyspace.slot()])
    {
        match rows.get_mut(key) {
            Some(old) => *old = OverlayValue::Present(value),
            None => {
                rows.insert(key.to_vec(), OverlayValue::Present(value));
            }
        }
    }
}

/// The keys of every row `state` stages in the single-valued `keyspace`.
fn listed_keys(state: &OverlayState, keyspace: OverlayKeyspace) -> Vec<Vec<u8>> {
    match state.keyspaces[keyspace.slot()].as_ref() {
        KeyspaceState::Single { rows, .. } => rows
            .iter()
            .filter(|(_, value)| matches!(value, OverlayValue::Present(_)))
            .map(|(key, _)| key.clone())
            .collect(),
        KeyspaceState::DupSort { .. } => Vec::new(),
    }
}

/// The vault-meta key of `id`'s index source fields.
fn source_key(id: &[u8]) -> Vec<u8> {
    let mut key = INDEX_SOURCE_TEXT_PREFIX.to_vec();
    key.extend_from_slice(id);
    key
}

/// The HNSW meta key of the one-way exception record of `id`.
fn exception_key(id: &[u8]) -> Vec<u8> {
    let mut key = ONE_WAY_EXCEPTION_PREFIX.to_vec();
    key.extend_from_slice(id);
    key
}
