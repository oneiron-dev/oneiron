//! The memory a room's overlay actually retains, the bytes its host's
//! retained-memory line is charged (FIX 10104): every row's key and value at
//! their capacity with its map node, the journal's slots, payloads and run
//! tokens, the bookkeeping marks, and a live segment's preview, mutations and
//! journal, the states live snapshots read and the copies live promotion
//! plans hold. A copy-on-write allocation two states share, or a run token
//! many entries share, counts once. The room's byte budget is apart and keeps
//! its exemptions: this counts what is held, never what the room may spend.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::mem::size_of;
use std::sync::Arc;

use super::super::journal::{JournalEntry, PromotePlan, PublishedEntry};
use super::super::keyspace::{
    DupDelta, KeyspaceState, OverlayMutation, OverlayState, OverlayValue,
};
use super::held::Held;
use super::segment::TxnSegment;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::skill_attribution::RunWriteToken;

/// A B-tree map or set entry's share of its node: room for a sparse node's
/// unused slots, the node header and its edges (as the host's room entry
/// bytes count one).
const MAP_ENTRY_OVERHEAD: usize = 32;

/// The strong and weak counts every `Arc` allocation carries.
const ARC_COUNTS: usize = 2 * size_of::<usize>();

/// The bytes counted so far, and the shared allocations already counted.
#[derive(Default)]
pub(super) struct Retained {
    seen: HashSet<usize>,
    bytes: usize,
}

impl Retained {
    /// The bytes counted.
    pub(super) const fn bytes(&self) -> usize {
        self.bytes
    }

    fn add(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes);
    }

    /// Whether the allocation at `address` is counted for the first time.
    fn first(&mut self, address: usize) -> bool {
        self.seen.insert(address)
    }

    /// One published or previewed state, each of its shared parts once.
    pub(super) fn state(&mut self, state: &Arc<OverlayState>) {
        if !self.first(Arc::as_ptr(state) as usize) {
            return;
        }
        self.add(ARC_COUNTS + size_of::<OverlayState>());
        for keyspace in &state.keyspaces {
            self.keyspace(keyspace);
        }
        if self.first(Arc::as_ptr(&state.journal) as usize) {
            self.add(ARC_COUNTS + size_of::<Vec<PublishedEntry>>());
            self.add(
                state
                    .journal
                    .capacity()
                    .saturating_mul(size_of::<PublishedEntry>()),
            );
            for entry in state.journal.iter() {
                self.entry_heap(entry);
            }
        }
        if self.first(Arc::as_ptr(&state.bookkeeping) as usize) {
            self.add(ARC_COUNTS + size_of::<BTreeMap<usize, BTreeSet<Vec<u8>>>>());
            for marked in state.bookkeeping.values() {
                self.add(MAP_ENTRY_OVERHEAD + size_of::<usize>() + size_of::<BTreeSet<Vec<u8>>>());
                for key in marked {
                    self.add(MAP_ENTRY_OVERHEAD + size_of::<Vec<u8>>() + key.capacity());
                }
            }
        }
    }

    /// A live segment: its preview, staged mutations and staged journal.
    pub(super) fn segment(&mut self, segment: &TxnSegment) {
        self.state(&segment.preview);
        self.add(
            segment
                .mutations
                .capacity()
                .saturating_mul(size_of::<OverlayMutation>()),
        );
        for mutation in &segment.mutations {
            self.add(mutation_heap(mutation));
        }
        self.add(
            segment
                .journal
                .capacity()
                .saturating_mul(size_of::<JournalEntry>()),
        );
        for entry in &segment.journal {
            self.entry_heap(entry);
        }
    }

    /// What live snapshots and promotion plans hold: each snapshot's
    /// state, each shared part once, and each plan's copies, its run
    /// tokens once beside the journal's.
    pub(super) fn held(&mut self, held: &Held) {
        for state in &held.states {
            self.state(state);
        }
        for plan in &held.plans {
            self.add(plan.bytes);
            for &(address, bytes) in &plan.tokens {
                if self.first(address) {
                    self.add(bytes);
                }
            }
        }
    }

    fn keyspace(&mut self, keyspace: &Arc<KeyspaceState>) {
        if !self.first(Arc::as_ptr(keyspace) as usize) {
            return;
        }
        self.add(ARC_COUNTS + size_of::<KeyspaceState>());
        match keyspace.as_ref() {
            KeyspaceState::Single { rows, .. } => {
                for (key, value) in rows {
                    let value = match value {
                        OverlayValue::Present(value) => value.capacity(),
                        OverlayValue::Tombstone => 0,
                    };
                    self.add(row_bytes::<OverlayValue>(key) + value);
                }
            }
            KeyspaceState::DupSort { rows, .. } => {
                for (key, delta) in rows {
                    self.add(row_bytes::<DupDelta>(key));
                    for (identity, value) in &delta.present {
                        self.add(row_bytes::<Vec<u8>>(identity) + value.capacity());
                    }
                    for value in &delta.deleted {
                        self.add(MAP_ENTRY_OVERHEAD + size_of::<Vec<u8>>() + value.capacity());
                    }
                }
            }
        }
    }

    /// One journal entry's heap beyond its slot: its op's payload, and its
    /// run token's allocation, once however many entries share it.
    fn entry_heap(&mut self, entry: &JournalEntry) {
        self.add(op_heap(&entry.op));
        if let Some(token) = &entry.source_run {
            let (address, bytes) = token.heap_allocation();
            if self.first(address) {
                self.add(bytes);
            }
        }
    }
}

/// A map row's node share, its key at capacity and its value's inline size.
fn row_bytes<V>(key: &Vec<u8>) -> usize {
    MAP_ENTRY_OVERHEAD + size_of::<Vec<u8>>() + key.capacity() + size_of::<V>()
}

/// The heap one staged mutation holds.
pub(super) fn mutation_heap(mutation: &OverlayMutation) -> usize {
    match mutation {
        OverlayMutation::Put { key, value, .. }
        | OverlayMutation::DeleteDuplicate { key, value, .. } => {
            key.capacity().saturating_add(value.capacity())
        }
        OverlayMutation::Delete { key, .. } | OverlayMutation::Bookkeeping { key, .. } => {
            key.capacity()
        }
        OverlayMutation::Clear { .. } => 0,
    }
}

/// The heap one journal entry about to be staged holds beyond its slot,
/// its run token counted whole.
pub(super) fn staged_entry_heap(entry: &JournalEntry) -> usize {
    let token = entry
        .source_run
        .as_ref()
        .map_or(0, |token| token.heap_allocation().1);
    size_of::<JournalEntry>()
        .saturating_add(op_heap(&entry.op))
        .saturating_add(token)
}

/// The heap a promotion plan copies out of the journal beyond its run
/// tokens: each replay op's slot and payload at capacity, its in-room
/// aliases, and the vectors of ids, windows, journal identities and run
/// tokens it builds.
pub(super) fn plan_heap(plan: &PromotePlan) -> usize {
    let ops = plan.ops.iter().fold(
        plan.ops.capacity().saturating_mul(size_of::<BatchOp>()),
        |bytes, op| bytes.saturating_add(op_heap(op)),
    );
    let aliases = plan.temporary_short_ids.iter().fold(
        plan.temporary_short_ids
            .capacity()
            .saturating_mul(size_of::<(EntityId, String)>()),
        |bytes, (_, alias)| bytes.saturating_add(alias.capacity()),
    );
    ops.saturating_add(aliases)
        .saturating_add(
            plan.replayed
                .capacity()
                .saturating_mul(size_of::<EntityId>()),
        )
        .saturating_add(
            plan.source_learned_at
                .capacity()
                .saturating_add(plan.cut_from.capacity())
                .saturating_mul(size_of::<u64>()),
        )
        .saturating_add(
            plan.source_runs
                .capacity()
                .saturating_mul(size_of::<Option<RunWriteToken>>()),
        )
}

/// The heap one journaled op's payload holds, at capacity. A journal stages
/// only puts, edges, text, vectors, media vectors and deletes.
fn op_heap(op: &BatchOp) -> usize {
    match op {
        BatchOp::Put { data, .. } => data.capacity(),
        BatchOp::Vector {
            vector,
            pending_embedding_token,
            ..
        } => vector
            .capacity()
            .saturating_mul(size_of::<f32>())
            .saturating_add(pending_embedding_token.as_ref().map_or(0, Vec::capacity)),
        BatchOp::Text { fields, .. } => fields.iter().fold(
            fields
                .capacity()
                .saturating_mul(size_of::<(String, String)>()),
            |bytes, (name, value)| {
                bytes
                    .saturating_add(name.capacity())
                    .saturating_add(value.capacity())
            },
        ),
        BatchOp::MediaVector { space, vector, .. } => vector
            .capacity()
            .saturating_mul(size_of::<f32>())
            .saturating_add(space.capacity()),
        _ => 0,
    }
}
