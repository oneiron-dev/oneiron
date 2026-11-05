//! Transaction-owner handoff for Dreamer VAD approvals and digest invalidation.
//!
//! `batch_in` receives a bare heed transaction, not its owner. Keep its pending
//! work scoped to that exact transaction and the vault's store on the
//! synchronous caller's thread, so a helper that holds only the store joins it
//! too. The owner drains it before commit and runs it only after commit.
//! Dropping the scope on error or unwind discards all work. Internal raw-transaction
//! owners retain their existing explicit postcommit hooks.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use crate::batch::builder::ops::BatchOp;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub type TransactionKey = (usize, usize);

#[derive(Default)]
pub struct PostcommitWork {
    pub vad_ids: BTreeSet<EntityId>,
    pub proactivity_changed: bool,
    /// TASKs this transaction wrote, announced only after it commits.
    pub task_ids: BTreeSet<EntityId>,
    /// Rows this transaction wrote (puts, and the sources of edges it wrote),
    /// mirrored into the live sync windows only after it commits.
    pub rows: BTreeSet<EntityId>,
    /// Room joins this transaction filed, by their bare join refs, pushed to
    /// the live windows of their rooms or threads only after it commits.
    pub room_joins: BTreeSet<String>,
    /// Windows a WORLD delete staged its pads' `pt:` tombstones in, published
    /// only after the transaction commits (FIX 3334).
    pub pad_windows: BTreeSet<String>,
    /// TASKs this transaction settled, whose peer-result waiters wake only
    /// after it commits (FIX 1140).
    pub settled_tasks: BTreeSet<EntityId>,
    /// Whether this transaction put or marked a notification, whose live
    /// queries wake only after it commits (FIX 3084).
    pub notifications_changed: bool,
    /// NOTE documents invalidated only after this transaction commits.
    pub note_document_ids: BTreeSet<EntityId>,
}

thread_local! {
    static PENDING_VAD: RefCell<BTreeMap<TransactionKey, PostcommitWork>> =
        const { RefCell::new(BTreeMap::new()) };
}

pub fn store_transaction_key<S>(store: &S, txn: &RwTxn<'_>) -> TransactionKey {
    // Identity only: neither address is dereferenced or retained past the scope.
    (
        std::ptr::from_ref(store) as usize,
        std::ptr::from_ref(txn) as usize,
    )
}

/// Mark written rows for the owner's post-commit live-window mirror, from a
/// helper holding only the store. The scope is keyed by the store's address,
/// so only the vault's own store finds it. A rolled-back scope drops them, so
/// no live window mirrors a write that did not land.
pub fn queue_committed_rows_in_txn<S>(store: &S, txn: &RwTxn<'_>, rows: BTreeSet<EntityId>) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending
            .borrow_mut()
            .get_mut(&store_transaction_key(store, txn))
        {
            queued.rows.extend(rows);
        }
    });
}

/// The rows `ops` write: each put, and the source of each edge they write or
/// remove, whose window carries the edge: an edge-only batch wakes the live
/// mirror too (FIX 9599).
pub fn ops_written_rows(ops: &[BatchOp]) -> BTreeSet<EntityId> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. } => Some(*id),
            BatchOp::Edge { src, .. }
            | BatchOp::PublicEdgeWithCreatedAt { src, .. }
            | BatchOp::EdgeWithCreatedAt { src, .. }
            | BatchOp::SetEdgeWeight { src, .. }
            | BatchOp::SetEdgeVad { src, .. }
            | BatchOp::DeleteEdge { src, .. } => Some(*src),
            _ => None,
        })
        .collect()
}

/// The edges `ops` remove, each as `(src, kind, tgt)`: the window that holds
/// one loses its copy only by an exact removal (FIX 9599).
#[cfg(feature = "sync")]
pub fn ops_removed_edges(
    ops: &[BatchOp],
) -> Vec<(EntityId, oneiron_base::edge::EdgeKind, EntityId)> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::DeleteEdge { src, kind, tgt } => Some((*src, *kind, *tgt)),
            _ => None,
        })
        .collect()
}

/// Whether the batch's commit wakes the proactivity watch: a claim it
/// writes, a row it deletes, or an authority row (an owner home pick may
/// have re-elected this node's MACRO home in the batch, DOOR-101).
pub fn ops_change_proactivity(ops: &[BatchOp]) -> bool {
    ops.iter().any(|op| {
        matches!(
            op,
            BatchOp::ClaimCandidate { .. }
                | BatchOp::Put {
                    entity_type: oneiron_base::registry::ENTITY_TYPE_CLAIM
                        | oneiron_base::registry::ENTITY_TYPE_AUTHORITY_LOG,
                    ..
                }
                | BatchOp::Delete { .. }
        )
    })
}
