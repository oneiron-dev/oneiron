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

use super::BatchOp;
use crate::store::Store;
use crate::{EntityId, Result, Vault};

type TransactionKey = (usize, usize);

#[derive(Default)]
pub(crate) struct PostcommitWork {
    pub(crate) vad_ids: BTreeSet<EntityId>,
    pub(crate) proactivity_changed: bool,
    /// TASKs this transaction wrote, announced only after it commits.
    pub(crate) task_ids: BTreeSet<EntityId>,
    /// Rows this transaction wrote (puts, and the sources of edges it wrote),
    /// mirrored into the live sync windows only after it commits.
    pub(crate) rows: BTreeSet<EntityId>,
    /// Room joins this transaction filed, by their bare join refs, pushed to
    /// the live windows of their rooms or threads only after it commits.
    pub(crate) room_joins: BTreeSet<String>,
    /// Windows a WORLD delete staged its pads' `pt:` tombstones in, published
    /// only after the transaction commits (FIX 3334).
    pub(crate) pad_windows: BTreeSet<String>,
    /// TASKs this transaction settled, whose peer-result waiters wake only
    /// after it commits (FIX 1140).
    pub(crate) settled_tasks: BTreeSet<EntityId>,
    /// Whether this transaction put or marked a notification, whose live
    /// queries wake only after it commits (FIX 3084).
    pub(crate) notifications_changed: bool,
}

thread_local! {
    static PENDING_VAD: RefCell<BTreeMap<TransactionKey, PostcommitWork>> =
        const { RefCell::new(BTreeMap::new()) };
}

fn transaction_key(vault: &Vault, txn: &RwTxn<'_>) -> TransactionKey {
    store_transaction_key(&vault.store, txn)
}

fn store_transaction_key(store: &Store, txn: &RwTxn<'_>) -> TransactionKey {
    // Identity only: neither address is dereferenced or retained past the scope.
    (
        std::ptr::from_ref(store) as usize,
        std::ptr::from_ref(txn) as usize,
    )
}

pub(crate) struct VadPostcommitScope {
    key: TransactionKey,
}

impl VadPostcommitScope {
    pub(crate) fn new(vault: &Vault, txn: &RwTxn<'_>) -> Self {
        let key = transaction_key(vault, txn);
        PENDING_VAD.with(|pending| {
            let previous = pending.borrow_mut().insert(key, PostcommitWork::default());
            assert!(previous.is_none(), "duplicate VAD transaction owner");
        });
        Self { key }
    }

    pub(crate) fn finish(self) -> PostcommitWork {
        PENDING_VAD.with(|pending| pending.borrow_mut().remove(&self.key).unwrap_or_default())
    }
}

impl Drop for VadPostcommitScope {
    fn drop(&mut self) {
        PENDING_VAD.with(|pending| {
            pending.borrow_mut().remove(&self.key);
        });
    }
}

pub(super) fn has_vad_postcommit_owner(vault: &Vault, txn: &RwTxn<'_>) -> bool {
    PENDING_VAD.with(|pending| pending.borrow().contains_key(&transaction_key(vault, txn)))
}

pub(super) fn queue_dreamer_vad_approvals(vault: &Vault, txn: &RwTxn<'_>, ids: Vec<EntityId>) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(vault, txn)) {
            queued.vad_ids.extend(ids);
        }
    });
}

/// Mark transaction-owned claim writes for the owner's post-commit watch.
/// A rolled-back scope drops the marker without signaling the timer.
pub(crate) fn queue_proactivity_change(vault: &Vault, txn: &RwTxn<'_>) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(vault, txn)) {
            queued.proactivity_changed = true;
        }
    });
}

/// Mark a notification put or inbox mark for the owner's post-commit wake of
/// the live queries that follow notifications (FIX 3084). A rolled-back scope
/// drops the marker, so no subscriber re-reads for a write that did not land.
pub(crate) fn queue_notification_change(vault: &Vault, txn: &RwTxn<'_>) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(vault, txn)) {
            queued.notifications_changed = true;
        }
    });
}

/// Mark TASK writes for the owner's post-commit announcement. A rolled-back
/// scope drops them, so a subscriber never hears of a write that did not land.
pub(crate) fn queue_task_updates(
    vault: &Vault,
    txn: &RwTxn<'_>,
    ids: impl IntoIterator<Item = EntityId>,
) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(vault, txn)) {
            queued.task_ids.extend(ids);
        }
    });
}

/// Mark settled TASKs for the owner's post-commit peer-result wake (FIX 1140).
/// A rolled-back scope drops them, so no waiter wakes on a settlement that
/// did not land; a transaction with no owner scope leaves them to the wake
/// pass.
pub(crate) fn queue_settled_tasks(
    vault: &Vault,
    txn: &RwTxn<'_>,
    ids: impl IntoIterator<Item = EntityId>,
) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(vault, txn)) {
            queued.settled_tasks.extend(ids);
        }
    });
}

/// Mark written rows for the owner's post-commit live-window mirror. A
/// rolled-back scope drops them, so no live window mirrors a write that did
/// not land.
pub(crate) fn queue_committed_rows(vault: &Vault, txn: &RwTxn<'_>, rows: BTreeSet<EntityId>) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(vault, txn)) {
            queued.rows.extend(rows);
        }
    });
}

/// Mark a filed room join for the owner's post-commit live-window push. A
/// rolled-back scope drops it, so no live window carries a join that did not
/// land.
#[cfg(feature = "sync")]
pub(crate) fn queue_room_join(vault: &Vault, txn: &RwTxn<'_>, join_ref: &str) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(vault, txn)) {
            queued.room_joins.insert(join_ref.to_owned());
        }
    });
}

/// Mark a window whose `pt:` pad tombstones this transaction staged, for the
/// owner's post-commit publication (FIX 3334). A rolled-back scope drops it, so
/// no window publishes a tombstone that did not land.
pub(crate) fn queue_pad_tombstone_window(store: &Store, txn: &RwTxn<'_>, window: String) {
    let key = store_transaction_key(store, txn);
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&key) {
            queued.pad_windows.insert(window);
        }
    });
}

/// The rows `ops` write: each put, and the source of each edge they write or
/// remove, whose window carries the edge. A removal's source wakes the live
/// mirror, which takes the removal from its durable marker (FIX 9599).
pub(super) fn ops_written_rows(ops: &[BatchOp]) -> BTreeSet<EntityId> {
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

pub(super) fn ops_put_tasks(ops: &[BatchOp]) -> Vec<EntityId> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_TASK,
                ..
            } => Some(*id),
            _ => None,
        })
        .collect()
}

/// Whether the batch's commit wakes the proactivity watch: a claim it
/// writes, a row it deletes, or an authority row (an owner home pick may
/// have re-elected this node's MACRO home in the batch, DOOR-101).
pub(super) fn ops_change_proactivity(ops: &[BatchOp]) -> bool {
    ops.iter().any(|op| {
        matches!(
            op,
            BatchOp::ClaimCandidate { .. }
                | BatchOp::Put {
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM
                        | crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
                    ..
                }
                | BatchOp::Delete { .. }
        )
    })
}

/// Whether the batch writes or deletes a unit some question watches for
/// arrivals. Its arrival is queued in this transaction; the commit then wakes
/// the question pump, as a claim write does.
pub(super) fn ops_touch_watched_units(
    vault: &Vault,
    txn: &RoTxn<'_>,
    ops: &[BatchOp],
) -> Result<bool> {
    for op in ops {
        let (BatchOp::Put { id, .. } | BatchOp::Delete { id }) = op else {
            continue;
        };
        if crate::llm::decision::questions::unit_watched_in_txn(&vault.store, txn, id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn pending_dreamer_vad_approvals(
    vault: &Vault,
    txn: &RoTxn<'_>,
    ops: &[BatchOp],
) -> Result<Vec<EntityId>> {
    let mut pending_ids = Vec::new();
    for op in ops {
        let (id, approval) = match op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                allow_reserved_predicate: false,
                ..
            } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM => {
                (*id, crate::claim::decode_claim_body(data, false)?.approval)
            }
            BatchOp::ClaimCandidate { id, envelope, .. } => (*id, envelope.approval()),
            _ => continue,
        };
        if vault.pending_dreamer_vad_approval_in_txn(txn, &id, approval)? {
            pending_ids.push(id);
        }
    }
    Ok(pending_ids)
}
