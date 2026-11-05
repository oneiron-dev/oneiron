//! Core half of `batch::vad_postcommit`: its store-layer items live in `oneiron_store::batch::vad_postcommit` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::vad_postcommit::*;

use super::BatchOp;
use crate::store::Store;
use crate::{EntityId, Result, Vault};
use heed::{RoTxn, RwTxn};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

fn transaction_key(vault: &Vault, txn: &RwTxn<'_>) -> TransactionKey {
    store_transaction_key(&vault.store, txn)
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

impl Vault {
    /// Queue a NOTE document invalidation for this transaction's owner.
    /// No owner scope means no work; rollback or unwind discards the id.
    pub(crate) fn queue_note_document_update_in_txn(&self, txn: &RwTxn<'_>, id: EntityId) {
        PENDING_VAD.with(|pending| {
            if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(self, txn)) {
                queued.note_document_ids.insert(id);
            }
        });
    }
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

pub(super) fn ops_put_tasks(ops: &[BatchOp]) -> Vec<EntityId> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_TASK,
                data,
                ..
            } => Some(crate::context_board::task_body_for_announcement(data, *id)),
            _ => None,
        })
        .collect()
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
        if crate::store::decision_question_watches::unit_watched_in_txn(&vault.store, txn, id)? {
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
            } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM => (
                *id,
                crate::write_envelope::claim_body::decode_claim_body(data, false)?.approval,
            ),
            BatchOp::ClaimCandidate { id, envelope, .. } => (*id, envelope.approval()),
            _ => continue,
        };
        if vault.pending_dreamer_vad_approval_in_txn(txn, &id, approval)? {
            pending_ids.push(id);
        }
    }
    Ok(pending_ids)
}

/// Move a successful nested actor batch's postcommit work to its actual owner.
pub(super) fn merge_postcommit_work(vault: &Vault, txn: &RwTxn<'_>, work: PostcommitWork) {
    PENDING_VAD.with(|pending| {
        if let Some(queued) = pending.borrow_mut().get_mut(&transaction_key(vault, txn)) {
            queued.vad_ids.extend(work.vad_ids);
            queued.proactivity_changed |= work.proactivity_changed;
            queued.task_ids.extend(work.task_ids);
            queued.rows.extend(work.rows);
            queued.room_joins.extend(work.room_joins);
            queued.pad_windows.extend(work.pad_windows);
            queued.settled_tasks.extend(work.settled_tasks);
            queued.notifications_changed |= work.notifications_changed;
            queued.note_document_ids.extend(work.note_document_ids);
        }
    });
}
