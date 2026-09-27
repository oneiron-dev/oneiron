//! Transaction-owner handoff for Dreamer VAD approvals and digest invalidation.
//!
//! `batch_in` receives a bare heed transaction, not its owner. Keep its pending
//! work scoped to that exact transaction and vault on the synchronous caller's
//! thread. The owner drains it before commit and runs it only after commit.
//! Dropping the scope on error or unwind discards all work. Internal raw-transaction
//! owners retain their existing explicit postcommit hooks.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use super::BatchOp;
use crate::{EntityId, Result, Vault};

type TransactionKey = (usize, usize);

#[derive(Default)]
pub(crate) struct PostcommitWork {
    pub(crate) vad_ids: BTreeSet<EntityId>,
    pub(crate) proactivity_changed: bool,
}

thread_local! {
    static PENDING_VAD: RefCell<BTreeMap<TransactionKey, PostcommitWork>> =
        const { RefCell::new(BTreeMap::new()) };
}

fn transaction_key(vault: &Vault, txn: &RwTxn<'_>) -> TransactionKey {
    // Identity only: neither address is dereferenced or retained past the scope.
    (
        std::ptr::from_ref(vault) as usize,
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

pub(super) fn ops_change_proactivity(ops: &[BatchOp]) -> bool {
    ops.iter().any(|op| {
        matches!(
            op,
            BatchOp::ClaimCandidate { .. }
                | BatchOp::Put {
                    entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                    ..
                }
                | BatchOp::Delete { .. }
        )
    })
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
