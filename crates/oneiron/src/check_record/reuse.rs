//! Reuse of a recorded native check (ARCH-0068 #rc5-check-reuse, FIX
//! [L4-30-CHECK-REUSE-RECORD]): the inputs index, the receiver's lookup, and
//! the completion void.
//!
//! A finished check that passed on pinned, unchanged inputs is filed under
//! its reuse key. Another attempt in the same PROJECT reuses it only when
//! the stored record still passes every canon condition, re-checked live;
//! the receipt names the source attempt. Completion checks the tree again
//! and voids a reuse the tree changed under.

use heed::{RoTxn, RwTxn};

use super::{AttemptCheckRecord, CHECK_RECORDS, CheckInputVersions};
use crate::EntityId;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::side_table::{Named, SideKey, SideTable};
use crate::store::Store;
use crate::store::checkout_lease::{CheckoutError, CheckoutId};
use crate::store::contract_oracle::invalid;
use crate::task_verb::linear_store::task_revision_in_txn;

/// One reusable native check filed under its reuse key. Key: the 32-byte
/// reuse key, then AttemptId, then id16 (the check).
const CHECK_BY_INPUTS: SideTable<([u8; 32], AttemptId, EntityId), (), Named> =
    SideTable::new(&crate::side_table::ATTEMPT_CHECK_BY_INPUTS);

/// One reused native check filed under the checkout it was reused on. Key:
/// CheckoutId, then AttemptId, then id16 (the check).
const CHECK_REUSE_ON_CHECKOUT: SideTable<(CheckoutId, AttemptId, EntityId), (), Named> =
    SideTable::new(&crate::side_table::ATTEMPT_CHECK_REUSE_ON_CHECKOUT);

/// The reuse key of a check's inputs: the repo, the ref, the pinned tree and
/// the part digests, never the request revision (checked live). `None` when
/// the tree is not pinned, so the check is never reusable.
///
/// # Errors
/// An encoding failure.
pub(crate) fn reuse_key(
    repo: EntityId,
    git_ref: &str,
    inputs: &CheckInputVersions,
) -> crate::Result<Option<[u8; 32]>> {
    let Some(tree) = &inputs.tree else {
        return Ok(None);
    };
    let bytes = rmp_serde::to_vec_named(&(
        "oneiron:check-record-reuse:v1",
        repo,
        git_ref,
        tree,
        &inputs.command_digest,
        &inputs.toolchain_digest,
        &inputs.environment_digest,
    ))
    .map_err(|_| invalid("check reuse key encoding failed"))?;
    Ok(Some(*blake3::hash(&bytes).as_bytes()))
}

/// Files `record` under its reuse key when it is reusable: a check the run
/// ran (never a reuse), not world, finished passed and stable on a pinned
/// tree. Anything else leaves no row.
///
/// # Errors
/// A store or encoding failure.
pub(crate) fn index_reusable_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    record: &AttemptCheckRecord,
) -> crate::Result<()> {
    if record.reused_from.is_some() || record.world {
        return Ok(());
    }
    let Some(finish) = &record.finish else {
        return Ok(());
    };
    if !finish.passed || !finish.stable {
        return Ok(());
    }
    let Some(key) = reuse_key(record.repo, &record.git_ref, &record.inputs)? else {
        return Ok(());
    };
    CHECK_BY_INPUTS.put(
        store,
        txn,
        &(key, record.producer.attempt, record.check),
        &(),
    )
}

/// What the receiver looks a reusable check up by: its own repo, ref and
/// project, and the inputs the engine captured for it.
pub(crate) struct ReuseRequest<'r> {
    pub(crate) repo: EntityId,
    pub(crate) git_ref: &'r str,
    pub(crate) project: EntityId,
    pub(crate) inputs: &'r CheckInputVersions,
}

/// Whether `record` answers `request`: every canon condition re-checked on
/// the stored record, never trusted from the index alone. `revision` is the
/// source TASK's current revision.
fn record_matches(request: &ReuseRequest<'_>, record: &AttemptCheckRecord, revision: u64) -> bool {
    let Some(finish) = &record.finish else {
        return false;
    };
    finish.passed
        && revision == record.inputs.request_revision
        && finish.stable
        && record.repo == request.repo
        && record.git_ref == request.git_ref
        && record.inputs.tree == request.inputs.tree
        && record.inputs.command_digest == request.inputs.command_digest
        && record.inputs.toolchain_digest == request.inputs.toolchain_digest
        && record.inputs.environment_digest == request.inputs.environment_digest
        && !record.world
        && record.producer.project == request.project
        && record.reused_from.is_none()
        && !record.voided
}

/// The newest reusable record under the receiver's reuse key, if any: the
/// by-inputs rows newest attempt first, each stored record re-checked.
///
/// # Errors
/// A store or encoding failure.
pub(crate) fn find_reusable_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    request: &ReuseRequest<'_>,
) -> crate::Result<Option<AttemptCheckRecord>> {
    let Some(key) = reuse_key(request.repo, request.git_ref, request.inputs)? else {
        return Ok(None);
    };
    let mut prefix = Vec::new();
    key.encode_into(&mut prefix);
    for row in CHECK_BY_INPUTS.iter_rev_from(store, txn, &prefix)? {
        let (_, attempt, check) = row?.0;
        let Some(record) = CHECK_RECORDS.get(store, txn, &(attempt, check))? else {
            continue;
        };
        let revision = task_revision_in_txn(store, txn, record.producer.task)?;
        if record_matches(request, &record, revision) {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// Stores the receiver's reused record and files it under the checkout it
/// was reused on, so the checkout's publication checks it again.
///
/// # Errors
/// A store failure.
pub(crate) fn record_reuse_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    record: &AttemptCheckRecord,
    checkout: CheckoutId,
) -> crate::Result<()> {
    CHECK_RECORDS.put(store, txn, &(record.producer.attempt, record.check), record)?;
    CHECK_REUSE_ON_CHECKOUT.put(
        store,
        txn,
        &(checkout, record.producer.attempt, record.check),
        &(),
    )
}

/// The checkout worktree's HEAD tree at publication, when the checkout
/// carries reuses: `None` when no reuse was filed under `checkout` (so no
/// git is read), else the pinned tree, or `None` when the lease is missing,
/// the tree is not pinned, or the capture fails closed. A store failure is
/// the error.
///
/// # Errors
/// A store failure.
pub(crate) fn completion_tree(
    vault: &Vault,
    checkout: CheckoutId,
) -> crate::Result<Option<Option<String>>> {
    let txn = vault.store.env.read_txn()?;
    let mut prefix = Vec::new();
    checkout.encode_into(&mut prefix);
    if CHECK_REUSE_ON_CHECKOUT
        .scan_keys(&vault.store, &txn, &prefix)?
        .is_empty()
    {
        return Ok(None);
    }
    let lease = match crate::checkout::lease::load_act_in_txn(vault, &txn, checkout) {
        Ok(lease) => lease,
        Err(CheckoutError::Store(error)) => return Err(error),
        Err(_) => None,
    };
    drop(txn);
    let Some(act) = lease else {
        return Ok(Some(None));
    };
    let tree = match crate::git_wire::GitWire::new(vault)?.checkout_head_tree(&act) {
        Ok(tree) => tree,
        Err(CheckoutError::Store(error)) => return Err(error),
        Err(_) => None,
    };
    Ok(Some(tree.map(|oid| oid.as_str().to_owned())))
}

/// Voids every reuse filed under `checkout` on `epoch` whose reused tree
/// differs from `tree`: what completion commits with the publication.
/// Answers how many it voided. A record on another epoch is left alone.
///
/// # Errors
/// A store failure.
pub(crate) fn void_changed_reuses_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    checkout: CheckoutId,
    epoch: u64,
    tree: Option<&str>,
) -> crate::Result<usize> {
    let mut prefix = Vec::new();
    checkout.encode_into(&mut prefix);
    let keys = CHECK_REUSE_ON_CHECKOUT.scan_keys(store, txn, &prefix)?;
    let mut voided = 0;
    for (_, attempt, check) in keys {
        let key = (attempt, check);
        let Some(mut record) = CHECK_RECORDS.get(store, txn, &key)? else {
            continue;
        };
        if record.reused_from.is_some()
            && !record.voided
            && record.epoch == epoch
            && record.inputs.tree.as_deref() != tree
        {
            record.voided = true;
            CHECK_RECORDS.put(store, txn, &key, &record)?;
            voided += 1;
        }
    }
    Ok(voided)
}
