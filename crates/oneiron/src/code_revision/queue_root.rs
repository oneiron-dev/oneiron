//! The checked Baseline a tested queue revision's parent chain ends at,
//! kept by key when its seal is finalized (FIX 7390, 7391). An export, a
//! readiness view and a promotion read the root in one keyed read, never by
//! walking the chain's parent links. A revision with no kept root (one an
//! archive carried, or one below an erased ancestor) walks the links as
//! before, and meets what that walk meets.
use std::collections::HashSet;

use heed::{RoTxn, RwTxn};

use super::CodeRevision;
use super::keys::{PARENT_INDEX, QUEUE_ROOTS};
use super::storage::read_code_revision_record_in_txn;
use crate::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;

/// The record `revision`'s parent chain ends at, read in `txn`: by its kept
/// root when there is one, else by the parent links.
///
/// # Errors
/// A missing record, a cycle, or a store failure.
pub(super) fn queue_chain_root_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    revision: CodeRevision,
) -> Result<CodeRevision> {
    match QUEUE_ROOTS.get(store, txn, &revision.revision_id)? {
        Some(root) if root == revision.revision_id => Ok(revision),
        Some(root) => {
            read_code_revision_record_in_txn(store, txn, &root)?.ok_or(Error::EntityNotFound)
        }
        None => walk_to_root_in_txn(store, txn, revision),
    }
}

/// The root of `revision`'s chain by its parent links, each record read
/// once and counted.
fn walk_to_root_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    revision: CodeRevision,
) -> Result<CodeRevision> {
    let start = revision.revision_id;
    let mut root = revision;
    let mut count = ScanCount::start(store, txn, EngineScan::DagWalkRecords, start.as_bytes())?;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(root.revision_id) {
            count.defer(store);
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision parent chain contains a cycle",
            )));
        }
        count.row();
        let Some(parent) = root.parent_revision_id else {
            break;
        };
        root =
            read_code_revision_record_in_txn(store, txn, &parent)?.ok_or(Error::EntityNotFound)?;
    }
    count.defer(store);
    Ok(root)
}

/// Keeps the root of the queue revision `revision` in `wtxn`, the writer
/// that finalizes it: itself for a Baseline, else its parent's root.
///
/// # Errors
/// A missing parent, a cycle, or a store failure.
pub(super) fn put_queue_root_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision: &CodeRevision,
) -> Result<()> {
    let root = match revision.parent_revision_id {
        None => revision.revision_id,
        Some(parent) => {
            let parent = read_code_revision_record_in_txn(store, wtxn, &parent)?
                .ok_or(Error::EntityNotFound)?;
            queue_chain_root_in_txn(store, wtxn, parent)?.revision_id
        }
    };
    QUEUE_ROOTS.put(store, wtxn, &revision.revision_id, &root)
}

/// Drops the kept root of `revision_id` and of every revision below it, so
/// a chain whose ancestor is deleted walks its links again. A revision with
/// no kept root (no queue revision) has none below it either.
///
/// # Errors
/// A store failure.
pub(super) fn delete_queue_roots_below_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    revision_id: &EntityId,
) -> Result<()> {
    if !QUEUE_ROOTS.contains(store, wtxn, revision_id)? {
        return Ok(());
    }
    let mut next = vec![*revision_id];
    let mut seen = HashSet::new();
    while let Some(id) = next.pop() {
        if !seen.insert(id) {
            continue;
        }
        QUEUE_ROOTS.delete(store, wtxn, &id)?;
        for (_, child) in PARENT_INDEX.scan_keys(store, wtxn, id.as_bytes())? {
            next.push(child);
        }
    }
    Ok(())
}
