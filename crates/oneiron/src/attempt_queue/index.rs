//! FIX 11318: the attempt ledger's side indexes, so a reader that wants a
//! kind's rows, a task's rows, a try's retries or the rows an annotation holds
//! reads those rows by key and decodes no others. A row's kind, `task_ref` and
//! `retry_of` are set when it is created; a compacted lineage's relink is the
//! one rewrite. FIX 11970: a row's run-tree children too, so a reader that
//! wants one TASK's tree walks it down by key; a row's run-tree parent moves
//! when a placement, a relink or a payload rebind changes it.

use crate::error::{Error, Result};
use crate::run_tree::effective_parent;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

use super::types::{AttemptId, AttemptRecord};

/// Key: u64be kind length + kind + id16.
const KIND: SideTable<Vec<u8>, (), Raw> = SideTable::new(&side_table::ATTEMPT_KIND_INDEX);
/// Key: u64be task ref length + task ref + id16.
const TASK: SideTable<Vec<u8>, (), Raw> = SideTable::new(&side_table::ATTEMPT_TASK_INDEX);
/// Key: parent id16 + child id16.
const RETRY_CHILD: SideTable<(AttemptId, AttemptId), (), Raw> =
    SideTable::new(&side_table::ATTEMPT_RETRY_CHILD_INDEX);
/// Key: parent id16 + child id16.
const PARENT_CHILD: SideTable<(AttemptId, AttemptId), (), Raw> =
    SideTable::new(&side_table::ATTEMPT_PARENT_CHILD_INDEX);
/// Key: id16.
const ANNOTATION_HOLD: SideTable<AttemptId, (), Raw> =
    SideTable::new(&side_table::ATTEMPT_ANNOTATION_HOLD);

/// The key prefix of every entry under `text`: its u64be length, then its bytes.
fn text_prefix(text: &str) -> Vec<u8> {
    let mut key = (text.len() as u64).to_be_bytes().to_vec();
    key.extend_from_slice(text.as_bytes());
    key
}

/// The kind index's key of `record`.
fn kind_key(record: &AttemptRecord) -> Vec<u8> {
    let mut key = text_prefix(&record.kind);
    key.extend_from_slice(record.id.as_bytes());
    key
}

/// The task index's key of `record`, when it realizes a task.
fn task_key(record: &AttemptRecord) -> Option<Vec<u8>> {
    let mut key = text_prefix(record.task_ref.as_deref()?);
    key.extend_from_slice(record.id.as_bytes());
    Some(key)
}

/// Writes the kind, task, retry-child and parent-child entries of a newly created `record`.
pub(super) fn put_created_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    KIND.put(store, wtxn, &kind_key(record), &())?;
    if let Some(key) = task_key(record) {
        TASK.put(store, wtxn, &key, &())?;
    }
    if let Some(parent) = record.retry_of {
        RETRY_CHILD.put(store, wtxn, &(parent, record.id), &())?;
    }
    if let Some(parent) = effective_parent(record) {
        PARENT_CHILD.put(store, wtxn, &(parent, record.id), &())?;
    }
    Ok(())
}

/// Deletes every entry of a deleted `record`: its kind, task, retry-child, parent-child and
/// hold entries.
pub(super) fn delete_deleted_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    KIND.delete(store, wtxn, &kind_key(record))?;
    if let Some(key) = task_key(record) {
        TASK.delete(store, wtxn, &key)?;
    }
    if let Some(parent) = record.retry_of {
        RETRY_CHILD.delete(store, wtxn, &(parent, record.id))?;
    }
    if let Some(parent) = effective_parent(record) {
        PARENT_CHILD.delete(store, wtxn, &(parent, record.id))?;
    }
    ANNOTATION_HOLD.delete(store, wtxn, &record.id)?;
    Ok(())
}

/// Moves `child`'s retry-child entry from the parent `from` to the parent `to`.
pub(super) fn move_retry_child_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    child: AttemptId,
    from: Option<AttemptId>,
    to: Option<AttemptId>,
) -> Result<()> {
    if let Some(parent) = from {
        RETRY_CHILD.delete(store, wtxn, &(parent, child))?;
    }
    if let Some(parent) = to {
        RETRY_CHILD.put(store, wtxn, &(parent, child), &())?;
    }
    Ok(())
}

/// Moves `child`'s parent-child entry from the run-tree parent `from` to the run-tree parent
/// `to`; equal parents leave the entry as it is.
pub(super) fn move_parent_child_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    child: AttemptId,
    from: Option<AttemptId>,
    to: Option<AttemptId>,
) -> Result<()> {
    if from == to {
        return Ok(());
    }
    if let Some(parent) = from {
        PARENT_CHILD.delete(store, wtxn, &(parent, child))?;
    }
    if let Some(parent) = to {
        PARENT_CHILD.put(store, wtxn, &(parent, child), &())?;
    }
    Ok(())
}

/// The ids of every row of `kind`, in any state, in id order.
pub(super) fn kind_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    kind: &str,
) -> Result<Vec<AttemptId>> {
    let prefix = text_prefix(kind);
    KIND.scan_keys(store, txn, &prefix)?
        .iter()
        .map(|key| {
            key.strip_prefix(prefix.as_slice())
                .and_then(|id| AttemptId::from_bytes(id).ok())
                .ok_or(Error::CorruptedIndex("attempt kind index"))
        })
        .collect()
}

/// The ids of every row realizing the task `task_ref`, in any state, in id order.
pub(super) fn task_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task_ref: &str,
) -> Result<Vec<AttemptId>> {
    let prefix = text_prefix(task_ref);
    TASK.scan_keys(store, txn, &prefix)?
        .iter()
        .map(|key| {
            key.strip_prefix(prefix.as_slice())
                .and_then(|id| AttemptId::from_bytes(id).ok())
                .ok_or(Error::CorruptedIndex("attempt task index"))
        })
        .collect()
}

/// The ids of every row whose `retry_of` names `parent`, in id order.
pub(super) fn retry_child_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    parent: AttemptId,
) -> Result<Vec<AttemptId>> {
    Ok(RETRY_CHILD
        .scan_keys(store, txn, parent.as_bytes())?
        .into_iter()
        .map(|(_, child)| child)
        .collect())
}

/// The ids of every row whose run-tree parent is `parent`, in id order.
pub(super) fn parent_child_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    parent: AttemptId,
) -> Result<Vec<AttemptId>> {
    Ok(PARENT_CHILD
        .scan_keys(store, txn, parent.as_bytes())?
        .into_iter()
        .map(|(_, child)| child)
        .collect())
}

/// Marks `id` as paused for an annotation hold.
pub(super) fn put_annotation_hold_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: AttemptId,
) -> Result<()> {
    ANNOTATION_HOLD.put(store, wtxn, &id, &())
}

/// Removes `id`'s annotation-hold mark; an id with none is left as it is.
pub(super) fn delete_annotation_hold_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: AttemptId,
) -> Result<()> {
    ANNOTATION_HOLD.delete(store, wtxn, &id)?;
    Ok(())
}

/// The ids marked as paused for an annotation hold, in id order; a mark may outlive its hold.
pub(super) fn annotation_hold_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<AttemptId>> {
    ANNOTATION_HOLD.scan_keys(store, txn, &[])
}

/// Deletes every entry of the five indexes, for a restore that rebuilds them.
pub(super) fn clear_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    KIND.delete_from(store, wtxn, &[])?;
    TASK.delete_from(store, wtxn, &[])?;
    RETRY_CHILD.delete_from(store, wtxn, &[])?;
    PARENT_CHILD.delete_from(store, wtxn, &[])?;
    ANNOTATION_HOLD.delete_from(store, wtxn, &[])?;
    Ok(())
}
