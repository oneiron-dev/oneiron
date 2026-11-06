//! A drafted reply with files ends whole when a row it depends on goes (fix
//! list row 17645): one of its files' artifacts, a pinned version's CLAIM or
//! ASSET (a released version tears its CLAIM), a source a pinned version
//! quotes, the thread, the answered TURN or one of its MESSAGE rows, or the
//! mailbox source when it is retired. Each revision registers every such row
//! in a declared index as it lands, so an erase finds exactly the drafts that
//! name the erased row and no other. In the eraser's own writer the draft's
//! retained message, its kept Gmail plan and its manifest, each with its
//! key's retirement, its Ask and the draft itself go: nothing of it stays to
//! send, and nothing is written again. A send already pressed finds its
//! message gone at egress and fails there, as any refused send does.
//!
//! A revision's own end (a redraft, a discard, a settled send) retires its
//! message and plan in its own writer; the draft, its manifest and its index
//! rows stay while the draft names its files, and a redraft ends them too.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::reply::{DRAFTS, MailReplyDraftRow};
use super::reply_custody::{
    retire_reply_manifest_in_txn, retire_reply_message_in_txn, retire_reply_plan_stub_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::CustodyWrite;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Which drafted replies with files depend on a row. Key: id16(row) +
/// id16(draft).
const DEPENDENTS: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::MAIL_PACK_REPLY_DEPENDENCY);

/// Records, in `wtxn`, the writer that lands one of its revisions, that the
/// draft `draft` depends on each of `dependencies`.
///
/// # Errors
///
/// Storage failures.
pub(super) fn register_reply_dependencies_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
    dependencies: &[EntityId],
) -> Result<()> {
    for dependency in dependencies {
        DEPENDENTS.put(store, wtxn, &(*dependency, *draft), &())?;
    }
    Ok(())
}

/// Drops, in `wtxn`, every index row a revision of one of `drafts`
/// registered. The index is keyed by the row depended on, so this reads it
/// whole; the draft's own row names no dependency.
fn forget_reply_dependencies_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    drafts: &BTreeSet<EntityId>,
) -> Result<()> {
    for (dependency, draft) in DEPENDENTS.scan_keys(store, wtxn, &[])? {
        if drafts.contains(&draft) {
            DEPENDENTS.delete(store, wtxn, &(dependency, draft))?;
        }
    }
    Ok(())
}

/// Ends the send of the draft `draft`, a reply with files, in `wtxn`, the
/// writer that discards it or settles its send: its retained message and its
/// kept plan go, each with its key's retirement staged. The draft stays, and
/// so do its manifest and its index rows, so an erase of a row it names
/// still reaches it.
///
/// # Errors
///
/// Custody and storage failures.
pub(super) fn retire_reply_send_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
) -> Result<()> {
    retire_reply_message_in_txn(store, wtxn, draft)?;
    retire_reply_plan_stub_in_txn(store, wtxn, draft)
}

/// Ends revision `row` of the draft `draft` whole, in `wtxn`, the writer
/// that lands its next revision: its send as [`retire_reply_send_in_txn`]
/// ends it, its manifest, and its index rows, which the next revision
/// registers for itself. A revision without files has none of these.
///
/// # Errors
///
/// Custody and storage failures.
pub(super) fn retire_reply_revision_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
    row: &MailReplyDraftRow,
) -> Result<()> {
    if row.attached.is_none() {
        return Ok(());
    }
    retire_reply_send_in_txn(store, wtxn, draft)?;
    retire_reply_manifest_in_txn(store, wtxn, draft)?;
    forget_reply_dependencies_in_txn(store, wtxn, &BTreeSet::from([*draft]))
}

/// The erase of `id` ends every drafted reply with files that depends on it
/// (fix list row 17645), in the erase's own transaction: its retained
/// message, its kept plan and its manifest (each key's retirement staged),
/// its index rows, its Ask and the draft. Registered in
/// `deletion::derived_rows`, so both delete doors run it before the row
/// goes; a mailbox source's retirement runs it with the source's id. An id
/// no draft names changes nothing.
///
/// # Errors
///
/// Custody and storage failures.
pub(crate) fn erase_reply_attachment_dependents_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let store = write.store;
    let drafts: BTreeSet<EntityId> = DEPENDENTS
        .scan_keys(store, wtxn, id.as_bytes())?
        .into_iter()
        .map(|(_, draft)| draft)
        .collect();
    if drafts.is_empty() {
        return Ok(());
    }
    for draft in &drafts {
        drop_reply_draft_in_txn(write, wtxn, draft)?;
    }
    forget_reply_dependencies_in_txn(store, wtxn, &drafts)
}

/// Drops the draft `draft` whole in `wtxn`: its retained message, its kept
/// plan, its manifest, its Ask and its row; the caller drops its index rows.
/// A row that does not read still loses everything sealed beside it and its
/// row.
fn drop_reply_draft_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
) -> Result<()> {
    let store = write.store;
    retire_reply_send_in_txn(store, wtxn, draft)?;
    retire_reply_manifest_in_txn(store, wtxn, draft)?;
    if let Some(row) = DRAFTS.get_lenient(store, wtxn, draft)? {
        super::reply_ask::erase_reply_ask_in_txn(write, wtxn, draft, row.revision)?;
    }
    DRAFTS.delete(store, wtxn, draft)?;
    Ok(())
}
