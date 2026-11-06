//! A drafted reply with files ends whole when a row it depends on goes (fix
//! list row 17645): one of its files' artifacts, a pinned version's CLAIM or
//! ASSET (a released version tears its CLAIM), the thread, the answered TURN
//! or one of its MESSAGE rows, or the mailbox source when it is retired. Each
//! revision registers every such row in a declared index as it lands, so an
//! erase finds exactly the drafts that name the erased row and no other. In
//! the eraser's own writer the draft's retained message and its key, its
//! kept Gmail plan, its Ask and the draft itself go: nothing of it stays to
//! send, and nothing is written again. A send already pressed finds its
//! message gone at egress and fails there, as any refused send does.
//!
//! A revision's own end (a redraft, a discard, a settled send) retires its
//! message and plan in its own writer; the draft and its index rows stay
//! while the draft names its files.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::reply::{DRAFTS, MailReplyDraftRow};
use super::reply_custody::retire_reply_message_in_txn;
use crate::channel_identity_provider::gmail::GmailSendPlan;
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

/// Ends the send of revision `row` of the draft `draft`, a reply with files,
/// in `wtxn`, the writer that discards it or settles its send: its retained
/// message, with its key's retirement staged, and its kept plan go. The
/// draft stays, and so do its index rows, so an erase of a row it names
/// still reaches it.
///
/// # Errors
///
/// Custody and storage failures.
pub(super) fn retire_reply_send_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
    row: &MailReplyDraftRow,
) -> Result<()> {
    retire_reply_message_in_txn(store, wtxn, draft)?;
    GmailSendPlan::drop_kept_in_txn(store, wtxn, &row.plan_ref)
}

/// Ends revision `row` of the draft `draft` whole, in `wtxn`, the writer
/// that lands its next revision: its send as [`retire_reply_send_in_txn`]
/// ends it, and its index rows, which the next revision registers for
/// itself. A revision without files has none of these.
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
    let Some(attached) = &row.attached else {
        return Ok(());
    };
    retire_reply_send_in_txn(store, wtxn, draft, row)?;
    for dependency in &attached.dependencies {
        DEPENDENTS.delete(store, wtxn, &(*dependency, *draft))?;
    }
    Ok(())
}

/// The erase of `id` ends every drafted reply with files that depends on it
/// (fix list row 17645), in the erase's own transaction: its retained
/// message (its key's retirement staged), its kept plan, its index rows, its
/// Ask and the draft. Registered in `deletion::derived_rows`, so both delete
/// doors run it before the row goes; a mailbox source's retirement runs it
/// with the source's id. An id no draft names changes nothing.
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
    for draft in &drafts {
        drop_reply_draft_in_txn(write, wtxn, draft)?;
        DEPENDENTS.delete(store, wtxn, &(*id, *draft))?;
    }
    Ok(())
}

/// Drops the draft `draft` whole in `wtxn`: its retained message, its kept
/// plan, every index row its revision registered, its Ask and its row. A
/// row that does not read still loses its message and its row.
fn drop_reply_draft_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    draft: &EntityId,
) -> Result<()> {
    let store = write.store;
    retire_reply_message_in_txn(store, wtxn, draft)?;
    if let Some(row) = DRAFTS.get_lenient(store, wtxn, draft)? {
        GmailSendPlan::drop_kept_in_txn(store, wtxn, &row.plan_ref)?;
        if let Some(attached) = &row.attached {
            for dependency in &attached.dependencies {
                DEPENDENTS.delete(store, wtxn, &(*dependency, *draft))?;
            }
        }
        super::reply_ask::erase_reply_ask_in_txn(write, wtxn, draft, row.revision)?;
    }
    DRAFTS.delete(store, wtxn, draft)?;
    Ok(())
}
