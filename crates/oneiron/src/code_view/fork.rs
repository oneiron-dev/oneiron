//! An owner working view's own file states (row 6 WORKING-VIEW-EDIT). Each
//! edit of a view file is one code-document operation on the view's fork of
//! that file, never on the shared document: the fork row names the state the
//! edits reached and each operation's actor, and the view's copy of the file
//! is that state's text. The view revision counts the view's edits, so one
//! writer at a time moves a view's forks.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::CodeViewSet;
use crate::code_document::{CodeDocumentFrontier, ReceiptActor};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Vault};

/// One view's fork of one file, keyed by (view id, view path).
pub(crate) const VIEW_FORK_FILES: SideTable<(EntityId, String), ViewForkFile, Named> =
    SideTable::new(&side_table::CODE_VIEW_FORK_FILE);

/// One view's fork revision, keyed by view id; no row is revision 0.
pub(crate) const VIEW_FORK_REVISIONS: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::CODE_VIEW_FORK_REVISION);

/// One view's fork of one file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewForkFile {
    /// The state the fork grew from: the tested revision's document state of
    /// the path, or the birth state of a tested queue revision's untouched
    /// blob.
    pub(crate) base: CodeDocumentFrontier,
    /// The state the view's last edit of the file reached.
    pub(crate) state: CodeDocumentFrontier,
    /// The BLAKE3 of `state`'s text: what the view's copy of the file holds.
    pub(crate) text_blake3: [u8; 32],
    /// Each edit of the file in the view, oldest first.
    pub(crate) ops: Vec<ViewForkOp>,
}

/// One edit of a view's file: the operation, who made it, and the states it
/// went from and to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewForkOp {
    #[serde(with = "super::entity_serde")]
    pub(crate) operation: EntityId,
    #[serde(with = "super::entity_serde")]
    pub(crate) session: EntityId,
    /// The actor, or no one once that actor was erased (FIX 3520).
    pub(crate) actor: ReceiptActor,
    pub(crate) actor_class: u8,
    /// The view revision this edit made.
    pub(crate) revision: u64,
    pub(crate) before: CodeDocumentFrontier,
    pub(crate) after: CodeDocumentFrontier,
}

/// The one writer of view fork copies in this process: an edit holds it from
/// its fork row's write through its copy's replace, and a repair from its read
/// of the rows through its replaces, so no writer that read a row before
/// another's edit leaves a copy older than that edit.
static VIEW_FORK_COPIES: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes [`VIEW_FORK_COPIES`].
///
/// # Errors
/// A writer that panicked while holding it.
pub(crate) fn view_fork_copies_lock() -> Result<std::sync::MutexGuard<'static, ()>> {
    VIEW_FORK_COPIES
        .lock()
        .map_err(|_| Error::InvariantViolation("view fork lock poisoned"))
}

impl CodeViewSet<'_> {
    /// Rewrites each copy of view `id` whose bytes are not its fork row's
    /// text, from that row's stored state: an edit that committed its row but
    /// not its copy heals at the next owner read of the view. A view with no
    /// fork reads nothing more.
    ///
    /// # Errors
    /// A store or file failure, or a stored state whose text is not its row's.
    pub(crate) fn project_view_forks(&self, id: EntityId) -> Result<()> {
        let _copies = view_fork_copies_lock()?;
        let forks = {
            let txn = self.vault.store.env.read_txn()?;
            view_fork_files_in_txn(self.vault, &txn, id)?
        };
        if forks.is_empty() {
            return Ok(());
        }
        let root = self.view_path(id)?;
        for (path, fork) in forks {
            let copy = super::read_view_file(&root, &path)?;
            if *blake3::hash(&copy).as_bytes() == fork.text_blake3 {
                continue;
            }
            let text = self.vault.code_document_at(&fork.state)?;
            if *blake3::hash(text.as_bytes()).as_bytes() != fork.text_blake3 {
                return Err(Error::CorruptedIndex(
                    "view fork state does not hold its row's text",
                ));
            }
            self.replace_view_file(id, &path, text.as_bytes())?;
        }
        Ok(())
    }
}

/// The fork revision of `view` in `txn`: how many edits it holds.
///
/// # Errors
/// A store failure, or a row that does not decode.
pub(crate) fn view_fork_revision_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    view: EntityId,
) -> Result<u64> {
    Ok(VIEW_FORK_REVISIONS
        .get(&vault.store, txn, &view)?
        .unwrap_or(0))
}

/// Every forked file of `view` in `txn`, by view path.
///
/// # Errors
/// A store failure, or a row that does not decode.
pub(crate) fn view_fork_files_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    view: EntityId,
) -> Result<BTreeMap<String, ViewForkFile>> {
    VIEW_FORK_FILES
        .iter_from(&vault.store, txn, view.as_bytes())?
        .map(|row| row.map(|((_, path), file)| (path, file)))
        .collect()
}

/// Deletes every fork row of `view`, for the erase that retires the view.
///
/// # Errors
/// A store failure.
pub(super) fn delete_view_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    view: EntityId,
) -> Result<()> {
    VIEW_FORK_FILES.delete_from(&vault.store, txn, view.as_bytes())?;
    VIEW_FORK_REVISIONS.delete(&vault.store, txn, &view)?;
    Ok(())
}

/// Erasing `actor` from the view forks (FIX 3520): each edit it made keeps
/// its operation, states and revision and names no one. One-way, in the
/// erase's own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
/// Storage errors, or a fork row that cannot be read.
pub(crate) fn erase_view_fork_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut named = Vec::new();
    for row in VIEW_FORK_FILES.iter_from(&vault.store, wtxn, &[])? {
        let (key, mut file) = row?;
        let mut forgot = false;
        for op in &mut file.ops {
            forgot |= op.actor.forget(*actor);
        }
        if forgot {
            named.push((key, file));
        }
    }
    for (key, file) in named {
        VIEW_FORK_FILES.put(&vault.store, wtxn, &key, &file)?;
    }
    Ok(())
}
