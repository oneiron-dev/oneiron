//! What a commit changed for the backup watermark (FIX 6730): a write that
//! moves nothing an owner backs up (a host's telemetry, a backup's own chain
//! advance, its incarnation) says so, so the watermark stays where the last
//! content commit left it and an idle host reuses the backup it has.
//!
//! A classed write runs as a group of its own, so no other write's rows share
//! its commit, and stamps [`BackupCommitState`] in that same transaction: its
//! id, the last content commit's id and its class. A reader takes the
//! content id only while the stamp is the last commit's own; a commit that
//! stamped nothing (every content write, and a raw writer past the group)
//! counts as content, so a change is never missed. A write whose rows are
//! dropped stamps nothing; a refusal whose receipt is kept does.
//!
//! The row is Runtime-tier and in no image: a restored store starts with
//! every commit counted, as its fresh incarnation does.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{Callback, Rows, Store};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// The last stamped commit. Key: ().
const BACKUP_CHANGE: SideTable<(), BackupCommitState, Named> =
    SideTable::new(&side_table::BACKUP_CHANGE);

/// What a write changes for the backup watermark.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum BackupWriteClass {
    /// Anything an owner backs up: every write that names no other class.
    #[default]
    Content,
    /// A host's own counters and questions, which no restore needs.
    Telemetry,
    /// A backup's own bookkeeping: its chain advance and its incarnation.
    BackupMetadata,
}

impl BackupWriteClass {
    /// The class of one commit holding writes of `self` and `other`: content
    /// wins a mixed commit.
    fn merge(self, other: Self) -> Self {
        if self == Self::Content || other == Self::Content {
            Self::Content
        } else {
            self
        }
    }
}

/// The last stamped commit: its transaction id, the id of the last commit
/// that changed content at or before it, and its class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupCommitState {
    physical_txn: u64,
    content_txn: u64,
    class: BackupWriteClass,
}

/// Stamps `wtxn`'s commit as `class`, in `wtxn`: content records itself as
/// the last content commit; any other class keeps the last one's.
///
/// # Errors
///
/// Storage errors.
fn stamp_backup_commit_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    class: BackupWriteClass,
) -> Result<()> {
    let physical_txn = wtxn.id() as u64;
    let prior = BACKUP_CHANGE.get_lenient(dbs, wtxn, &())?;
    let (class, content_txn) = match prior {
        // A classed write before this one in the same transaction.
        Some(prior) if prior.physical_txn == physical_txn => {
            let class = prior.class.merge(class);
            let content = if class == BackupWriteClass::Content {
                physical_txn
            } else {
                prior.content_txn
            };
            (class, content)
        }
        _ if class == BackupWriteClass::Content => (class, physical_txn),
        // The commit just before stamped itself: its content mark stands.
        Some(prior) if prior.physical_txn.checked_add(1) == Some(physical_txn) => {
            (class, prior.content_txn)
        }
        // The commit just before stamped nothing: it changed content.
        _ => (class, physical_txn.saturating_sub(1)),
    };
    BACKUP_CHANGE.put(
        dbs,
        wtxn,
        &(),
        &BackupCommitState {
            physical_txn,
            content_txn,
            class,
        },
    )
}

/// The last commit `txn` sees that changed content: the stamp's content id
/// while the stamp is the last commit's own, else `txn`'s id. A stamp that
/// does not read counts every commit, never a refusal.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn backup_content_txn_in_txn(dbs: &impl SideTableDbs, txn: &RoTxn<'_>) -> Result<u64> {
    let at = txn.id() as u64;
    Ok(match BACKUP_CHANGE.get_lenient(dbs, txn, &())? {
        Some(state) if state.physical_txn == at => state.content_txn,
        _ => at,
    })
}

/// The class of a host's `sync_state` write of `keys`: telemetry when there
/// is at least one and every one is a declared telemetry row (a wire
/// window's counters, a wire question, a `[limits]` question, the managed
/// ledger's revision); content otherwise. An unsupported key makes the
/// write content, never a refusal.
#[cfg(feature = "sync")]
pub(crate) fn telemetry_batch_class<K: AsRef<str>>(
    keys: impl IntoIterator<Item = K>,
) -> BackupWriteClass {
    let families = [
        side_table::RC42_WIRE_RECEIPT.prefix,
        side_table::RC42_WIRE_QUESTION.prefix,
        side_table::WIRE_LIMIT_QUESTION.prefix,
    ];
    let telemetry = |key: &str| {
        let key = key.as_bytes();
        key == side_table::MANAGED_LEDGER_REV.prefix
            || families
                .iter()
                .any(|prefix| key.len() > prefix.len() && key.starts_with(prefix))
    };
    let mut any = false;
    for key in keys {
        if !telemetry(key.as_ref()) {
            return BackupWriteClass::Content;
        }
        any = true;
    }
    if any {
        BackupWriteClass::Telemetry
    } else {
        BackupWriteClass::Content
    }
}

impl Store {
    /// [`Self::group_write_as`] for a write of `class` (FIX 6730): a content
    /// write is any write. Any other class runs as a group of its own, so no
    /// content another write stages rides its commit, and is stamped in its
    /// own transaction when its rows stay (a refusal's receipt included).
    pub(crate) fn group_write_classed<T, E>(
        &self,
        callback: Callback,
        class: BackupWriteClass,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        if class == BackupWriteClass::Content {
            return self.group_write_as(callback, None, write);
        }
        self.group_write_as(Callback::Opaque, None, |txn| {
            let rows = write(txn);
            if matches!(rows, Rows::Discard(_)) {
                return rows;
            }
            match stamp_backup_commit_in_txn(self, txn, class) {
                Ok(()) => rows,
                Err(error) => Rows::Discard(Err(E::from(error))),
            }
        })
    }
}
