//! Borrowed original archive/removal inputs, not permission or a complete read certificate.
//! Staleness delegates and memo-hit physical inputs are not covered here.
use crate::error::Result;
use crate::side_table::{SideCodec, SideDb, SideKey, SideTable};
use crate::store::ManifestDbs;
use heed::RoTxn;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeletionSourceTable {
    VaultMeta,
    SyncState,
    Entities,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DeletionSource<'row> {
    Row {
        table: DeletionSourceTable,
        key: &'row [u8],
        value: Option<&'row [u8]>,
    },
    /// A successful empty first-row seek, not a traversal of a nonempty prefix.
    ScanComplete {
        table: DeletionSourceTable,
        prefix: &'row [u8],
    },
}

/// Synchronous, infallible and nonretaining; no store reentry, scope changes or panic.
pub(crate) type DeletionSourceObserver<'observer> =
    dyn for<'row> FnMut(DeletionSource<'row>) + 'observer;

pub(crate) fn observe(
    observer: &mut Option<&mut DeletionSourceObserver<'_>>,
    source: DeletionSource<'_>,
) {
    if let Some(observer) = observer.as_deref_mut() {
        observer(source);
    }
}

/// The original presence-only side-table read; values are never decoded.
pub(crate) fn deletion_source_contains<K: SideKey, V, C: SideCodec<V>>(
    table: SideTable<K, V, C>,
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    key: &K,
    observer: &mut Option<&mut DeletionSourceObserver<'_>>,
) -> Result<bool> {
    if observer.is_none() {
        return table.contains(dbs, txn, key);
    }
    let raw = table.get_borrowed(dbs, txn, key)?;
    observe(
        observer,
        DeletionSource::Row {
            table: match table.decl().db {
                SideDb::VaultMeta => DeletionSourceTable::VaultMeta,
                SideDb::SyncState => DeletionSourceTable::SyncState,
            },
            key: &table.key_bytes(key),
            value: raw.as_deref(),
        },
    );
    Ok(raw.is_some())
}
