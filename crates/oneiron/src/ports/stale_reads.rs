//! Partial physical inputs of the original staleness read.
//!
//! These borrowed events cover the stale mark, direct walk/dependency reads and
//! epoch-summary and calendar-origin reads, including ClaimOf and settlement rows.
//! They grant no permission to retain bytes and are not a complete read certificate.
use crate::EntityId;
use crate::error::Result;
use crate::side_table::{SideCodec, SideDb, SideKey, SideTable, SideTableDbs};
use crate::store::ManifestDbs;
use heed::RoTxn;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StaleReadTable {
    VaultMeta,
    SyncState,
    Entities,
    EdgesIn,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum StaleRead<'row> {
    Row {
        table: StaleReadTable,
        key: &'row [u8],
        value: Option<&'row [u8]>,
    },
    ScanComplete {
        table: StaleReadTable,
        prefix: &'row [u8],
    },
    /// The original first-row walk seek treats an iterator error as occupied.
    /// This event reports missing evidence without changing that answer.
    ScanFailed {
        table: StaleReadTable,
        prefix: &'row [u8],
    },
}

/// Synchronous, infallible and nonretaining; no store reentry, scope changes or panic.
pub(crate) type StaleReadObserver<'observer> = dyn for<'row> FnMut(StaleRead<'row>) + 'observer;

pub(crate) fn observe(observer: &mut Option<&mut StaleReadObserver<'_>>, read: StaleRead<'_>) {
    if let Some(observer) = observer.as_deref_mut() {
        observer(read);
    }
}

/// The same side-table get and codec, observed before its original decode.
pub(crate) fn side_row<K: SideKey, V, C: SideCodec<V>>(
    table: SideTable<K, V, C>,
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    key: &K,
    observer: &mut Option<&mut StaleReadObserver<'_>>,
) -> Result<Option<V>> {
    if observer.is_none() {
        return table.get(dbs, txn, key);
    }
    let raw = table.get_borrowed(dbs, txn, key)?;
    observe(
        observer,
        StaleRead::Row {
            table: match table.decl().db {
                SideDb::VaultMeta => StaleReadTable::VaultMeta,
                SideDb::SyncState => StaleReadTable::SyncState,
            },
            key: &table.key_bytes(key),
            value: raw.as_deref(),
        },
    );
    raw.map(|bytes| table.decode_value(&bytes)).transpose()
}

/// Original staleness result with partial original-read observations only.
pub(crate) fn stale_in_txn_observed(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    mut observer: Option<&mut StaleReadObserver<'_>>,
) -> Result<bool> {
    super::integrity::stale_observed_in(dbs, txn, id, &mut observer)
}

/// The original entity-record read, observed before its native header/body decode.
pub(crate) fn entity_record(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    observer: &mut Option<&mut StaleReadObserver<'_>>,
) -> Result<Option<super::EntityRecord>> {
    if observer.is_none() {
        return super::EntityStoreRead::port_entity_record(dbs, txn, id);
    }
    let raw = dbs.entities().get(txn, id.as_bytes())?;
    observe(
        observer,
        StaleRead::Row {
            table: StaleReadTable::Entities,
            key: id.as_bytes(),
            value: raw.as_deref(),
        },
    );
    raw.map(|raw| super::lmdb_query::decode_record(&raw))
        .transpose()
}
