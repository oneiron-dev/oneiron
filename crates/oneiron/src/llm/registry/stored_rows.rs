//! The registry's stored rows. Each is written as itself; a legacy pre-9534
//! stored copy of the installed model pack's row whose catalog cost names
//! no `currency` key is read under that pack's currency contract (FIX 9534,
//! narrowed by FIX 11778). Any other row reads as it is stored.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::ModelRegistryRow;
use super::installed_pack::{installed_pack_source, stored_pack_row};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, LegacyJson, SideTable, SideTableDbs};

/// The rows as they are stored and written.
const ROWS: SideTable<String, ModelRegistryRow, LegacyJson> =
    SideTable::new(&side_table::LLM_REGISTRY_ROW);

/// [`ROWS`], each read through [`decoded`].
#[derive(Clone, Copy)]
pub(super) struct StoredRows;

impl StoredRows {
    pub(super) fn get(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key: &str,
    ) -> Result<Option<ModelRegistryRow>> {
        ROWS.get_bytes(dbs, txn, &key.to_owned())?
            .map(|bytes| decoded(dbs, txn, &bytes))
            .transpose()
    }

    /// Every row's key, in key order, beside its row as [`Self::get`] reads
    /// it or why it does not read: a row that does not decode is that row's
    /// alone (FIX 10862). A storage failure reading a key fails the scan.
    pub(super) fn scan_each(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
    ) -> Result<Vec<(String, Result<ModelRegistryRow>)>> {
        let mut rows = Vec::new();
        for key in ROWS.scan_keys(dbs, txn, &[])? {
            if let Some(bytes) = ROWS.get_bytes(dbs, txn, &key)? {
                let row = decoded(dbs, txn, &bytes);
                rows.push((key, row));
            }
        }
        Ok(rows)
    }

    /// The rows under `key_prefix`, in key order.
    pub(super) fn iter_from(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key_prefix: &[u8],
    ) -> Result<std::vec::IntoIter<Result<(String, ModelRegistryRow)>>> {
        let rows: Vec<_> = ROWS
            .scan_keys(dbs, txn, key_prefix)?
            .into_iter()
            .filter_map(|key| match ROWS.get_bytes(dbs, txn, &key) {
                Ok(Some(bytes)) => Some(decoded(dbs, txn, &bytes).map(|row| (key, row))),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            })
            .collect();
        Ok(rows.into_iter())
    }

    pub(super) fn put(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &str,
        row: &ModelRegistryRow,
    ) -> Result<()> {
        ROWS.put(dbs, txn, &key.to_owned(), row)
    }

    pub(super) fn delete(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &str,
    ) -> Result<bool> {
        ROWS.delete(dbs, txn, &key.to_owned())
    }

    /// Stores again, as it reads, each row that reads under the currency
    /// contract of the pack installed from one of `packs`
    /// ([`stored_pack_row`]): an install that replaces that pack's receipt
    /// first writes the pack's currency into a stored pack-copy whose cost
    /// names no `currency` key, so it still reads as stored (FIX 9534,
    /// narrowed by FIX 11778 to legacy pre-9534 copies). Every other row
    /// stays as it is.
    pub(super) fn keep_pack_rows(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        packs: &BTreeSet<EntityId>,
    ) -> Result<()> {
        for key in ROWS.scan_keys(dbs, txn, &[])? {
            let Some(bytes) = ROWS.get_bytes(dbs, txn, &key)? else {
                continue;
            };
            let copied = packs.iter().find_map(|pack| stored_pack_row(&bytes, *pack));
            if let Some(row) = copied.and_then(|copied| ROWS.decode_value(&copied).ok()) {
                ROWS.put(dbs, txn, &key, &row)?;
            }
        }
        Ok(())
    }
}

/// `bytes`, one stored row, decoded. A stored copy of the installed
/// pack's row whose catalog cost names no `currency` key is read with that
/// pack's currency contract ([`stored_pack_row`]); any other row, explicit
/// `null` or any code included, reads as it is stored.
fn decoded(dbs: &impl SideTableDbs, txn: &RoTxn<'_>, bytes: &[u8]) -> Result<ModelRegistryRow> {
    match installed_pack_source(dbs, txn)?.and_then(|pack| stored_pack_row(bytes, pack)) {
        Some(copied) => ROWS.decode_value(&copied),
        None => ROWS.decode_value(bytes),
    }
}
