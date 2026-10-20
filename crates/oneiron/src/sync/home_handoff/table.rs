//! The tables a home move carries. A domain implements [`HomeTable`] for each
//! node-local table that must follow the home, and passes the carrier one
//! [`HomeTableRegistration`] per table. The carrier walks those registrations
//! and never reads or writes a table's rows itself: each table exports its
//! own typed rows and adopts them through its own typed writes.
//!
//! On the wire a section names its table by the declaration's name and
//! carries the rows as the table's named MessagePack DTO, whatever codec the
//! table stores them in.

use heed::{RoTxn, RwTxn};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{HomeFence, HomeMove, refused};
use crate::Vault;
use crate::error::Result;
use crate::side_table::{Named, SideCodec, SideDb, SideTableDecl};

/// A restore image's rows of one database, sorted by key.
pub(crate) type ImageRows = [(Vec<u8>, Vec<u8>)];

/// What one table's adopt did with the rows it was handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TableAdopt {
    /// The rows are this node's now: equal rows were a no-op, a proven
    /// successor merged as the domain merges it.
    Applied,
    /// Rows here diverge from the carried ones and neither follows the
    /// other. The carrier drops its writer, so no section lands.
    Conflict,
}

/// One node-local table that follows the vault's home.
pub(crate) trait HomeTable: Send + Sync + 'static {
    /// The rows a move carries: a typed DTO the domain owns, never raw rows.
    type Rows: Serialize + DeserializeOwned;
    /// The table's declaration; its name is the section's id on the wire.
    const TABLE: &'static SideTableDecl;
    /// The version of [`Self::Rows`]. A target adopts only the version it
    /// registers.
    const SCHEMA_VERSION: u16;

    /// Whether every write this table admitted before the move has settled,
    /// so its rows can freeze.
    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, movement: &HomeMove) -> Result<bool>;

    /// The rows the move carries, read in the source's final writer.
    fn export(vault: &Vault, txn: &RoTxn<'_>, fence: &HomeFence) -> Result<Self::Rows>;

    /// Lands `rows` in the target's one adopting transaction. An error or a
    /// [`TableAdopt::Conflict`] drops that transaction, earlier sections too.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        fence: &HomeFence,
        rows: Self::Rows,
    ) -> Result<TableAdopt>;

    /// The full stored keys of every row this table manages now, deletion
    /// witnesses and new descendants included, for restore to keep live.
    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>>;

    /// The full stored keys this table manages among `image`, a restore
    /// image's rows of [`Self::TABLE`]'s database (FIX 5661 C2b): with
    /// [`Self::live_keys`] they restore live, so this node's current row, or
    /// its absence, wins over the image's. A table may read this node's rows
    /// in `txn` to judge one, and may name keys only this node holds. By
    /// default every key of the table's family.
    fn manages(_vault: &Vault, _txn: &RoTxn<'_>, image: &ImageRows) -> Result<Vec<Vec<u8>>> {
        Ok(image
            .iter()
            .filter(|(key, _)| key.starts_with(Self::TABLE.prefix))
            .map(|(key, _)| key.clone())
            .collect())
    }
}

type QuiescentFn = fn(&Vault, &RoTxn<'_>, &HomeMove) -> Result<bool>;
type ExportFn = fn(&Vault, &RoTxn<'_>, &HomeFence) -> Result<Vec<u8>>;
type CheckFn = fn(&[u8]) -> Result<()>;
type AdoptFn = fn(&Vault, &mut RwTxn<'_>, &HomeFence, &[u8]) -> Result<TableAdopt>;
type LiveKeysFn = fn(&Vault, &RoTxn<'_>) -> Result<Vec<Vec<u8>>>;
type ManagesFn = fn(&Vault, &RoTxn<'_>, &ImageRows) -> Result<Vec<Vec<u8>>>;

/// One registered [`HomeTable`], its row type erased: what the carrier walks.
#[derive(Clone, Copy)]
pub(crate) struct HomeTableRegistration {
    table: &'static SideTableDecl,
    schema_version: u16,
    quiescent: QuiescentFn,
    export: ExportFn,
    check: CheckFn,
    adopt: AdoptFn,
    live_keys: LiveKeysFn,
    manages: ManagesFn,
}

impl HomeTableRegistration {
    /// The registration of `T`.
    pub(crate) const fn of<T: HomeTable>() -> Self {
        Self {
            table: T::TABLE,
            schema_version: T::SCHEMA_VERSION,
            quiescent: T::quiescent,
            export: export_rows::<T>,
            check: check_rows::<T>,
            adopt: adopt_rows::<T>,
            live_keys: T::live_keys,
            manages: T::manages,
        }
    }

    /// The table's id on the wire: its declaration's name.
    pub(crate) fn table_id(&self) -> &'static str {
        self.table.name
    }

    pub(crate) fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// The full stored keys of every row the table manages now.
    pub(crate) fn live_keys(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        (self.live_keys)(vault, txn)
    }

    /// The database the table's rows are in.
    pub(crate) fn database(&self) -> SideDb {
        self.table.db
    }

    /// The full stored keys the table manages among a restore image's rows
    /// of its database ([`HomeTable::manages`]).
    pub(crate) fn manages(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        image: &ImageRows,
    ) -> Result<Vec<Vec<u8>>> {
        (self.manages)(vault, txn, image)
    }

    pub(super) fn quiescent(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        movement: &HomeMove,
    ) -> Result<bool> {
        (self.quiescent)(vault, txn, movement)
    }

    pub(super) fn export(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        fence: &HomeFence,
    ) -> Result<Vec<u8>> {
        (self.export)(vault, txn, fence)
    }

    /// Whether `rows` decode as this table's rows, before any writer.
    pub(super) fn check(&self, rows: &[u8]) -> Result<()> {
        (self.check)(rows)
    }

    pub(super) fn adopt(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        fence: &HomeFence,
        rows: &[u8],
    ) -> Result<TableAdopt> {
        (self.adopt)(vault, txn, fence, rows)
    }
}

/// Refuses a registry that names one table twice: each table is one section.
pub(super) fn check_registry(tables: &[HomeTableRegistration]) -> Result<()> {
    for (index, table) in tables.iter().enumerate() {
        if tables[..index]
            .iter()
            .any(|earlier| earlier.table_id() == table.table_id())
        {
            return Err(refused("the registry names one table twice"));
        }
    }
    Ok(())
}

fn export_rows<T: HomeTable>(vault: &Vault, txn: &RoTxn<'_>, fence: &HomeFence) -> Result<Vec<u8>> {
    let rows = T::export(vault, txn, fence)?;
    <Named as SideCodec<T::Rows>>::encode(&rows)
        .map_err(|_| refused("a table's rows do not encode"))
}

fn decode_rows<T: HomeTable>(rows: &[u8]) -> Result<T::Rows> {
    <Named as SideCodec<T::Rows>>::decode(rows)
        .map_err(|_| refused("a section's rows do not decode"))
}

fn check_rows<T: HomeTable>(rows: &[u8]) -> Result<()> {
    decode_rows::<T>(rows).map(drop)
}

fn adopt_rows<T: HomeTable>(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    fence: &HomeFence,
    rows: &[u8],
) -> Result<TableAdopt> {
    T::adopt(vault, txn, fence, decode_rows::<T>(rows)?)
}
