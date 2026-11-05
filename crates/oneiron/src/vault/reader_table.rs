//! Core half of `vault::reader_table`: its store-layer items live in `oneiron_store::vault::reader_table` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::vault::reader_table::*;

use super::Vault;

impl Vault {
    /// The slots this vault's LMDB reader table holds, read back from LMDB.
    pub(crate) fn reader_slots(&self) -> u32 {
        self.store.env.info().maximum_number_of_readers
    }

    /// `Some` when LMDB gave this vault fewer reader slots than its config
    /// asked for: another process opened the vault first with a smaller table
    /// and still holds it, so LMDB kept that table. Reads past it fail with
    /// `MDB_READERS_FULL` until every process has closed the vault and it is
    /// opened again.
    #[must_use]
    pub fn reader_table_shortfall(&self) -> Option<ReaderTableShortfall> {
        let granted = self.reader_slots();
        (granted < self.config.max_readers).then_some(ReaderTableShortfall {
            requested: self.config.max_readers,
            granted,
        })
    }
}
