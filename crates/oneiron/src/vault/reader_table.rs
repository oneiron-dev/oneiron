//! The LMDB reader table a vault's environment got, against what it asked for.

use super::Vault;

/// A vault whose LMDB reader table holds fewer slots than its config asked
/// for (see [`crate::config::READER_SLOTS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderTableShortfall {
    /// The slots this vault's config asked for.
    pub requested: u32,
    /// The slots its reader table holds.
    pub granted: u32,
}

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
