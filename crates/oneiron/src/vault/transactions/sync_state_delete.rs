//! One host row's delete in its caller's writer (FIX 6476): a host that reads
//! a row, decides on its bytes and deletes it in the same transaction, as the
//! usage repair does, so the row it deletes is the one it read.

use crate::Vault;
use crate::error::Result;

impl Vault {
    /// Deletes `key` from `sync_state` in the caller's write transaction;
    /// `true` when it held a row. The key passes the checks
    /// [`Self::sync_state_delete`] makes: it falls under a declared
    /// `SyncState` table and is no row only its own door writes.
    #[doc(hidden)]
    pub fn sync_state_delete_in_write_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        key: &str,
    ) -> Result<bool> {
        super::check_generic_sync_state_key(key)?;
        crate::side_table::host_sync_state_delete(&self.store, wtxn, key)
    }
}
