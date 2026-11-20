//! Entity rows put past every write door, for the integration-test doors
//! (`crate::test_doors`): a damaged row, or a row a vault already holds that
//! a write door would refuse today. The one raw core-table write stays here,
//! inside `store/`, which owns the core tables
//! (`scripts/ratchet/raw_write_census.py`). Compiled only under
//! `--cfg oneiron_test_support`; never API.

use heed::RwTxn;

use super::Store;
use crate::entity_id::EntityId;
use crate::error::Result;

impl Store {
    /// Stores `bytes` as the entity row `id` in `txn`, past every write door:
    /// no record check, no index row, no hook. The row's key and any index
    /// row it already has stay as they are.
    ///
    /// # Errors
    ///
    /// The store refuses the write.
    pub(crate) fn put_entity_row_bytes_for_test(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        bytes: &[u8],
    ) -> Result<()> {
        self.entities.put(txn, id.as_bytes(), bytes)?;
        Ok(())
    }
}
