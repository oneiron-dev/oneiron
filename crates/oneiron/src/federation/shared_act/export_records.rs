//! The record ids an export-first removal's export counted, beside its
//! receipt (FIX 11886). The first execution keeps them in its own writer
//! beside the receipt it writes, so a later receipt read lists what the
//! first execution listed (`verbs/shared.rs execute_shared_act_listing`).

use crate::error::Result;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::{EntityId, Vault};

/// Each export-first removal's counted record ids. Key: hex32 (receipt id).
const EXPORT_RECORDS: SideTable<HexId, Vec<EntityId>, Named> =
    SideTable::new(&side_table::SHARED_ACT_REMOVAL_EXPORT_RECORDS);

impl Vault {
    /// Keeps `records`, the ids `receipt_id`'s export counted, beside that
    /// receipt, in the execution's own writer.
    pub(super) fn keep_export_records_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        receipt_id: &str,
        records: &[EntityId],
    ) -> Result<()> {
        let receipt = HexId(EntityId::from_hex(receipt_id)?);
        let records = records.to_vec();
        EXPORT_RECORDS.put(&self.store, txn, &receipt, &records)
    }

    /// The ids the removal receipt `receipt_id`'s export counted, as kept
    /// beside it; `None` for one executed before they were kept. The
    /// receipt's own read decides who reads them.
    pub fn shared_act_export_records(
        &self,
        receipt_id: &str,
    ) -> Result<Option<Vec<EntityId>>> {
        let txn = self.store.env.read_txn()?;
        let receipt = HexId(EntityId::from_hex(receipt_id)?);
        EXPORT_RECORDS.get(&self.store, &txn, &receipt)
    }
}
