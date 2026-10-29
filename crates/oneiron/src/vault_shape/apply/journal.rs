//! Every apply's journal: one row per apply, keyed by the frontier of the
//! plan it lands, written after each item so a torn apply resumes where it
//! stopped.
use super::ShapeApplyReceipt;
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// Every apply's journal, keyed by the frontier of the plan it lands.
pub(super) const JOURNAL: SideTable<String, ShapeApplyReceipt, Named> =
    SideTable::new(&side_table::VAULT_SHAPE_APPLY);

impl Vault {
    /// The journal of the apply landing the plan at `frontier`.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn shape_apply(&self, frontier: &str) -> Result<Option<ShapeApplyReceipt>> {
        let txn = self.store.env.read_txn()?;
        JOURNAL.get(&self.store, &txn, &frontier.to_owned())
    }

    /// Every apply with an item still pending or waiting for the owner.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn open_shape_applies(&self) -> Result<Vec<ShapeApplyReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(JOURNAL
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .filter(|receipt| !receipt.done)
            .collect())
    }

    /// Records `receipt`, and settles its run rows to match, in one writer.
    pub(in crate::vault_shape) fn put_shape_apply(
        &self,
        receipt: &ShapeApplyReceipt,
        now: u64,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            JOURNAL.put(&self.store, txn, &receipt.frontier, receipt)?;
            self.settle_shape_run_in_txn(txn, receipt, now)
        })
    }
}
