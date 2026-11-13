//! What a failed try of a workflow step spent, kept for the retry that follows
//! it (ARCH-0053 #paid-leg-built: "persisting a failed workflow try's spend, so
//! a retry after a restart replays it exactly").
//!
//! The step runner holds this in its process too; the row is what a retry
//! reads once that process is gone. Each row is keyed by the failed try and
//! holds the units its whole retry chain had spent when it failed. The retry
//! takes the row, and the row goes with its attempt row when the ledger
//! deletes it.

use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::AttemptQueue;
use super::types::AttemptId;

/// Key: id16 (the failed try). Value: units spent by the try's chain.
const CARRIED_SPEND: SideTable<AttemptId, u64, Named> =
    SideTable::new(&side_table::ATTEMPT_CARRIED_SPEND);

/// Deletes `id`'s carried spend with its row; an id with none is left as it is.
pub(super) fn delete_carried_spend_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: AttemptId,
) -> Result<()> {
    CARRIED_SPEND.delete(store, wtxn, &id)?;
    Ok(())
}

impl AttemptQueue<'_> {
    /// Records that the failed try `id` left its retry chain having spent
    /// `units`, replacing any earlier record for `id`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn record_carried_spend(&self, id: AttemptId, units: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        CARRIED_SPEND.put(self.store, &mut wtxn, &id, &units)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Takes what the failed try `id` recorded for its retry: the units, and
    /// the row is gone. `None` when `id` recorded none.
    ///
    /// # Errors
    ///
    /// Storage errors, or a row that does not decode.
    pub fn take_carried_spend(&self, id: AttemptId) -> Result<Option<u64>> {
        let mut wtxn = self.store.env.write_txn()?;
        let units = CARRIED_SPEND.get(self.store, &wtxn, &id)?;
        if units.is_some() {
            CARRIED_SPEND.delete(self.store, &mut wtxn, &id)?;
            wtxn.commit()?;
        }
        Ok(units)
    }

    /// Drops the failed try `id`'s record once no retry follows it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn forget_carried_spend(&self, id: AttemptId) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if CARRIED_SPEND.delete(self.store, &mut wtxn, &id)? {
            wtxn.commit()?;
        }
        Ok(())
    }
}
