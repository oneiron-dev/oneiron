//! What a failed try of a workflow step spent, kept for the retry that follows
//! it (ARCH-0053 #paid-leg-built: "persisting a failed workflow try's spend, so
//! a retry after a restart replays it exactly").
//!
//! The step runner holds this in its process too; the row is what a retry
//! reads once that process is gone. Each row is keyed by a try and holds the
//! units its whole retry chain had spent. A failed try records its row; the
//! retry that follows inherits it, the row moving to the retry in the
//! transaction that reads it, so a crash before the retry settles leaves the
//! row where a reclaim of that same try finds it. The row goes when no retry
//! follows its try, or with its attempt row when the ledger deletes it.

use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::AttemptQueue;
use super::types::AttemptId;

/// Key: id16 (the try). Value: units spent by the try's chain.
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

    /// The units the try `id` replays before it runs: its own row when it
    /// has one (the same try reclaimed after a crash), else the row of the
    /// try it retries, `retry_of`, which moves to `id` in this transaction.
    /// Either way `retry_of`'s row is gone after. `None` when neither try
    /// has a row.
    ///
    /// # Errors
    ///
    /// Storage errors, or a row that does not decode.
    pub fn inherit_carried_spend(
        &self,
        id: AttemptId,
        retry_of: Option<AttemptId>,
    ) -> Result<Option<u64>> {
        // A first try retries nothing: it reads its own row and writes none.
        let Some(parent) = retry_of else {
            let rtxn = self.store.env.read_txn()?;
            return CARRIED_SPEND.get(self.store, &rtxn, &id);
        };
        let mut wtxn = self.store.env.write_txn()?;
        let own = CARRIED_SPEND.get(self.store, &wtxn, &id)?;
        let Some(parent_units) = CARRIED_SPEND.get(self.store, &wtxn, &parent)? else {
            return Ok(own);
        };
        CARRIED_SPEND.delete(self.store, &mut wtxn, &parent)?;
        if own.is_none() {
            CARRIED_SPEND.put(self.store, &mut wtxn, &id, &parent_units)?;
        }
        wtxn.commit()?;
        Ok(own.or(Some(parent_units)))
    }

    /// Drops the try `id`'s record once no retry follows it.
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
