//! Owed claim VAD consolidation (FIX 9598). An approval that owes a Dreamer
//! claim's VAD consolidation writes the debt in its own commit, and the
//! consolidation clears it in its own. The writer that approved still runs
//! the consolidation right after its commit, as before; a process that stops
//! between the two commits, or a consolidation that fails, leaves the debt,
//! and the housekeeping pass finishes it later. The in-memory queue a batch
//! carries to its commit stays a hint; this row is the debt.

use heed::{RoTxn, RwTxn};

use super::Store;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// Key: the claim; value: when the debt was written.
const OWED: SideTable<EntityId, u64, Named> = SideTable::new(&side_table::CLAIM_VAD_OWED);

/// Writes the debt of each approved claim in `ids`, in the approval's own
/// transaction. A debt already owed keeps its first stamp.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn owe_claim_vad_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    ids: &[EntityId],
    now: u64,
) -> Result<()> {
    for id in ids {
        if !OWED.contains(store, wtxn, id)? {
            OWED.put(store, wtxn, id, &now)?;
        }
    }
    Ok(())
}

/// Clears `id`'s debt in the transaction that settles it: the consolidation
/// that committed it, or the claim's erase (a per-entity eraser in
/// `deletion/derived_rows.rs`).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn settle_claim_vad_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    OWED.delete(store, wtxn, id)?;
    Ok(())
}

/// Every owed claim, in id order.
fn owed_claim_vads_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    Ok(OWED
        .scan(store, txn)?
        .into_iter()
        .map(|(id, _)| id)
        .collect())
}

impl crate::Vault {
    /// Finishes the owed claim VAD consolidations, each in its own writer,
    /// until `stop` says the pass is out of time. A consolidation that
    /// commits clears its debt, as does one that finds the claim no longer
    /// consolidatable (it clears the claim's outputs); a claim that is gone
    /// owes nothing; any other failure keeps its debt for a later pass.
    /// Returns how many debts were settled, how many failed, and how many
    /// were left untried when `stop` came.
    ///
    /// # Errors
    ///
    /// Storage errors reading or clearing the debt rows.
    pub(crate) fn drain_owed_claim_vads(
        &self,
        now: u64,
        mut stop: impl FnMut() -> bool,
    ) -> Result<(u64, u64, u64)> {
        let owed = {
            let txn = self.store.env.read_txn()?;
            owed_claim_vads_in_txn(&self.store, &txn)?
        };
        let (mut settled, mut failed, mut left) = (0_u64, 0_u64, 0_u64);
        for (done, id) in owed.iter().enumerate() {
            if stop() {
                left = (owed.len() - done) as u64;
                break;
            }
            match self.consolidate_claim_vad_now(id, now) {
                Ok(_) => settled = settled.saturating_add(1),
                Err(error) => {
                    let mut wtxn = self.store.env.write_txn()?;
                    if !OWED.contains(&self.store, &wtxn, id)? {
                        settled = settled.saturating_add(1);
                    } else if self.get_claim_in_txn(&wtxn, id)?.is_none() {
                        settle_claim_vad_in_txn(&self.store, &mut wtxn, id)?;
                        wtxn.commit()?;
                        settled = settled.saturating_add(1);
                    } else {
                        drop(wtxn);
                        tracing::warn!(
                            claim = %id,
                            error = %error,
                            "owed claim VAD consolidation failed; the debt stays for a later pass"
                        );
                        failed = failed.saturating_add(1);
                    }
                }
            }
        }
        Ok((settled, failed, left))
    }
}
