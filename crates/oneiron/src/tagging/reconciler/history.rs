//! The trace history's upkeep at the start of a pass: trimming to the
//! per-turn bound in force, and expiry by age.

use std::sync::PoisonError;
use std::sync::atomic::Ordering;

use super::coordinator::TaggingReconciler;
use crate::error::Result;
use crate::tagging::history as trace_history;

impl TaggingReconciler {
    /// Trims history kept under a larger per-turn bound down to the one in
    /// force, one bounded read a pass until a read reaches the end, once per
    /// reconciler: the bound can only have shrunk across a reopen. The excess
    /// is found outside the writer and deleted in bounded transactions, so a
    /// history within the bound commits nothing. `Ok(true)` when `paused`
    /// cut it short: the read it did not finish deleting from is read again.
    pub(super) fn trim_history(&self, paused: &dyn Fn() -> bool) -> Result<bool> {
        if self.history_trimmed.load(Ordering::Acquire) {
            return Ok(false);
        }
        if paused() {
            return Ok(true);
        }
        let mut from = self
            .trim_from
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (excess, next) = {
            let txn = self.vault.store.env.read_txn()?;
            trace_history::excess_per_turn_in_txn(&self.vault, &txn, *from)?
        };
        for chunk in excess.chunks(trace_history::PRUNE_BUDGET) {
            if paused() {
                return Ok(true);
            }
            self.vault.try_with_write_txn_grouped(|txn| {
                trace_history::delete_excess_in_txn(&self.vault, txn, chunk)
            })?;
        }
        match next {
            Some(turn) => *from = Some(turn),
            None => self.history_trimmed.store(true, Ordering::Release),
        }
        Ok(false)
    }

    /// Prunes every trace past the history's age, in bounded transactions,
    /// before the pass claims anything: a pass records its traces only after
    /// this, so expiry keeps up with any batch size. Each round reads first,
    /// so a pass with nothing to prune commits nothing. `Ok(true)` when
    /// `paused` cut it short before a round; the next pass prunes the rest.
    pub(super) fn prune_expired_traces(&self, paused: &dyn Fn() -> bool) -> Result<bool> {
        loop {
            if paused() {
                return Ok(true);
            }
            let due = {
                let txn = self.vault.store.env.read_txn()?;
                let now = self.stamp_in_txn(&txn)?;
                trace_history::expired_in_txn(&self.vault, &txn, now)?
            };
            if !due {
                return Ok(false);
            }
            let pruned = self.vault.try_with_write_txn_grouped(|txn| {
                let now = self.stamp_in_txn(txn)?;
                trace_history::prune_expired_in_txn(&self.vault, txn, now)
            })?;
            if pruned == 0 {
                return Ok(false);
            }
        }
    }
}
