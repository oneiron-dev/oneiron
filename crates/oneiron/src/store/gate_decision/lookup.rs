//! First-match reads on the caller's gate-decision ledger transaction.

use std::ops::Bound;

use heed::RoTxn;

use crate::error::{Error, Result};

use super::keys::{GATE_DECISION_CLAIM_INDEX_PREFIX, gate_decision_claim_index_prefix};
use super::ledger::{CLAIM_INDEX, LEDGER, suffix_of, tail_id};
use super::orcb;
use super::{GateDecisionId, GateDecisionRecord, Store};

/// What one snapshot says about a claim's newest decision in the window.
enum ClaimLookup {
    /// The answer.
    Found(Option<GateDecisionId>),
    /// The claim index is not known complete, so it cannot answer.
    Unindexed,
    /// The candidate failed authentication (`CorruptedIndex("gate decision
    /// ORCB")`), and this snapshot shows its key retired.
    Retired(GateDecisionId),
}

#[cfg(test)]
thread_local! {
    static BEFORE_GATE_CLAIM_REREAD: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// Runs `callback` once, on this thread, before the claim lookup opens a
/// second snapshot.
#[cfg(test)]
pub(in crate::store) fn arm_before_gate_claim_reread(callback: impl FnOnce() + 'static) {
    BEFORE_GATE_CLAIM_REREAD.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

impl Store {
    /// Returns the first matching id in ascending decision_id order, including
    /// uncommitted rows when `txn` is the caller's write transaction.
    ///
    /// Each visited row is decoded and checked against its key before matching.
    /// A match ends the cursor walk immediately; no match scans the full ledger.
    pub(crate) fn find_gate_decision_id_in_txn(
        &self,
        txn: &RoTxn<'_>,
        mut matches: impl FnMut(&GateDecisionRecord) -> bool,
    ) -> Result<Option<GateDecisionId>> {
        for row in LEDGER.iter_from(self, txn, &[])? {
            let (decision_id, raw) = row?;
            let record = self.decode_gate_decision_value(decision_id, &raw)?;

            if record.decision_id != decision_id {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            if matches(&record) {
                return Ok(Some(decision_id));
            }
        }
        Ok(None)
    }

    /// The newest decision about `claim_id` among the `scan` newest ledger
    /// rows: the id [`Store::gate_decisions`] filtered to that claim ranks
    /// first.
    ///
    /// With the claim index complete, the candidate is the claim's newest
    /// indexed decision, kept when its key is among the `scan` newest ledger
    /// keys (walked by key; no row is decrypted). Only that row is decoded,
    /// authenticated and checked against the claim, so a corrupt row of
    /// another claim, or one below the candidate, does not fail the lookup,
    /// while a corrupt candidate does. Without a complete index, the page
    /// reader authenticates the whole window, as before.
    pub(crate) fn latest_gate_decision_for_claim(
        &self,
        claim_id: &[u8; 16],
        scan: usize,
    ) -> Result<Option<GateDecisionId>> {
        let custody = self.gate_custody_read_guard()?;
        let rtxn = self.env.read_txn()?;
        let retired = match self.latest_indexed_gate_decision_in_txn(&rtxn, claim_id, scan)? {
            ClaimLookup::Found(found) => return Ok(found),
            ClaimLookup::Retired(decision_id) => decision_id,
            ClaimLookup::Unindexed => {
                drop(rtxn);
                drop(custody);
                return Ok(self
                    .gate_decisions(scan)?
                    .into_iter()
                    .filter(|record| record.claim_id.as_ref() == Some(claim_id))
                    .map(|record| record.decision_id)
                    .max_by_key(|decision_id| decision_id.to_hex()));
            }
        };
        // As the page reader does: the failing snapshot holds the witness
        // that the candidate's key was retired. A newer snapshot answers only
        // once retirement has removed that row; otherwise the error stands.
        drop(rtxn);
        #[cfg(test)]
        BEFORE_GATE_CLAIM_REREAD.with(|slot| {
            if let Some(callback) = slot.borrow_mut().take() {
                callback();
            }
        });
        let failed = Error::CorruptedIndex("gate decision ORCB");
        let current = self.env.read_txn()?;
        if LEDGER.contains(self, &current, &retired)? {
            return Err(failed);
        }
        match self.latest_indexed_gate_decision_in_txn(&current, claim_id, scan)? {
            ClaimLookup::Found(found) => Ok(found),
            ClaimLookup::Retired(_) | ClaimLookup::Unindexed => Err(failed),
        }
    }

    fn latest_indexed_gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
        scan: usize,
    ) -> Result<ClaimLookup> {
        if !self.gate_decision_claim_index_backfill_complete_in_txn(txn)? {
            return Ok(ClaimLookup::Unindexed);
        }
        // The window's oldest row: the `scan`-th newest ledger key.
        let Some(oldest) = LEDGER
            .iter_rev_range(self, txn, Bound::Unbounded, Bound::Unbounded)?
            .take(scan)
            .last()
            .transpose()?
            .map(|(decision_id, _)| decision_id)
        else {
            return Ok(ClaimLookup::Found(None));
        };
        let prefix = suffix_of(
            gate_decision_claim_index_prefix(claim_id),
            GATE_DECISION_CLAIM_INDEX_PREFIX,
        );
        let Some(row) = CLAIM_INDEX.iter_rev_from(self, txn, &prefix)?.next() else {
            return Ok(ClaimLookup::Found(None));
        };
        let (key, ()) = row?;
        let decision_id = GateDecisionId::from_bytes(tail_id(&key, "gate decision claim index")?);
        if decision_id.as_bytes() < oldest.as_bytes() {
            return Ok(ClaimLookup::Found(None));
        }
        let Some(raw) = LEDGER.get(self, txn, &decision_id)? else {
            return Err(Error::CorruptedIndex("gate decision claim index"));
        };
        let record = match self.decode_gate_decision_value(decision_id, &raw) {
            Err(error @ Error::CorruptedIndex("gate decision ORCB")) => {
                if orcb::raw_key_retired(self.core.key_custody.local(), &raw)? {
                    return Ok(ClaimLookup::Retired(decision_id));
                }
                return Err(error);
            }
            decoded => decoded?,
        };
        if record.decision_id != decision_id || record.claim_id.as_ref() != Some(claim_id) {
            return Err(Error::CorruptedIndex("gate decision claim index"));
        }
        Ok(ClaimLookup::Found(Some(decision_id)))
    }
}
