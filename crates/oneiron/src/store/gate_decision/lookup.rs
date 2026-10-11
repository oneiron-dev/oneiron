//! First-match reads on the caller's gate-decision ledger transaction.

use std::ops::Bound;

use heed::RoTxn;

use crate::error::{Error, Result};

use super::ledger::{LEDGER, decode_gate_decision};
use super::orcb;
use super::{GateDecisionId, GateDecisionRecord, Store};

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
    /// first. A row is matched on its claim id alone (an ORCB row's header, a
    /// plain row's body), so no other claim's row is decrypted; the matched
    /// row is decoded in full and checked as the page reader checks each row.
    pub(crate) fn latest_gate_decision_for_claim(
        &self,
        claim_id: &[u8; 16],
        scan: usize,
    ) -> Result<Option<GateDecisionId>> {
        let found = {
            let _custody = self.gate_custody_read_guard()?;
            let rtxn = self.env.read_txn()?;
            self.latest_gate_decision_for_claim_in_txn(&rtxn, claim_id, scan)
        };
        match found {
            // The matched row's key was retired under it: the page reader
            // re-reads the ledger without the rows that retirement removed.
            Err(Error::CorruptedIndex("gate decision ORCB")) => Ok(self
                .gate_decisions(scan)?
                .into_iter()
                .filter(|record| record.claim_id.as_ref() == Some(claim_id))
                .map(|record| record.decision_id)
                .max_by_key(|decision_id| decision_id.to_hex())),
            other => other,
        }
    }

    fn latest_gate_decision_for_claim_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_id: &[u8; 16],
        scan: usize,
    ) -> Result<Option<GateDecisionId>> {
        let rows = LEDGER.iter_rev_range(self, txn, Bound::Unbounded, Bound::Unbounded)?;
        for row in rows.take(scan) {
            let (decision_id, raw) = row?;
            let bound = if orcb::is_orcb(&raw) {
                Some(orcb::header_claim_id(&raw)?)
            } else {
                decode_gate_decision(&raw)?.claim_id
            };
            if bound.as_ref() != Some(claim_id) {
                continue;
            }
            let record = self.decode_gate_decision_value(decision_id, &raw)?;
            if record.decision_id != decision_id || record.claim_id.as_ref() != Some(claim_id) {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            return Ok(Some(decision_id));
        }
        Ok(None)
    }
}
