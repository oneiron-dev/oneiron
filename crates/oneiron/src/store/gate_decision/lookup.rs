//! First-match reads on the caller's gate-decision ledger transaction.

use heed::RoTxn;

use crate::error::{Error, Result};

use super::ledger::LEDGER;
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
            let (decision_id, record) = row?;
            if record.decision_id != decision_id {
                return Err(Error::CorruptedIndex("gate decision ledger"));
            }
            if matches(&record) {
                return Ok(Some(decision_id));
            }
        }
        Ok(None)
    }
}
