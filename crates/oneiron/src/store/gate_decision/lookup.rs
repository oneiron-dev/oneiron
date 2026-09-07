//! First-match reads on the caller's gate-decision ledger transaction.

use heed::RoTxn;

use crate::error::{Error, Result};

use super::{
    GATE_DECISION_KEY_PREFIX, GateDecisionId, GateDecisionRecord, Store, decode_gate_decision,
    gate_decision_id_from_key, gate_decision_upper_bound,
};

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
        let upper = gate_decision_upper_bound();
        for row in self.vault_meta.range(
            txn,
            &(
                std::ops::Bound::Included(GATE_DECISION_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            let decision_id = gate_decision_id_from_key(&key)?;
            let record = decode_gate_decision(&value)?;
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
