//! A tolerant streaming read of the gate-decision ledger (OF-499 A2): each
//! row reaches the caller as its own result, so a row that does not decode,
//! authenticate or match its key withholds only itself and the walk reads
//! on. The strict readers in `ledger.rs`, which erasure, restore and the
//! receipt queries stand on, still stop at their first bad row.

use heed::RoTxn;

use crate::error::{Error, Result};
use crate::side_table::SideKey;
use crate::store::Store;

use super::ledger::LEDGER;
use super::types::{GateDecisionId, GateDecisionRecord};

impl Store {
    /// Streams every primary ledger row in ascending decision_id order and
    /// hands `visit` each row's own result. A row is checked exactly as
    /// [`Store::for_each_gate_decision_in_txn`] checks it: its key names a
    /// decision id, its value decodes under the store's current custody
    /// (a claim-bound row decrypts under its claim's key), and the record's
    /// id is its key. A row that fails any of these reaches `visit` as that
    /// row's error, and the walk goes on to the next row.
    ///
    /// The returned error is the walk's own: the cursor did not open, or it
    /// stopped on a storage error. Rows visited before it stand; a caller
    /// reads the source as incomplete, never as permission.
    ///
    /// MEMORY CONTRACT: as the strict walk's, `visit` runs inside the cursor
    /// walk, so a filtered read retains only what it keeps.
    pub(crate) fn for_each_gate_decision_item_in_txn(
        &self,
        txn: &RoTxn<'_>,
        mut visit: impl FnMut(Result<GateDecisionRecord>),
    ) -> Result<()> {
        for row in LEDGER.iter_raw_from(self, txn, &[])? {
            let (key, raw) = row?;
            visit(self.gate_decision_item(&key, &raw));
        }
        Ok(())
    }

    /// One ledger row read whole: its key, its value under custody, and the
    /// record's id against its key.
    fn gate_decision_item(&self, key: &[u8], raw: &[u8]) -> Result<GateDecisionRecord> {
        let decision_id =
            GateDecisionId::decode_key(key).ok_or(Error::CorruptedIndex("gate decision ledger"))?;
        let value = LEDGER.decode_value(raw)?;
        let record = self.decode_gate_decision_value(decision_id, &value)?;
        if record.decision_id != decision_id {
            return Err(Error::CorruptedIndex("gate decision ledger"));
        }
        Ok(record)
    }
}
