//! The ERASE completeness scan for many claims at once (SCAN C049): one
//! tombstone batch's missing-id probes share one walk of the ledger.

use std::collections::BTreeSet;

use heed::RoTxn;

use crate::error::Result;
use crate::store::Store;

impl Store {
    /// [`Self::verify_claim_erasure_by_scan_in_txn`] for every claim of
    /// `claim_ids` in ONE full `gate_decision:v0:` keyspace scan: the claims
    /// some unredacted decision is still bound to or cites. The same
    /// independent proof, never a read of the claim index; a claim the answer
    /// leaves out is erased. Uncapped, as that scan is.
    pub(crate) fn claims_with_unerased_decisions_by_scan_in_txn(
        &self,
        txn: &RoTxn<'_>,
        claim_ids: &BTreeSet<[u8; 16]>,
    ) -> Result<BTreeSet<[u8; 16]>> {
        let mut unerased = BTreeSet::new();
        if claim_ids.is_empty() {
            return Ok(unerased);
        }
        self.for_each_gate_decision_in_txn(txn, |record| {
            if record.redacted_at.is_some() {
                return Ok(());
            }
            if let Some(claim) = record.claim_id.filter(|claim| claim_ids.contains(claim)) {
                unerased.insert(claim);
            }
            for claim in self.gate_decision_claim_refs_in_txn(txn, record.decision_id)? {
                if claim_ids.contains(&claim) {
                    unerased.insert(claim);
                }
            }
            Ok(())
        })?;
        Ok(unerased)
    }
}
