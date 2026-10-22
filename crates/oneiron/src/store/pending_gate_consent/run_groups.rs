//! Each waiting run with every proposal it holds, read in one snapshot (FIX 9524).
//! `Vault::pending_gate_consent_run_groups` is its call surface.
//! `records` defines `PendingGateConsentGroup`, the shape returned.

use std::collections::BTreeSet;

use crate::error::Result;

use super::Store;
use super::records::PendingGateConsentGroup;

impl Store {
    /// Each run with a proposal among the first `limit` waiting rows, with
    /// every pending proposal the run holds, read through the run index in
    /// the same snapshot as the discovery: a run's members past the first
    /// rows are its members too. Runs come in the order their first
    /// discovered proposal waits; a row no run stamps is in none.
    pub(crate) fn pending_gate_consent_run_groups(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentGroup>> {
        let rtxn = self.env.read_txn()?;
        let mut seen = BTreeSet::new();
        let mut runs = Vec::new();
        for record in self.pending_gate_consents_in_txn(&rtxn, limit)? {
            if let Some(run) = record.dreamer_run_id
                && seen.insert(run.clone())
            {
                runs.push(run);
            }
        }
        runs.into_iter()
            .map(|run| {
                Ok(PendingGateConsentGroup {
                    records: self.pending_gate_consents_for_run_in_txn(&rtxn, &run)?,
                    dreamer_run_id: Some(run),
                })
            })
            .collect()
    }
}

impl crate::Vault {
    /// Each run with a proposal among the first `limit` waiting rows, beside
    /// every pending proposal it holds, read in one snapshot (FIX 9524): a
    /// listing that admits a run admits all of it, never its first rows.
    pub fn pending_gate_consent_run_groups(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentGroup>> {
        self.store.pending_gate_consent_run_groups(limit)
    }
}
