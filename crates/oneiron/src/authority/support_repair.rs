//! FIX 4407: a support holder runs one repair the customer selected.
//!
//! The customer's support grant (OF-606) names each repair it allows by its
//! id, signed into the slip's delegation ([`SupportRepair`]). This door
//! admits the support slip and spends its holder proof in one writer, where
//! the grant's use receipt names the support PERSON and the grant
//! (`support_receipt`); it refuses a repair the delegation does not name,
//! and then runs that one sweep. It never runs the whole housekeeping pass,
//! never takes the owner's floor (no exception in the owner binding check)
//! and never makes an owner proof.

use super::*;
use crate::Vault;
use crate::error::Result;
use crate::housekeeping::{HousekeepingBudget, HousekeepingReport, HousekeepingSweep};

/// The housekeeping sweep a support repair runs.
const fn repair_sweep(repair: SupportRepair) -> HousekeepingSweep {
    match repair {
        SupportRepair::CriticalConfirmExpiry => HousekeepingSweep::CriticalConfirmExpiry,
        SupportRepair::SymbolLeaseExpiry => HousekeepingSweep::SymbolLeaseExpiry,
        SupportRepair::EsignExpiry => HousekeepingSweep::EsignExpiry,
        SupportRepair::EsignSealBackstop => HousekeepingSweep::EsignSealBackstop,
        SupportRepair::CommitmentLapse => HousekeepingSweep::CommitmentLapse,
        SupportRepair::PprCacheEviction => HousekeepingSweep::PprCacheEviction,
        SupportRepair::SharedActMaturity => HousekeepingSweep::SharedActMaturity,
    }
}

impl Vault {
    /// Runs `repair` now for the holder of the support `slip`, whose
    /// request proof is `timestamp`, `signature` and `nonce`, within
    /// `budget`: the report names that one sweep.
    ///
    /// # Errors
    ///
    /// The slip's own refusal (not live, not this vault's, a spent or stale
    /// proof, a support delegation that no longer stands); an authority
    /// refusal when the slip carries no support delegation naming `repair`;
    /// the pass's own error when its schedule does not read.
    pub fn run_support_repair_by_slip(
        &self,
        slip: &CapabilitySlip,
        timestamp: u64,
        signature: &[u8],
        nonce: &[u8],
        repair: SupportRepair,
        budget: HousekeepingBudget,
    ) -> Result<HousekeepingReport> {
        let mut txn = self.store.env.write_txn()?;
        let verified =
            self.admit_capability_slip_request_in_txn(&mut txn, slip, timestamp, signature, nonce)?;
        let named = verified
            .claims()
            .delegation
            .as_ref()
            .is_some_and(|delegation| delegation.repairs.contains(&repair));
        if !named {
            return Err(invalid_authority());
        }
        txn.commit()?;
        self.housekeeping_one(repair_sweep(repair), budget)
    }
}
