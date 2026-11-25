//! The allocations a self-hosted server granted its own host account from its config,
//! `[gpu_jobs.host_allocation]` (R6-VAULT-MACHINE-FUNDING = A): one row per allocation id.
//!
//! The host account holds the live meter in memory, so a restart starts it empty. This row is
//! what makes the grant happen once: a start whose id the vault already recorded grants nothing,
//! and a new id grants its units afresh. Nothing here spends, holds or settles; every job still
//! reserves and settles on the host account (FRAUD-1).
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::llm::run_admission::LeaseUnit;
use crate::side_table::{self, Named, SideTable};

const GRANTS: SideTable<String, HostAllocationGrant, Named> =
    SideTable::new(&side_table::GPU_HOST_ALLOCATION_GRANT);

/// One config allocation the server granted its host account: how many units, in which unit,
/// and when it was granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAllocationGrant {
    pub units: u64,
    pub unit: LeaseUnit,
    pub granted_at_ms: u64,
}

impl Vault {
    /// Records the grant of the config allocation `id`, once. Answers `None` when this call
    /// recorded it, so the caller grants it now, and the earlier grant when the vault recorded
    /// `id` before, so the caller grants nothing.
    ///
    /// # Errors
    ///
    /// The vault's write failed; nothing was recorded.
    pub fn record_host_allocation_grant(
        &self,
        id: &str,
        grant: &HostAllocationGrant,
    ) -> crate::Result<Option<HostAllocationGrant>> {
        let key = id.to_owned();
        self.with_write_txn_grouped(|txn| {
            if let Some(earlier) = GRANTS.get(&self.store, txn, &key)? {
                return Ok(Some(earlier));
            }
            GRANTS.put(&self.store, txn, &key, grant)?;
            Ok(None)
        })
    }

    /// The recorded grant of the config allocation `id`, if the vault holds one.
    ///
    /// # Errors
    ///
    /// The vault could not be read.
    pub fn host_allocation_grant(&self, id: &str) -> crate::Result<Option<HostAllocationGrant>> {
        GRANTS.get(&self.store, &self.store.env.read_txn()?, &id.to_owned())
    }
}
