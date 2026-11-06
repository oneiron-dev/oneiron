//! Core half of `settings::backup`: its store-layer items live in `oneiron_store::settings::backup` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::settings::backup::*;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

/// The owner's stored choice. Absent is no choice, never the defaults.
const POLICY: SideTable<(), BackupPolicy, Named> = SideTable::new(&side_table::BACKUP_POLICY);

impl Vault {
    /// The owner's stored backup choice, or `None` while he has made none.
    /// A stored row that does not decode, or breaks the rules, is an error,
    /// never no choice: reading it as none would hand an owner's explicit
    /// off back to the deployment's section.
    pub fn backup_policy(&self) -> Result<Option<BackupPolicy>> {
        let rtxn = self.store.env.read_txn()?;
        let stored = POLICY.get(&self.store, &rtxn, &())?;
        if stored.is_some_and(|policy| policy.problem().is_some()) {
            return Err(Error::CorruptedIndex("backup policy"));
        }
        Ok(stored)
    }

    /// The owner stores his backup choice, the whole triple at once, after
    /// [`BackupPolicy::problem`] finds nothing. `enabled: false` is a choice
    /// like any other, not a reset.
    pub fn set_backup_policy(
        &self,
        owner: &AuthenticatedOwner,
        policy: BackupPolicy,
    ) -> Result<()> {
        if let Some(problem) = policy.problem() {
            return Err(Error::InvalidConfig(problem.to_owned()));
        }
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            POLICY.put(&self.store, txn, &(), &policy)
        })
    }
}
