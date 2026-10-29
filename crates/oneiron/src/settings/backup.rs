//! The owner's backup setting (FIX 5621): whether a running server takes
//! backups on its own, how many hours apart, and how many it keeps. It is
//! owner policy kept in the vault, one row for the whole choice. A server's
//! schedule follows it over the deployment's `[backup]` section, which
//! decides while the owner has stored none; where backups go stays the
//! deployment's alone. A checkpoint keeps the row, and a restore keeps the
//! live vault's.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// Hours between scheduled backups when nothing sets them.
pub const DEFAULT_EVERY_HOURS: u64 = 24;
/// Newest backups kept when nothing sets it.
pub const DEFAULT_KEEP: usize = 7;

/// The owner's stored choice. Absent is no choice, never the defaults.
const POLICY: SideTable<(), BackupPolicy, Named> = SideTable::new(&side_table::BACKUP_POLICY);

/// One backup policy: the owner's choice, or the deployment's `[backup]`
/// section read as one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupPolicy {
    /// Whether a running server takes backups on its own. A backup asked
    /// for now is taken either way.
    pub enabled: bool,
    /// Hours between scheduled backups.
    pub every_hours: u64,
    /// Newest backups kept; older ones are deleted after each new backup.
    pub keep: usize,
}

impl Default for BackupPolicy {
    /// Off, one a day, the newest seven kept.
    fn default() -> Self {
        Self {
            enabled: false,
            every_hours: DEFAULT_EVERY_HOURS,
            keep: DEFAULT_KEEP,
        }
    }
}

impl BackupPolicy {
    /// The rule this policy breaks, naming its field, or `None`: `every_hours`
    /// and `keep` are each greater than zero, with the schedule on or off.
    /// These are the `[backup]` section's own rules; nothing else bounds them.
    #[must_use]
    pub const fn problem(&self) -> Option<&'static str> {
        if self.every_hours == 0 {
            Some("every_hours must be greater than zero")
        } else if self.keep == 0 {
            Some("keep must be greater than zero; set enabled to false to stop scheduled backups")
        } else {
            None
        }
    }
}

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
