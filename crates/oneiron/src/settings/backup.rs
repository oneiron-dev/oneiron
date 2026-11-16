//! Core half of `settings::backup`: its store-layer items live in `oneiron_store::settings::backup` and are
//! re-exported here; the items below stay in the engine. The owner's choice is the catalogue key
//! `backup.policy` (`settings::setting_keys`).

pub use oneiron_store::settings::backup::*;

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::SettingValue;
use serde::{Deserialize, Serialize};

use super::setting_keys::BACKUP_POLICY;

/// The owner's backup choice as the key `backup.policy` holds it: one policy, or none while he
/// has made none, never the defaults.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct BackupChoice(pub Option<BackupPolicy>);

impl SettingValue for BackupChoice {
    /// A stored policy breaks none of [`BackupPolicy::problem`]'s rules.
    fn check(self) -> Result<Self> {
        match self.0.as_ref().and_then(BackupPolicy::problem) {
            Some(problem) => Err(Error::InvalidConfig(problem.to_owned())),
            None => Ok(self),
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
        let stored = BACKUP_POLICY.read_in_txn(self, &rtxn, &[], None)?.value.0;
        if stored.is_some_and(|policy| policy.problem().is_some()) {
            return Err(Error::CorruptedIndex("backup policy"));
        }
        Ok(stored)
    }
}
