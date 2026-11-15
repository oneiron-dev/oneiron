//! The browser program library's Setting key (restriction wave 13, census C125; the owner's
//! principle of 16 Nov: an optional freedom with a good default): how many strict misses in a row
//! retire a filed program as drift (CUA E2). The default is the count the library has always
//! used. The owner changes it; an agent's change waits on the owner's approval.
//!
//! Direction: a lower count is tighter, since a program that keeps missing its postcondition is
//! retired sooner and no longer replays. A row that does not decode reads as one miss.

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::STRICT_MISSES_BEFORE_DRIFT;
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// Strict misses in a row that retire a program: at least 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct DriftMissCount(pub(crate) u32);

impl SettingValue for DriftMissCount {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "a program retires as drift after at least 1 strict miss".to_owned(),
            ))
        }
    }
}

fn default_drift_misses() -> DriftMissCount {
    DriftMissCount(STRICT_MISSES_BEFORE_DRIFT)
}

fn fewest_drift_misses() -> DriftMissCount {
    DriftMissCount(1)
}

crate::setting::setting_keys! {
    /// Strict misses in a row that retire a filed browser program as drift (default 3). Lower is
    /// tighter: the run that makes a program's strict misses this many retires it in the same
    /// write (record_workflow_run), and a retired program no longer resolves for a replay.
    pub(crate) BROWSER_LIBRARY_DRIFT_MISSES: DriftMissCount = "browser.library.drift_misses" {
        kind: Kind::new(default_drift_misses)
            .strictest(fewest_drift_misses)
            .tighter(lower_is_tighter::<DriftMissCount>),
    };
}

/// The strict misses in a row that retire a program in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn drift_misses_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<u32> {
    Ok(BROWSER_LIBRARY_DRIFT_MISSES
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0)
}
