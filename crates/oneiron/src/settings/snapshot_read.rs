//! The owner's bounds on primitive A's snapshot handles (slice 6.4b; lead 19:4x
//! S64-2-SETTINGS): one value holds all six, and an unset key reads as the
//! defaults below. The cap at a credential's own expiry is not a setting: it
//! is a security property, fixed in `crate::snapshot_read`.
//!
//! It is the catalogue key `snapshot_read.bounds` (`settings::setting_keys`),
//! set through `vault.settings.set` by the owner, or by a holder of
//! `engine.controls.work_budget` (untangle 6.6f; SNAPSHOT-SETTINGS-IN-6.6).
//! Every bound's lower value is the tighter one, so the key's rows meet bound
//! by bound (`each_order!` below). A holder's change that lowers lands, under
//! the owner's row too, and any change of theirs that raises a bound waits on
//! the owner's check-in (AUTH-1), its own lowering's too. Every change is one
//! `SETTING_CHANGE` row. The read (`vault.settings.get`) answers the owner, a
//! holder, or a whole-vault Steward grant naming any `engine.controls` class,
//! as every dial read does (S66F-READ = C).

use serde::{Deserialize, Serialize};

use super::setting_keys::SNAPSHOT_READ_BOUNDS;
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::SettingValue;

/// The bounds every snapshot handle is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReadSettings {
    /// Handles one actor may hold open at once.
    pub open_per_actor: u32,
    /// A handle's lifetime when its opener names none, in seconds.
    pub default_lifetime_secs: u64,
    /// The longest lifetime an opener may ask for, in seconds.
    pub max_lifetime_secs: u64,
    /// The most rows one page serves.
    pub page_rows: u32,
    /// The most bytes of rows one page serves.
    pub page_bytes: u64,
    /// The most rows one handle serves over all its pages.
    pub handle_rows: u64,
}

impl SnapshotReadSettings {
    /// The defaults (lead 19:4x): 8 open per actor, 10 min by default and
    /// 60 min at most, 200 rows and 4 MiB per page, 20,000 rows per handle.
    pub const DEFAULT: Self = Self {
        open_per_actor: 8,
        default_lifetime_secs: 600,
        max_lifetime_secs: 3_600,
        page_rows: 200,
        page_bytes: 4 * 1024 * 1024,
        handle_rows: 20_000,
    };

    /// Refuses a zero bound, and a default lifetime above the most lifetime.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming the bound.
    pub fn validate(&self) -> Result<()> {
        let zero = [
            ("open_per_actor", u64::from(self.open_per_actor)),
            ("default_lifetime_secs", self.default_lifetime_secs),
            ("max_lifetime_secs", self.max_lifetime_secs),
            ("page_rows", u64::from(self.page_rows)),
            ("page_bytes", self.page_bytes),
            ("handle_rows", self.handle_rows),
        ]
        .into_iter()
        .find(|(_, bound)| *bound == 0);
        if let Some((name, _)) = zero {
            return Err(Error::InvalidConfig(format!(
                "the snapshot bound {name} must be above zero"
            )));
        }
        if self.default_lifetime_secs > self.max_lifetime_secs {
            return Err(Error::InvalidConfig(
                "the default snapshot lifetime must not exceed the most lifetime".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Default for SnapshotReadSettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl SettingValue for SnapshotReadSettings {
    fn check(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }
}

oneiron_setting_contract::each_order!(SnapshotReadSettings {
    open_per_actor: lower,
    default_lifetime_secs: lower,
    max_lifetime_secs: lower,
    page_rows: lower,
    page_bytes: lower,
    handle_rows: lower,
});

impl Vault {
    /// The snapshot bounds in force: the owner's, a holder's lowering inside
    /// them, or the defaults while none is set.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn snapshot_read_settings(&self) -> Result<SnapshotReadSettings> {
        let rtxn = self.store.env.read_txn()?;
        Ok(SNAPSHOT_READ_BOUNDS
            .read_in_txn(self, &rtxn, &[], None)?
            .value)
    }
}
