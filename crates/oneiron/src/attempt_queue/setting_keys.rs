//! The setting keys `attempt_queue` declares (restriction wave 17): the crate's build script
//! lists each row in the setting catalogue.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::cancel::{
    LANDING_RESERVE_PERCENT, LEASE_LANDING_WARNING_PERCENT, MAX_LANDING_RESERVE_PERCENT,
};
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};
use crate::store::Store;

/// The largest landing reserve a caller may dial, as a percent of the attempt's budget: from
/// the default reserve up to the whole budget. A bound below the default reserve would refuse
/// every attempt that dials none.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct MaxReservePercent(pub(crate) u64);

impl SettingValue for MaxReservePercent {
    fn check(self) -> Result<Self> {
        if (LANDING_RESERVE_PERCENT..=100).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "the largest landing reserve is a percent of the budget from \
                 {LANDING_RESERVE_PERCENT} (the default reserve) to 100"
            )))
        }
    }
}

/// When the runtime warns a worker to land, as a percent of its lease timeout: 1 to 100. The
/// warning stays one second before expiry at most, whatever the percent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct LeaseWarningPercent(pub(crate) u64);

impl SettingValue for LeaseWarningPercent {
    fn check(self) -> Result<Self> {
        if (1..=100).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "the lease warning is a percent of the lease timeout from 1 to 100".into(),
            ))
        }
    }
}

const fn default_max_reserve() -> MaxReservePercent {
    MaxReservePercent(MAX_LANDING_RESERVE_PERCENT)
}

const fn default_lease_warning() -> LeaseWarningPercent {
    LeaseWarningPercent(LEASE_LANDING_WARNING_PERCENT)
}

crate::setting::setting_keys! {
    /// The largest landing reserve a caller may dial for an attempt, as a percent of its budget
    /// (ONE-1896): 50 unless the owner sets it, from 10 (the default reserve) to 100. A higher
    /// bound lets an attempt hold more of its budget back for landing.
    pub(crate) LANDING_MAX_RESERVE_PERCENT: MaxReservePercent = "attempt_queue.landing.max_reserve_percent" {
        kind: Kind::new(default_max_reserve).tighter(lower_is_tighter),
    };
    /// How far into its lease, as a percent of the lease timeout, the runtime warns a worker to
    /// land (ONE-1896): 80 unless the owner sets it, from 1 to 100. The warning asks and expiry
    /// forces; the warning stays at least one second before expiry. It widens nothing, so it
    /// names no tighter direction.
    pub(crate) LEASE_WARNING_PERCENT: LeaseWarningPercent = "attempt_queue.lease.warning_percent" {
        kind: Kind::new(default_lease_warning),
    };
}

/// The owner's `attempt_queue.landing.max_reserve_percent`, read in `txn`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn max_reserve_percent_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u64> {
    Ok(LANDING_MAX_RESERVE_PERCENT
        .read_in_dbs_txn(store, txn, &[], None)?
        .value
        .0)
}

/// The owner's `attempt_queue.lease.warning_percent`, read in `txn`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn lease_warning_percent_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u64> {
    Ok(LEASE_WARNING_PERCENT
        .read_in_dbs_txn(store, txn, &[], None)?
        .value
        .0)
}
