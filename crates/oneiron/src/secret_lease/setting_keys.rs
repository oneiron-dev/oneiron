//! The secret lease's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use super::grant::SECRET_GRANT_MAX_TTL_SECS;
use crate::setting::{Kind, lower_is_tighter};

/// One hour: the cap until the owner sets another.
fn one_hour() -> u64 {
    SECRET_GRANT_MAX_TTL_SECS
}

crate::setting::setting_keys! {
    /// The longest lifetime one secret grant takes, in seconds. A mint or a renewal that asks
    /// for longer is cut to it, and the answer's `expires_at` says so; a run host cuts the
    /// lifetime of the grants it mints for a run to it too, and with them the lifetime of the
    /// slip that run's credential helper and model door hold. One hour until the owner sets
    /// another; a value under one second reads as one second, and a row that does not decode
    /// reads as one hour. A longer cap is the looser value, so only the owner raises it; an
    /// agent's raise waits on the owner's answer. A T1 or T2 grant for a door effector still
    /// meets the credential door's own lease ceiling (`secret.door.max_lease_ttl_secs`).
    pub(crate) SECRET_GRANT_MAX_TTL: u64 = "secrets.grant.max_ttl_secs" {
        kind: Kind::new(one_hour).strictest(one_hour).tighter(lower_is_tighter::<u64>),
    };
}
