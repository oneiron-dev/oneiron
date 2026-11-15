//! The connector call owner Setting keys (DESIGN 15-setting-primitive; restriction census C21,
//! owner 16 Nov 00:44: "we apply the optional freedom with good defaults everywhere"): rows the
//! setting catalogue reads from this file.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// The shipped lifetime of a held connector call: seven days.
pub(crate) const DEFAULT_CONNECTOR_CALL_PENDING_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// The shortest lifetime: one minute, the settler's pass.
const MIN_CONNECTOR_CALL_PENDING_TTL_SECS: u64 = 60;

/// The longest lifetime: a number every SDK carries exactly.
const MAX_CONNECTOR_CALL_PENDING_TTL_SECS: u64 = (1 << 53) - 1;

/// Seconds a held or pending-delivery connector call waits, from when it was first held: at
/// least [`MIN_CONNECTOR_CALL_PENDING_TTL_SECS`] and at most
/// [`MAX_CONNECTOR_CALL_PENDING_TTL_SECS`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ConnectorCallPendingSecs(pub(crate) u64);

impl SettingValue for ConnectorCallPendingSecs {
    fn check(self) -> Result<Self> {
        if (MIN_CONNECTOR_CALL_PENDING_TTL_SECS..=MAX_CONNECTOR_CALL_PENDING_TTL_SECS)
            .contains(&self.0)
        {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a held connector call waits {MIN_CONNECTOR_CALL_PENDING_TTL_SECS} to \
                 {MAX_CONNECTOR_CALL_PENDING_TTL_SECS} seconds"
            )))
        }
    }
}

fn shipped_pending_ttl() -> ConnectorCallPendingSecs {
    ConnectorCallPendingSecs(DEFAULT_CONNECTOR_CALL_PENDING_TTL_SECS)
}

crate::setting::setting_keys! {
    /// How long a held connector call waits for someone to allow it, in seconds from when it was
    /// first held (seven days by default). A call nobody allows, and a sent call whose delivery
    /// stays unknown, settles as expired once this passes; a retry never moves the deadline. The
    /// value is read at each expiry pass, so a longer one keeps every held call open longer and
    /// a shorter one expires a call held longer than it at the next pass. A connector event wake
    /// a full count window paces fixes its deadline with the value in force at its first
    /// deferral. Longer is the looser value: only the owner sets it, and an agent's change waits
    /// on the owner's answer. A row that does not decode reads as the shipped seven days, so it
    /// neither strands a call nor expires one early.
    pub(crate) CONNECTOR_CALL_PENDING_TTL: ConnectorCallPendingSecs =
        "connectors.calls.pending_ttl_secs" {
        kind: Kind::new(shipped_pending_ttl)
            .strictest(shipped_pending_ttl)
            .tighter(lower_is_tighter::<ConnectorCallPendingSecs>),
    };
}
