//! The authority's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.
//!
//! Each key holds a lifetime the code fixed before (restriction census wave 1; owner 16 Nov
//! 00:44: "we apply the optional freedom with good defaults everywhere"). Its default is that
//! lifetime, so nothing moves until the owner moves it. A longer life is the looser value: only
//! the owner raises one, and an agent's raise waits on the owner's answer.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::step_up::STEP_UP_CHALLENGE_TTL_SECS;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// A lifetime in whole seconds, at least one: a lifetime of zero ends before anything can use it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct LifetimeSecs(u64);

impl LifetimeSecs {
    /// The lifetime in seconds.
    pub(crate) const fn secs(self) -> u64 {
        self.0
    }
}

impl SettingValue for LifetimeSecs {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            return Err(Error::InvalidConfig(
                "a lifetime is at least one second".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// Five minutes: WebAuthn's own default ceremony timeout.
fn step_up_challenge_default() -> LifetimeSecs {
    LifetimeSecs(STEP_UP_CHALLENGE_TTL_SECS)
}

/// One year.
fn mesh_grant_default() -> LifetimeSecs {
    LifetimeSecs(365 * 24 * 60 * 60)
}

crate::setting::setting_keys! {
    /// How long a step-up ceremony stays open, in seconds: a passkey challenge, and an
    /// authenticator app's enrolment, must be answered within it, or the ceremony starts again.
    /// Five minutes by default, WebAuthn's own default ceremony timeout. Each challenge still
    /// takes one answer. Longer is the looser value, so only the owner raises it; an agent's
    /// raise waits on the owner's answer.
    pub(crate) STEP_UP_CHALLENGE_TTL: LifetimeSecs = "step_up.challenge.ttl_secs" {
        kind: Kind::new(step_up_challenge_default)
            .strictest(step_up_challenge_default)
            .tighter(lower_is_tighter::<LifetimeSecs>),
    };

    /// The longest the owner's mesh grant to a paired machine runs, in seconds. One year by
    /// default. A machine's enrolment pairs it for this long, and a grant never outlives the
    /// pairing it rides on. Longer is the looser value, so only the owner raises it; an agent's
    /// raise waits on the owner's answer.
    pub(crate) MESH_GRANT_MAX_TTL: LifetimeSecs = "mesh.grant.max_ttl_secs" {
        kind: Kind::new(mesh_grant_default)
            .strictest(mesh_grant_default)
            .tighter(lower_is_tighter::<LifetimeSecs>),
    };
}
