//! The org two-admin rule's Setting keys (canon identity.md:223, ORG-1 A;
//! lead ORG-TWO-ADMIN-SCOPE, 15 Nov 20:1x; Engine RULING UNBUILT06-SHAPE Q4 = A).
//! Both sit at the shared vault, an Owner sets them (in a shared vault that is
//! any live Owner, through `vault.settings.set`), and every member reads them.

use crate::setting::{Kind, ReadBy, SettingValue, higher_is_tighter};

/// The rule is off until an Owner turns it on: "an admin should be able to just do".
fn two_admin_off() -> bool {
    false
}

/// On is the strict side: every admin power act waits for a second admin.
fn two_admin_on() -> bool {
    true
}

/// The longest a held admin act waits for its second admin: 90 days, in
/// seconds. A longer lapse refuses when an Owner sets it, so every held act
/// lapses in time (Astra on #8482, H4: a lapse near `u64::MAX` saturated to
/// a deadline that never came).
pub(crate) const TWO_ADMIN_LAPSE_CEILING_SECS: u64 = 90 * 24 * 60 * 60;

/// `org.two_admin_lapse_secs`'s value: seconds, at most
/// [`TWO_ADMIN_LAPSE_CEILING_SECS`]. Stored and read as a plain number.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct TwoAdminLapseSecs(u64);

impl TwoAdminLapseSecs {
    /// The lapse in seconds.
    pub(crate) const fn secs(self) -> u64 {
        self.0
    }
}

impl SettingValue for TwoAdminLapseSecs {
    fn check(self) -> oneiron_contracts::error::Result<Self> {
        if self.0 > TWO_ADMIN_LAPSE_CEILING_SECS {
            return Err(oneiron_contracts::error::Error::InvalidConfig(format!(
                "org.two_admin_lapse_secs is at most {TWO_ADMIN_LAPSE_CEILING_SECS} seconds (90 days)"
            )));
        }
        Ok(self)
    }
}

/// Seven days, in seconds.
fn seven_days() -> TwoAdminLapseSecs {
    TwoAdminLapseSecs(7 * 24 * 60 * 60)
}

crate::setting::setting_keys! {
    /// Whether an Admin's or a Deputy's power act in this shared vault waits for a second,
    /// distinct live admin's approve before it runs. An Owner's own act never waits.
    pub(crate) ORG_TWO_ADMIN: bool = "org.two_admin" {
        kind: Kind::new(two_admin_off).strictest(two_admin_on).tighter(higher_is_tighter::<bool>),
        read_by: ReadBy::Members,
    };
    /// How long, in seconds, a held admin act waits for its second admin before it lapses
    /// and its first admin is told: at most 90 days (7776000).
    pub(crate) ORG_TWO_ADMIN_LAPSE_SECS: TwoAdminLapseSecs = "org.two_admin_lapse_secs" {
        kind: Kind::new(seven_days),
        read_by: ReadBy::Members,
    };
}
