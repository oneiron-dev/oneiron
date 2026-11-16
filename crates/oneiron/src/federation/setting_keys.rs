//! The org two-admin rule's Setting keys (canon identity.md:223, ORG-1 A;
//! lead ORG-TWO-ADMIN-SCOPE, 15 Nov 20:1x; Engine RULING UNBUILT06-SHAPE Q4 = A).
//! Both sit at the shared vault, an Owner sets them (in a shared vault that is
//! any live Owner, through `vault.settings.set`), and every member reads them.

use crate::setting::{Kind, ReadBy, higher_is_tighter};

/// The rule is off until an Owner turns it on: "an admin should be able to just do".
fn two_admin_off() -> bool {
    false
}

/// On is the strict side: every admin power act waits for a second admin.
fn two_admin_on() -> bool {
    true
}

/// Seven days, in seconds.
fn seven_days() -> u64 {
    7 * 24 * 60 * 60
}

crate::setting::setting_keys! {
    /// Whether an Admin's or a Deputy's power act in this shared vault waits for a second,
    /// distinct live admin's approve before it runs. An Owner's own act never waits.
    pub(crate) ORG_TWO_ADMIN: bool = "org.two_admin" {
        kind: Kind::new(two_admin_off).strictest(two_admin_on).tighter(higher_is_tighter::<bool>),
        read_by: ReadBy::Members,
    };
    /// How long, in seconds, a held admin act waits for its second admin before it lapses
    /// and its first admin is told.
    pub(crate) ORG_TWO_ADMIN_LAPSE_SECS: u64 = "org.two_admin_lapse_secs" {
        kind: Kind::new(seven_days),
        read_by: ReadBy::Members,
    };
}
