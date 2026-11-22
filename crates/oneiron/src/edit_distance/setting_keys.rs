//! The catalogue keys `edit_distance` declares (DESIGN 15-setting-primitive, stage 1): the
//! publisher share dial (ED-08) and its install profile's default.

use crate::setting::{Kind, SettingSync};

use super::publisher::PUBLISHER_ENABLED_COMPILED_DEFAULT;

fn compiled_default() -> bool {
    PUBLISHER_ENABLED_COMPILED_DEFAULT
}

/// What an unreadable dial reads as: off, so no signature leaves on a dial nobody can read.
fn disabled() -> bool {
    false
}

crate::setting::setting_keys! {
    /// The owner's publisher share dial (ED-08): whether issue signatures may go to the
    /// publisher. With no row the install profile's default decides, then the compiled default
    /// (off).
    pub(crate) PUBLISHER_ENABLED: bool = "edit_distance.publisher.enabled" {
        kind: Kind::new(compiled_default).strictest(disabled),
    };
    /// The install profile's default for the publisher share dial, written at provisioning: the
    /// cloud posture's default-on (ARCH-0056 section 9 rung 1, owner ruling r6), or a self-host
    /// install's own answer. It never overrides the owner's dial.
    pub(crate) PUBLISHER_INSTALL_DEFAULT: bool = "edit_distance.publisher.install_default" {
        kind: Kind::new(compiled_default).strictest(disabled),
        sync: SettingSync::Install,
    };
}
