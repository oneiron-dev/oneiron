//! The setting keys `skill_reliability` declares (Setting stage 1): the crate's build script lists
//! each row in the setting catalogue.

use super::floor::{DEFAULT_SKILL_RELIABILITY_FLOOR, ReliabilityFloor};
use crate::setting::Kind;

const fn default_reliability_floor() -> ReliabilityFloor {
    ReliabilityFloor(DEFAULT_SKILL_RELIABILITY_FLOOR)
}

crate::setting::setting_keys! {
    /// The posterior lower bound a skill's reliability must hold: below it, once the skill carries
    /// enough attributed outcomes, the projection proposes quarantine. Finite, within [0, 1].
    pub(crate) RELIABILITY_FLOOR: ReliabilityFloor = "skills.reliability_floor" {
        kind: Kind::new(default_reliability_floor),
    };
}
