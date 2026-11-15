//! The setting keys `skill_reliability` declares (Setting stage 1): the crate's build script lists
//! each row in the setting catalogue.

use super::floor::{
    DEFAULT_SKILL_RELIABILITY_FLOOR, ReliabilityFloor, ReliabilityFloorMinOutcomes,
    SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES,
};
use crate::setting::{Kind, higher_is_tighter};

const fn default_reliability_floor() -> ReliabilityFloor {
    ReliabilityFloor(DEFAULT_SKILL_RELIABILITY_FLOOR)
}

const fn default_floor_min_outcomes() -> ReliabilityFloorMinOutcomes {
    ReliabilityFloorMinOutcomes(SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES)
}

crate::setting::setting_keys! {
    /// The posterior lower bound a skill's reliability must hold: below it, once the skill carries
    /// enough attributed outcomes, the projection proposes quarantine. Finite, within [0, 1].
    pub(crate) RELIABILITY_FLOOR: ReliabilityFloor = "skills.reliability_floor" {
        kind: Kind::new(default_reliability_floor),
    };
    /// The attributed outcomes a skill's learning cell must carry before the reliability floor
    /// can propose quarantine. At least one; a lower count is a loosening (an earlier proposal,
    /// never an automatic quarantine).
    pub(crate) RELIABILITY_FLOOR_MIN_OUTCOMES: ReliabilityFloorMinOutcomes =
        "skills.reliability_floor_min_outcomes" {
        kind: Kind::new(default_floor_min_outcomes)
            .tighter(higher_is_tighter::<ReliabilityFloorMinOutcomes>),
    };
}
