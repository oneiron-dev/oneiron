//! The setting keys `skill_optimize` declares (Setting stage 1): the crate's build script lists
//! each row in the setting catalogue.

use super::{
    DEFAULT_SKILL_EDIT_CYCLE_CAP, DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES, SkillEditCycleCap,
    SkillOptimizeMinOutcomes,
};
use crate::setting::Kind;

const fn default_min_outcomes() -> SkillOptimizeMinOutcomes {
    SkillOptimizeMinOutcomes(DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES)
}

const fn default_edit_cycle_cap() -> SkillEditCycleCap {
    SkillEditCycleCap(DEFAULT_SKILL_EDIT_CYCLE_CAP)
}

crate::setting::setting_keys! {
    /// N: the attributed outcomes a skill must carry before the optimizer may draft an edit of
    /// it. Above zero.
    pub(crate) MIN_OUTCOMES: SkillOptimizeMinOutcomes = "skills.optimize.min_outcomes" {
        kind: Kind::new(default_min_outcomes),
    };
    /// K: the accepted skill edits one Dreamer cycle may admit; the overflow is deferred, not
    /// lost. Above zero.
    pub(crate) EDIT_CYCLE_CAP: SkillEditCycleCap = "skills.optimize.edit_cycle_cap" {
        kind: Kind::new(default_edit_cycle_cap),
    };
}
