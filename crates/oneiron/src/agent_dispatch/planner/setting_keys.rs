//! The spawn planner's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::setting::{Kind, LEARNED_SCOPES};

crate::setting::setting_keys! {
    /// The spawn planner's solo-first gate floor (ARCH-0079 #planner, OF-541):
    /// when solo's measured success rate for a task type is at or above this,
    /// a team must clear [`PLANNER_SOLO_MARGIN`] past solo to displace it.
    pub PLANNER_SOLO_SUCCESS_FLOOR: f64 = "planner.solo_success_floor" {
        kind: Kind::new(|| 0.7).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// How far past solo's success rate a team shape must project before the
    /// planner prefers it once the solo-first gate is engaged.
    pub PLANNER_SOLO_MARGIN: f64 = "planner.solo_margin" {
        kind: Kind::new(|| 0.05).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The spawn width at which a plan counts as big and the planner ladder
    /// climbs to its strong rung regardless of care.
    pub PLANNER_BIG_PLAN_WIDTH: f64 = "planner.big_plan_width" {
        kind: Kind::new(|| 16.0).learned(1.0, 10000.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
