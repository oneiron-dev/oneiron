//! The learning projector's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::federation::EngineControlClass;
use crate::setting::{Kind, LEARNED_SCOPES, SetBy};

crate::setting::setting_keys! {
    /// The `learning.*` window: old runs halve in weight every this many days, so
    /// a silent vendor update under one model id shows up in the estimate.
    pub LEARNING_WINDOW_HALF_LIFE_DAYS: f64 = "learning.window_half_life_days" {
        kind: Kind::new(|| 90.0).learned(1.0, 3650.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The weight in runs a catalog seed carries as a `learning.setting` prior
    /// when the owner has seeded nothing.
    pub LEARNING_SHIPPED_PRIOR_RUNS: f64 = "learning.shipped_prior_runs" {
        kind: Kind::new(|| 2.0).learned(0.0, 100.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The most runs a borrowed reading (a parent type's, another executor's)
    /// counts as: carried weakly, so a cell's own runs soon outweigh it.
    pub LEARNING_BORROWED_PRIOR_RUNS: f64 = "learning.borrowed_prior_runs" {
        kind: Kind::new(|| 2.0).learned(0.0, 100.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
