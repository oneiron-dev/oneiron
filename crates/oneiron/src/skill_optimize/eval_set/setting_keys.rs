//! The offer eval set floor's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::setting::{Kind, LEARNED_SCOPES};

crate::setting::setting_keys! {
    /// The fewest families an offer eval set needs (FIX 10446): the owner's
    /// floor for a measured card. Zero asks for none.
    pub EVAL_FLOOR_MIN_FAMILIES: f64 = "eval_floor.min_families" {
        kind: Kind::new(|| 0.0).learned(0.0, 1_000_000.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The fewest families each required floor slice needs (FIX 10446). Zero
    /// asks for none.
    pub EVAL_FLOOR_MIN_FAMILIES_PER_SLICE: f64 = "eval_floor.min_families_per_slice" {
        kind: Kind::new(|| 0.0).learned(0.0, 1_000_000.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
