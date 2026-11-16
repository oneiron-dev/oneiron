//! Self-heal's detector learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::federation::EngineControlClass;
use crate::setting::{Kind, LEARNED_SCOPES, SetBy};

crate::setting::setting_keys! {
    /// The cosine a T2a candidate must reach against its corpus's centroid (FIX
    /// 2078): an owner-steered catalog row over every cosine, -1 to 1.
    pub DETECTOR_CENTROID_MIN_SIMILARITY: f64 = "detector.centroid.min_similarity" {
        kind: Kind::new(|| 0.8).learned(-1.0, 1.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
