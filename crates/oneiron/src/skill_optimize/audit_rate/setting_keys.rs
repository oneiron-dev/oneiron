//! The random audit's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::federation::EngineControlClass;
use crate::setting::{Kind, LEARNED_SCOPES, SetBy};

crate::setting::setting_keys! {
    /// The probability of a random audit (`audit_rate`). Its floor is strictly
    /// above zero: the honesty floor never samples nothing.
    pub AUDIT_RATE: f64 = "audit.rate" {
        kind: Kind::new(|| 0.05).learned(0.001, 1.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
