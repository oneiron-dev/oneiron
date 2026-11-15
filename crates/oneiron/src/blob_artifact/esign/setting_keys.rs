//! The e-signature ask's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::setting::{Kind, LEARNED_SCOPES};

crate::setting::setting_keys! {
    /// Hours a held sign act's unanswered ask waits on the person it went to
    /// before it climbs to the next role up its chain (CALLS "OF-415 held
    /// signing climb"). At the vault owners it waits on: no unanswered ask
    /// signs or lapses.
    pub ESIGN_ASK_CLIMB_HOURS: f64 = "esign.ask.climb_hours" {
        kind: Kind::new(|| 24.0).learned(1.0, 720.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
