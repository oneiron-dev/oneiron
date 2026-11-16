//! The Coach's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::federation::EngineControlClass;
use crate::setting::{Kind, LEARNED_SCOPES, SetBy};

crate::setting::setting_keys! {
    /// Hours a pending tradeoff ask waits on one rung before it climbs, a learned
    /// setting the owner seeds or pins (FIX 707). Canon names no window; the
    /// shipped seed is one night apart, less an hour of wake jitter, so a nightly
    /// pass climbs once a night.
    pub TRADEOFF_REMINDER_HOURS: f64 = "coach.tradeoff_reminder_hours" {
        kind: Kind::new(|| 23.0).learned(1.0, 720.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// How many distinct outcomes a pattern's live notes must come from before
    /// the Coach proposes a label for it. Canon names no count; two is the least
    /// that can recur, and the seed asks for three.
    pub ATTRIBUTION_LABEL_RECEIPTS: f64 = "coach.attribution_label_receipts" {
        kind: Kind::new(|| 3.0).learned(2.0, 1_000_000.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
