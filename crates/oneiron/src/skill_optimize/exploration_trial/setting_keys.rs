//! The exploration trial ask's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::setting::{Kind, LEARNED_SCOPES};

crate::setting::setting_keys! {
    /// Hours an unanswered overrun ask waits on the role it went to before it
    /// climbs to the next role up its chain: the ask's reminder. At the chain's
    /// top it waits on, until [`EXPLORATION_ASK_LAPSE_HOURS`].
    pub EXPLORATION_ASK_CLIMB_HOURS: f64 = "exploration.ask.climb_hours" {
        kind: Kind::new(|| 24.0).learned(1.0, 720.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// Hours an unanswered overrun ask waits at the top of its chain, counted
    /// from its last climb, before it lapses as a decline: the trial closes and
    /// its routed runs are measured. Checked once the climb window has passed too.
    pub EXPLORATION_ASK_LAPSE_HOURS: f64 = "exploration.ask.lapse_hours" {
        kind: Kind::new(|| 72.0).learned(1.0, 2160.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
