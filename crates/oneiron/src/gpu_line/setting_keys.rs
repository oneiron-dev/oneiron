//! The cadence of the line notices a clock makes due ([`super::notice::LINE_NOTICES_JOB`]): a
//! unit unconfirmed past its maximum plus one hour, and a review overdue (design pass 32 r2,
//! section 6). The bounds those notices measure are line fields (`BudgetPolicy`); only the
//! engine's cadence is a vault Setting. More often is tighter: a `maintenance_cadence` holder may
//! raise them sooner, never later, without the owner.

use crate::federation::EngineControlClass;
use crate::schedule::{Trigger, more_often_is_tighter};
use crate::setting::{Kind, SetBy};

fn hourly() -> Trigger {
    Trigger::Every {
        secs: 3_600,
        first_at: None,
    }
}

crate::setting::setting_keys! {
    /// How often the engine raises the line notices the clock makes due (a unit unconfirmed, a
    /// review overdue): hourly.
    pub(crate) LINE_NOTICES_EVERY: Trigger = "lines.notices.every" {
        kind: Kind::new(hourly).custom(more_often_is_tighter),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
}
