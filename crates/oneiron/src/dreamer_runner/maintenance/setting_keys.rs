//! The settings the Dreamer's maintenance keeps (DESIGN 15-setting-primitive, stages 1 and 2):
//! each row is one catalogue key, and the crate's build script lists it in the setting catalogue.

use super::action_mode::ActionModePolicy;
use super::digest::{
    ProactivityDelivery, ProactivityPeriod, ProactivityPresentation,
    measure_presentation_and_notify, notify_proactivity_settings, shipped_delivery, shipped_period,
    shipped_presentation,
};
use crate::federation::EngineControlClass;
use crate::setting::{Kind, SetBy};

/// No action-mode policy: the default of `dreamer.action_mode.policy`.
fn no_action_mode_policy() -> Option<ActionModePolicy> {
    None
}

crate::setting::setting_keys! {
    /// The owner's action-mode policy (OF-335): the window each state index is measured over and
    /// the bands that name a mode. Absent, no policy is set and no night refreshes an index for
    /// it.
    pub(crate) ACTION_MODE_POLICY: Option<ActionModePolicy> = "dreamer.action_mode.policy" {
        kind: Kind::new(no_action_mode_policy),
        after_commit: Some(ActionModePolicy::measure_in_force),
    };
    /// Seconds between two regular proactivity digests. A holder of the maintenance cadence
    /// class moves it either way, as before: the period moves no access, authority, money or
    /// identity, so its order is neutral. The digest's delivery and presentation stay the
    /// owner's. Absent, the shipped digest_defaults.json decides.
    pub(crate) PROACTIVITY_PERIOD: ProactivityPeriod = "dreamer.proactivity.period" {
        kind: Kind::new(shipped_period).neutral(),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        after_commit: Some(notify_proactivity_settings),
    };
    /// How the regular proactivity digest is delivered: grouped by facet, and whether an urgent
    /// item goes out before the period ends. Absent, the shipped digest_defaults.json decides.
    pub(crate) PROACTIVITY_DELIVERY: ProactivityDelivery = "dreamer.proactivity.delivery" {
        kind: Kind::new(shipped_delivery),
        after_commit: Some(notify_proactivity_settings),
    };
    /// The proactivity digest's presentation: group aliases, its two templates, the voice style
    /// hint and the groups an urgent delivery may carry. An agent drafts it; only the owner sets
    /// it. Absent, the shipped digest_presentation_defaults.json decides.
    pub(crate) PROACTIVITY_PRESENTATION: ProactivityPresentation =
        "dreamer.proactivity.presentation" {
        kind: Kind::new(shipped_presentation),
        after_commit: Some(measure_presentation_and_notify),
    };
}
