//! The setting keys `claim` declares (restriction wave 8): the crate's build script lists each row
//! in the setting catalogue.

use super::observed_preference::{
    OBSERVED_PREFERENCE_MIN_OBSERVATIONS, OBSERVED_PREFERENCE_MIN_SESSIONS, ObservedPreferenceCount,
};
use crate::setting::{Kind, higher_is_tighter};

fn count_of(count: usize) -> ObservedPreferenceCount {
    ObservedPreferenceCount(u32::try_from(count).unwrap_or(u32::MAX))
}

fn default_min_observations() -> ObservedPreferenceCount {
    count_of(OBSERVED_PREFERENCE_MIN_OBSERVATIONS)
}

fn default_min_sessions() -> ObservedPreferenceCount {
    count_of(OBSERVED_PREFERENCE_MIN_SESSIONS)
}

crate::setting::setting_keys! {
    /// The distinct observations (live, non-imported user TURNs) an Observed preference about the
    /// owner needs; at least 1. A preference about any other person keeps ARCH-0003's three.
    pub(crate) OBSERVED_PREFERENCE_OBSERVATIONS: ObservedPreferenceCount =
        "claim.observed_preference.min_observations" {
        kind: Kind::new(default_min_observations)
            .tighter(higher_is_tighter::<ObservedPreferenceCount>),
    };
    /// The distinct live SESSIONs an Observed preference about the owner's observations span; at
    /// least 1. A preference about any other person keeps ARCH-0003's two.
    pub(crate) OBSERVED_PREFERENCE_SESSIONS: ObservedPreferenceCount =
        "claim.observed_preference.min_sessions" {
        kind: Kind::new(default_min_sessions)
            .tighter(higher_is_tighter::<ObservedPreferenceCount>),
    };
}
