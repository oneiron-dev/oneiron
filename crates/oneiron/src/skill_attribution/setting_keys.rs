//! Skill attribution's and lineage credit's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::federation::EngineControlClass;
use crate::setting::{Kind, LEARNED_SCOPES, SetBy};

crate::setting::setting_keys! {
    /// The attribution judge's confidence floor (ARCH-0056 §5 #unclear-floor):
    /// below it, a hunk's verdict is recorded as `unclear` and charges nobody.
    pub ATTRIBUTION_UNCLEAR_FLOOR: f64 = "attribution.unclear_floor" {
        kind: Kind::new(|| 0.6).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The share of credited runs whose followed skills get a matched-fork
    /// contribution check (ARCH-0037 #lineage-credit): each check regenerates a
    /// step twice, with and without the skill. Zero checks none.
    pub CONTRIBUTION_CHECK_RATE: f64 = "contribution.check_rate" {
        kind: Kind::new(|| 0.1).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The share of credit a used lineage hop passes up (ARCH-0003
    /// #learning-settings `credit_decay`): halving per hop by default.
    pub CREDIT_DECAY: f64 = "credit.decay" {
        kind: Kind::new(|| 0.5).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// Whether used lineage hops pass late credit up at all (ARCH-0037
    /// #lineage-credit, the power user's off switch): on at one half or more.
    pub CREDIT_ENABLED: f64 = "credit.enabled" {
        kind: Kind::new(|| 1.0).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The most used hops late credit climbs from an outcome (ARCH-0037
    /// #lineage-credit); at its maximum, the full used chain, canon's default.
    pub CREDIT_DEPTH_CAP: f64 = "credit.depth_cap" {
        kind: Kind::new(|| 1024.0).learned(0.0, 1024.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// Whether late credit crosses only hops a contribution check measured
    /// (ARCH-0037 #lineage-credit): on at one half or more; off by default, so
    /// an unchecked used hop passes credit.
    pub CREDIT_CHECK_EVERY_HOP: f64 = "credit.check_every_hop" {
        kind: Kind::new(|| 0.0).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
