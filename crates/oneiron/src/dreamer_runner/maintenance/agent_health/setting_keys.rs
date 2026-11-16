//! The agent-health review's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::federation::EngineControlClass;
use crate::setting::{Kind, LEARNED_SCOPES, SetBy};

crate::setting::setting_keys! {
    /// The review runs at all (1) or not (0).
    pub HEALTH_REVIEW: f64 = "health.review" {
        kind: Kind::new(|| 1.0).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `loop`: identical calls in a row, with no other call between them.
    pub HEALTH_LOOP_REPEATS: f64 = "health.loop.repeats" {
        kind: Kind::new(|| 3.0).learned(2.0, 100.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `failed_check_repeat`: the same tool run failing the same way, the canon
    /// failure-ladder N.
    pub HEALTH_CHECK_FAILS: f64 = "health.check.fails" {
        kind: Kind::new(|| 3.0).learned(2.0, 100.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `long_wait`: the share of an attempt's life spent waiting, not on a person.
    pub HEALTH_WAIT_SHARE: f64 = "health.wait.share" {
        kind: Kind::new(|| 0.5).learned(0.05, 1.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `long_wait`: the shortest attempt life the share is judged over.
    pub HEALTH_WAIT_MINUTES: f64 = "health.wait.minutes" {
        kind: Kind::new(|| 10.0).learned(1.0, 1440.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `silent`: minutes a leased attempt may go without activity of its own, a
    /// call or a model step at its lease generation (OF-568 L5).
    pub HEALTH_SILENT_MINUTES: f64 = "health.silent.minutes" {
        kind: Kind::new(|| 30.0).learned(1.0, 10080.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `misalignment`: widen proposals one attempt raised in the review window
    /// that the board has not approved, pending or declined.
    pub HEALTH_WIDEN_DENIALS: f64 = "health.widen.denials" {
        kind: Kind::new(|| 3.0).learned(1.0, 100.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `cost_spike`: an attempt's own spend over this many times its task type's
    /// p90, or the plan's expected spend while the type has too few runs.
    pub HEALTH_COST_SPIKE: f64 = "health.cost.spike" {
        kind: Kind::new(|| 3.0).learned(1.0, 100.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// Hours an open card waits on its leader before the owner gets a copy.
    pub HEALTH_ESCALATE_TTL_HOURS: f64 = "health.escalate.ttl_hours" {
        kind: Kind::new(|| 24.0).learned(1.0, 720.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The lowest card impact that still makes a card: struggling 100, off
    /// course 150, concern 200, so a concern always does. A finding below it
    /// writes its DIAGNOSTIC and no card.
    pub HEALTH_CARD_FLOOR: f64 = "health.card.floor" {
        kind: Kind::new(|| 0.0).learned(0.0, 200.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `duplicate_work`: the least spend, in policy-budget units (tokens), that a
    /// duplicate must cost to make a finding, so a cheap repeat is ignored. 0
    /// keeps every duplicate.
    pub HEALTH_DUP_MIN_COST: f64 = "health.dup.min_cost" {
        kind: Kind::new(|| 2_000.0).learned(0.0, 10_000_000.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The owner gets a copy of every card at once (1) or only of a concern, a
    /// card on the project's leader, a card with no other recipient and a card
    /// left open past the TTL (0). It only adds the owner: a concern always
    /// reaches the owner, whatever this says.
    pub HEALTH_OWNER_COPY: f64 = "health.card.owner_copy" {
        kind: Kind::new(|| 0.0).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// Hours back one review reads receipts and settled attempts.
    pub HEALTH_REVIEW_WINDOW_HOURS: f64 = "health.review.window_hours" {
        kind: Kind::new(|| 24.0).learned(1.0, 720.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// `cost_spike`: the settled runs of a task type its p90 needs; with fewer,
    /// the plan's expected spend is the baseline, at low confidence. It sets
    /// the baseline only, never which work runs.
    pub HEALTH_COST_MIN_RUNS: f64 = "health.cost.min_runs" {
        kind: Kind::new(|| 10.0).learned(1.0, 10_000.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };

    /// The complete UTC days each side of a trend comparison spans: the latest N
    /// against the N before them.
    pub HEALTH_TREND_PERIOD_DAYS: f64 = "health.trend.period_days" {
        kind: Kind::new(|| 7.0).learned(1.0, 365.0),
        scopes: &LEARNED_SCOPES,
        set_by: SetBy::Class(EngineControlClass::WakeCadence),
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
