//! The cadences of the engine's 19 sweeps (DESIGN 15-setting-primitive, stage 5a): one catalogue
//! key each, `housekeeping.<sweep>.every`, whose value in force arms the sweep's job
//! ([`super::jobs`]). The owner sets them, and so does a live holder of the
//! `maintenance_cadence` class of `engine.controls` unless the owner has set the key. The write
//! that changes a key arms its job again (`schedule::rearm_on_change`). The defaults are the
//! cadences the code held as constants before: the code's own stated duty where canon is silent.
//!
//! A deadline a door noted makes its sweep due then, whatever the cadence (the lease, print,
//! confirm and shared-act doors, and the erasure queue); the cadence runs it besides, for a
//! deadline no door noted.

use crate::federation::EngineControlClass;
use crate::schedule::Trigger;
use crate::setting::{Kind, SetBy};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

fn every(secs: u64) -> Trigger {
    Trigger::Every {
        secs,
        first_at: None,
    }
}

fn every_minute() -> Trigger {
    every(MINUTE)
}

fn every_five_minutes() -> Trigger {
    every(5 * MINUTE)
}

fn every_fifteen_minutes() -> Trigger {
    every(15 * MINUTE)
}

fn hourly() -> Trigger {
    every(HOUR)
}

fn daily() -> Trigger {
    every(DAY)
}

crate::setting::setting_keys! {
    /// How often the secret-lease expiry sweep runs besides each lease's noted expiry: hourly.
    pub(crate) SWEEP_SECRET_LEASE_EXPIRY: Trigger = "housekeeping.secret_lease_expiry.every" {
        kind: Kind::new(hourly),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the critical-confirm expiry sweep runs besides each confirm's noted 300-second
    /// window: hourly.
    pub(crate) SWEEP_CRITICAL_CONFIRM_EXPIRY: Trigger = "housekeeping.critical_confirm_expiry.every" {
        kind: Kind::new(hourly),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the symbol-lease holds past their expiry are cleared: every five minutes.
    pub(crate) SWEEP_SYMBOL_LEASE_EXPIRY: Trigger = "housekeeping.symbol_lease_expiry.every" {
        kind: Kind::new(every_five_minutes),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the voice-print retention sweep runs besides each print's noted deadline:
    /// hourly.
    pub(crate) SWEEP_VOICE_PRINT_RETENTION: Trigger = "housekeeping.voice_print_retention.every" {
        kind: Kind::new(hourly),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often signing documents and recipients past their window are expired: every fifteen
    /// minutes.
    pub(crate) SWEEP_ESIGN_EXPIRY: Trigger = "housekeeping.esign_expiry.every" {
        kind: Kind::new(every_fifteen_minutes),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often a signing request's missed seal is queued again: every fifteen minutes
    /// (ARCH-0064 SGN-04).
    pub(crate) SWEEP_ESIGN_SEAL_BACKSTOP: Trigger = "housekeeping.esign_seal_backstop.every" {
        kind: Kind::new(every_fifteen_minutes),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often overdue open commitments are lapsed and missed close hooks repaired: every
    /// fifteen minutes.
    pub(crate) SWEEP_COMMITMENT_LAPSE: Trigger = "housekeeping.commitment_lapse.every" {
        kind: Kind::new(every_fifteen_minutes),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often staged key retirements finish and gate decisions past the owner's horizon age
    /// out: hourly, and at each start.
    pub(crate) SWEEP_GATE_DECISION_RETENTION: Trigger = "housekeeping.gate_decision_retention.every" {
        kind: Kind::new(hourly),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often queued erasure obligations are discharged from historical carriers: daily, and
    /// at least hourly while an obligation waits (ARCH-0038's deadline is 30 days).
    pub(crate) SWEEP_HARD_ERASE_SWEEP: Trigger = "housekeeping.hard_erase_sweep.every" {
        kind: Kind::new(daily),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often cached graph walks past the longest serve window are evicted: daily.
    pub(crate) SWEEP_PPR_CACHE_EVICTION: Trigger = "housekeeping.ppr_cache_eviction.every" {
        kind: Kind::new(daily),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the shared-act maturity sweep runs besides each act's noted deadline, for an
    /// act an objection withdrawal released: hourly.
    pub(crate) SWEEP_SHARED_ACT_MATURITY: Trigger = "housekeeping.shared_act_maturity.every" {
        kind: Kind::new(hourly),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the historical secret lift looks for a queued run: every fifteen minutes; a run
    /// left unfinished at a pass's deadline is due again at once.
    pub(crate) SWEEP_SECRET_LIFT_HISTORY: Trigger = "housekeeping.secret_lift_history.every" {
        kind: Kind::new(every_fifteen_minutes),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often owed claim VAD consolidations are finished, behind the payment worker each
    /// write wakes: every fifteen minutes, and at each start.
    pub(crate) SWEEP_CLAIM_VAD_DEBT: Trigger = "housekeeping.claim_vad_debt.every" {
        kind: Kind::new(every_fifteen_minutes),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the found-key notices left due are raised: every fifteen minutes.
    pub(crate) SWEEP_FOUND_KEY_NOTICES: Trigger = "housekeeping.found_key_notices.every" {
        kind: Kind::new(every_fifteen_minutes),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the bodies reads found without a whole line index are indexed: every fifteen
    /// minutes.
    pub(crate) SWEEP_BODY_LINE_INDEX_REBUILD: Trigger = "housekeeping.body_line_index_rebuild.every" {
        kind: Kind::new(every_fifteen_minutes),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often anchored comments follow their live document body: every minute, and at each
    /// start, so a stopped process leaves none behind.
    pub(crate) SWEEP_ANNOTATION_BODY_ANCHORS: Trigger = "housekeeping.annotation_body_anchors.every" {
        kind: Kind::new(every_minute),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the sealed drafter corpora no live version names, and training examples past
    /// the traffic's bound, are removed: daily, and at each start.
    pub(crate) SWEEP_DRAFTER_CORPUS_SWEEP: Trigger = "housekeeping.drafter_corpus_sweep.every" {
        kind: Kind::new(daily),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the model pack retirement pass runs, so a retirement day's move is recorded
    /// within a minute of the day's start: every minute.
    pub(crate) SWEEP_MODEL_PACK_RETIREMENT: Trigger = "housekeeping.model_pack_retirement.every" {
        kind: Kind::new(every_minute),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
    /// How often the OAuth server's rows past their lifetime are dropped: hourly.
    pub(crate) SWEEP_OAUTH_EXPIRY: Trigger = "housekeeping.oauth_expiry.every" {
        kind: Kind::new(hourly),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
        on_change: Some(crate::schedule::rearm_on_change),
    };
}
