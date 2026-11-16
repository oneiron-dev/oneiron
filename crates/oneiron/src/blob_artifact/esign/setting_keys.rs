//! E-sign's pack Setting keys (owner ruling PACK-SETTINGS-ALL = B).
//!
//! `esign.held_signing.owner_lapse`: how long a held automated sign act's ask waits at the vault
//! owners before it lapses. Before this key it waited until an owner answered; the shipped default
//! is 30 days (the Engine's choice, beside ARCH-0064's 30-day reminder cap). The owner changes
//! it, `never` included; an agent's change, either way, waits on the owner's approval.
//!
//! The e-signature ask's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use serde::{Deserialize, Serialize};

use crate::setting::{Kind, LEARNED_SCOPES, SettingValue};

/// Thirty days, in seconds: the shipped lapse.
const THIRTY_DAYS_SECS: u64 = 30 * 24 * 60 * 60;

/// When a held sign act's ask, left unanswered at the vault owners, lapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HeldSigningLapse {
    /// The ask waits at the vault owners until one of them answers.
    Never,
    /// The ask lapses once it has waited this many seconds at the vault owners.
    AfterSecs(u64),
}

impl SettingValue for HeldSigningLapse {}

fn thirty_days() -> HeldSigningLapse {
    HeldSigningLapse::AfterSecs(THIRTY_DAYS_SECS)
}

/// Whether `a` is at least as tight as `b`: a sooner lapse is tighter, and `never` is the
/// loosest end.
fn sooner_is_tighter(a: &HeldSigningLapse, b: &HeldSigningLapse) -> bool {
    match (a, b) {
        (_, HeldSigningLapse::Never) => true,
        (HeldSigningLapse::Never, HeldSigningLapse::AfterSecs(_)) => false,
        (HeldSigningLapse::AfterSecs(a), HeldSigningLapse::AfterSecs(b)) => a <= b,
    }
}

crate::setting::setting_keys! {
    /// How long a held automated sign act's ask waits at the vault owners before it lapses
    /// (default 30 days). A lapse never signs: the document stays unsigned, the recipient's turn
    /// stays open for the sender, the ask leaves the owners' queue, and each owner gets an inbox
    /// notice. A sooner lapse is tighter: the agent's request to sign stays open no longer than
    /// this at the owners (Vault::lapse_stale_esign_ask); `never` is the loosest end. A row that
    /// does not decode fails the read, and the hold waits on, as with `never`.
    pub(crate) ESIGN_HELD_SIGNING_OWNER_LAPSE: HeldSigningLapse =
        "esign.held_signing.owner_lapse" {
        kind: Kind::new(thirty_days).tighter(sooner_is_tighter),
    };

    /// Hours a held sign act's unanswered ask waits on the person it went to
    /// before it climbs to the next role up its chain (CALLS "OF-415 held
    /// signing climb"). At the vault owners it does not climb: it waits for the
    /// vault's `esign.held_signing.owner_lapse`, then lapses unsigned. No
    /// unanswered ask signs.
    pub ESIGN_ASK_CLIMB_HOURS: f64 = "esign.ask.climb_hours" {
        kind: Kind::new(|| 24.0).learned(1.0, 720.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
