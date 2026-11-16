//! E-sign's pack Setting keys (owner ruling PACK-SETTINGS-ALL = B).
//!
//! `esign.held_signing.owner_lapse`: how long a held automated sign act's ask waits at the vault
//! owners before it lapses. Before this key it waited until an owner answered; the shipped default
//! is 30 days (the Engine's choice, beside ARCH-0064's 30-day reminder cap). The owner changes
//! it, `never` included; an agent's change, either way, waits on the owner's approval.

use serde::{Deserialize, Serialize};

use crate::setting::{Kind, SettingValue};

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
}
