//! The outbound chokepoint's owner Setting keys (DESIGN 15-setting-primitive; restriction census
//! C64, Engine RULING RESTRICTION-WAVE-6-CANON-ROWS 16 Nov 03:35, C64 = A): rows the setting
//! catalogue reads from this file.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, higher_is_tighter};

/// The shipped semantic dedupe window: 24 hours.
pub(crate) const DEFAULT_DEDUPE_COOLDOWN_SECS: u64 = 86_400;

/// The shortest window: one hour. The key tunes the window; it never turns the dedupe off
/// (RESTRICTION-WAVE-6-CANON-ROWS, C64 = A: "floor 3600").
const MIN_DEDUPE_COOLDOWN_SECS: u64 = 3_600;

/// The longest window: a number every SDK carries exactly.
const MAX_DEDUPE_COOLDOWN_SECS: u64 = (1 << 53) - 1;

/// Seconds a delivered send's dedupe key suppresses a send with the same key: at least
/// [`MIN_DEDUPE_COOLDOWN_SECS`] and at most [`MAX_DEDUPE_COOLDOWN_SECS`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct DedupeCooldownSecs(pub(crate) u64);

impl SettingValue for DedupeCooldownSecs {
    fn check(self) -> Result<Self> {
        if (MIN_DEDUPE_COOLDOWN_SECS..=MAX_DEDUPE_COOLDOWN_SECS).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "the outbound dedupe window is {MIN_DEDUPE_COOLDOWN_SECS} to \
                 {MAX_DEDUPE_COOLDOWN_SECS} seconds"
            )))
        }
    }
}

fn shipped_cooldown() -> DedupeCooldownSecs {
    DedupeCooldownSecs(DEFAULT_DEDUPE_COOLDOWN_SECS)
}

crate::setting::setting_keys! {
    /// How long a send with a dedupe key suppresses another send with the same key, in seconds
    /// from the first one's delivery (24 hours by default, one hour at the least). A suppressed
    /// send is abandoned with a suppression receipt and never goes. The window is one value for
    /// the vault, so it applies uniformly whatever trigger fires the send (ARCH-0046), and a
    /// send whose delivery is still unknown keeps suppressing whatever it says. Shorter is the
    /// looser value: only the owner sets it, and an agent's change waits on the owner's answer.
    /// A row that does not decode reads as the shipped 24 hours.
    pub(crate) DEDUPE_COOLDOWN: DedupeCooldownSecs = "outbound.dedupe.cooldown_secs" {
        kind: Kind::new(shipped_cooldown)
            .strictest(shipped_cooldown)
            .tighter(higher_is_tighter::<DedupeCooldownSecs>),
    };
}
