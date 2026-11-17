//! The identity pass's paces as the owner's Setting keys (restriction wave 14, C104; owner 16 Nov
//! 00:44: "optional freedom with good defaults everywhere"): how many tag sets one nightly pass
//! reads, how many asks wait at once, and how long a failed decision waits. Each default is the
//! pace the pass kept before, so nothing moves until the owner sets a row through
//! `vault.settings.set`. Each pace is at least one: a zero page never moves the cursor, a zero
//! tray stops every pass at its first ask, and a zero wait retries a failing decision on every
//! host round.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, higher_is_tighter, lower_is_tighter};

/// A pace of the identity pass, at least one: a count of tag sets or asks, or seconds.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct IdentityPace(pub(crate) u64);

impl IdentityPace {
    /// The least pace a key takes.
    const LEAST: u64 = 1;

    /// The pace as a count of items, whole on every target the engine builds for.
    pub(crate) fn count(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }

    /// The pace as seconds.
    pub(crate) const fn secs(self) -> u64 {
        self.0
    }
}

impl SettingValue for IdentityPace {
    fn check(self) -> Result<Self> {
        if self.0 < Self::LEAST {
            return Err(Error::InvalidConfig(
                "an identity pass pace is at least 1".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// Tag sets one pass read before the keys: 2,048.
fn scan_turns_default() -> IdentityPace {
    IdentityPace(2_048)
}

/// Open asks before the keys: 64.
fn max_open_asks_default() -> IdentityPace {
    IdentityPace(64)
}

/// The wait after a failed decision before the keys: an hour.
fn retry_secs_default() -> IdentityPace {
    IdentityPace(3_600)
}

/// The least work that still moves: one tag set a pass, one ask at once.
fn least_pace() -> IdentityPace {
    IdentityPace(IdentityPace::LEAST)
}

/// What an unreadable wait row reads as: a day before the host tries again.
fn longest_retry_secs() -> IdentityPace {
    IdentityPace(86_400)
}

crate::setting::setting_keys! {
    /// Tag sets one nightly identity pass reads (2048 by default). The cursor moves past a full
    /// page; a short page starts the next pass over.
    pub(crate) SCAN_TURNS: IdentityPace = "dreamer.identity.scan_turns" {
        kind: Kind::new(scan_turns_default)
            .strictest(least_pace)
            .tighter(lower_is_tighter::<IdentityPace>),
    };
    /// Identity asks open at once, besides those kept separate (64 by default). Past this a pass
    /// stops at the turn that would open one, and the next pass starts there.
    pub(crate) MAX_OPEN_ASKS: IdentityPace = "dreamer.identity.max_open_asks" {
        kind: Kind::new(max_open_asks_default)
            .strictest(least_pace)
            .tighter(lower_is_tighter::<IdentityPace>),
    };
    /// Seconds a failed identity decision waits before the host tries it again (3600 by default).
    pub(crate) RETRY_SECS: IdentityPace = "dreamer.identity.retry_secs" {
        kind: Kind::new(retry_secs_default)
            .strictest(longest_retry_secs)
            .tighter(higher_is_tighter::<IdentityPace>),
    };
}
