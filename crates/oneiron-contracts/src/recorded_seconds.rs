//! `RecordedSeconds`: a time on the vault's recording clock, in whole seconds since the UNIX epoch.
//!
//! The Gate ledger's `created_at`, the Setting change row and the Schedule stamps are all whole seconds,
//! while a Dreamer run and the outbound fan-out count in milliseconds. A bare `u64` does not say which
//! unit it holds, so a millisecond value can reach a seconds field unnoticed (FIX
//! GATE-ROW-CREATED-AT-MILLISECONDS). This type names the unit, and `from_millis` is the one
//! milliseconds-to-seconds step.
//!
//! On the wire it is the bare `u64` (`serde(transparent)`): a stored field that changes from `u64` to
//! `RecordedSeconds` keeps its MessagePack and JSON bytes, so a row a vault already holds decodes as
//! before.

use serde::{Deserialize, Serialize};

/// A time on the vault's recording clock, in whole seconds since the UNIX epoch.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct RecordedSeconds(u64);

impl RecordedSeconds {
    /// A time given in whole seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// A time given in milliseconds, rounded down to the whole second.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis / 1_000)
    }

    /// The time in whole seconds.
    #[must_use]
    pub const fn secs(self) -> u64 {
        self.0
    }
}
