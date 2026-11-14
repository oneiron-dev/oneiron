//! Moved from `crates/oneiron/src/dreamer_runner/free_time/policy.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

/// The two owner-facing names of a cycle's one daily clock: one cycle a day
/// either way, at the policy's local time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeCadence {
    Daily,
    Nightly,
}

/// When each cycle opens: a local time of day in an IANA zone. A local time
/// a spring-forward gap skips opens no cycle that date; a fall-back fold
/// opens at its earlier instant. Never UTC by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeSchedule {
    pub cadence: FreeTimeCadence,
    /// 0..=23.
    pub hour: u8,
    /// 0..=59.
    pub minute: u8,
    /// An IANA zone, by its canonical name.
    pub zone: String,
}

/// A split the owner pinned: what each kind may spend of the total, as a
/// hard share each. Without one, both kinds draw on one shared total and the
/// agent chooses; no share is a minimum or a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeSplit {
    pub for_human_units: u64,
    pub own_time_units: u64,
}

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free-time policy: {reason}"))
}
