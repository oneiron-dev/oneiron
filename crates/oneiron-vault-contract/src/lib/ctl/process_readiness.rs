//! How a managed vault's process stands now (L8-11; runtime
//! `#provider-health`, decision `scour:S25`): the live state every `Ping`
//! reports beside the boot snapshot [`ManagedReadiness`](super::ManagedReadiness).

use serde::{Deserialize, Deserializer, Serialize};

/// A vault process's readiness, moved by its event-loop watchdog while it
/// runs. Lag at or over the threshold marks it `degraded`; a sustained hang
/// (no probe sample for the hang threshold) marks it `draining`, and a
/// managed vault then refuses new work; the first sample after the hang
/// moves it to `recovering`, and only a full stabilization window of clean
/// samples makes it `ready` again, from `degraded` or `recovering` alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    /// The event loop answers within the lag threshold.
    Ready,
    /// The event loop lags; the vault still takes work.
    Degraded,
    /// The hang ended; a managed vault takes no new work until a
    /// stabilization window of clean samples passes.
    Recovering,
    /// The event loop is hung; a managed vault takes no new work.
    Draining,
}

impl ProcessState {
    /// The wire spelling, for a log field or a health body.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Recovering => "recovering",
            Self::Draining => "draining",
        }
    }
}

/// `Ping`'s `process`: the state, and the event-loop lag of the watchdog's
/// last probe sample in whole milliseconds. A supervisor reads it to hold a
/// vault's intake or restart one that stays `draining`; when is its call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessReadinessReport {
    pub state: ProcessState,
    pub lag_ms: u64,
}

/// `Ping`'s `process` as a supervisor reads it: absent or `null` is `None`,
/// an engine built before the floor. A block that does not read (an unknown
/// state, a lag that is not a whole number a u64 holds) is `None` too,
/// unknown, and never fails the `Ping` it rides.
pub(super) fn observed<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ProcessReadinessReport>, D::Error> {
    let block = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(block.and_then(|block| serde_json::from_value(block).ok()))
}
