//! Moved from `crates/oneiron/src/memory/recall/call_mode.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::recall::Effort;
pub use oneiron_base::request_limits::DEFAULT_CALL_MODE_DEADLINE;
use serde::Deserialize;
use serde::Serialize;

/// Where a recall request sets the one effort dial: one of the five effort
/// levels, or `call`, the call mode for live calls. Call mode is a position
/// on the dial, not a sixth level: it runs [`Effort::Light`] under a hard
/// deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecallEffort {
    Light,
    Medium,
    High,
    Xhigh,
    Max,
    /// Light effort under a hard deadline: the request's `deadline_ms`, or
    /// else the vault's call-mode deadline.
    Call,
}

impl RecallEffort {
    /// The effort level the request runs at.
    #[must_use]
    pub const fn level(self) -> Effort {
        match self {
            Self::Light | Self::Call => Effort::Light,
            Self::Medium => Effort::Medium,
            Self::High => Effort::High,
            Self::Xhigh => Effort::Xhigh,
            Self::Max => Effort::Max,
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "call" => Some(Self::Call),
            level => Effort::parse(level).map(Self::from),
        }
    }
}

impl From<Effort> for RecallEffort {
    fn from(effort: Effort) -> Self {
        match effort {
            Effort::Light => Self::Light,
            Effort::Medium => Self::Medium,
            Effort::High => Self::High,
            Effort::Xhigh => Self::Xhigh,
            Effort::Max => Self::Max,
        }
    }
}
