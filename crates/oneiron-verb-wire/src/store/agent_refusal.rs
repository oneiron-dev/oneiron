//! Moved from `crates/oneiron/src/store/agent_refusal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One position on the dial, weakest to strongest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RefusalLevel {
    /// She proceeds silently; nothing is recorded.
    None,
    /// One objection with a reason, on the record, then she proceeds.
    Voice,
    /// She declines the act she objects to, with her reason.
    Veto,
    /// The far end: she refuses outright. Settable, never a default.
    Full,
}

/// The pinned sub-map keys for a [`RefusalDial`], in encode order. Each is
/// the wire string of its [`RefusalDomain`].
pub const REFUSAL_DIAL_KEYS: [&str; 2] = ["bond", "logistics"];

impl RefusalLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Voice => "voice",
            Self::Veto => "veto",
            Self::Full => "full",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "voice" => Some(Self::Voice),
            "veto" => Some(Self::Veto),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// What a refusal concerns. The agent names it when she refuses, and her dial
/// may sit differently for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalDomain {
    /// The bond itself: what she is asked to be, or to do to it.
    Bond,
    /// The mechanics of the work: arrangements, errands, scheduling.
    Logistics,
}

impl RefusalDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bond => REFUSAL_DIAL_KEYS[0],
            Self::Logistics => REFUSAL_DIAL_KEYS[1],
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "bond" => Some(Self::Bond),
            "logistics" => Some(Self::Logistics),
            _ => None,
        }
    }
}
