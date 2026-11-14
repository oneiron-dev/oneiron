//! Moved from `crates/oneiron/src/calendar/outcome.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What actually happened at one EVENT.
///
/// A closed four-value set. `Unknown` is a real recorded value, not a missing
/// one: it says "the question was asked and nothing established an outcome",
/// which reads the same as silence and is never transition evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    Held,
    NoShow,
    CancelledPreStart,
    Unknown,
}

impl EventOutcome {
    /// Wire token for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::NoShow => "no_show",
            Self::CancelledPreStart => "cancelled_pre_start",
            Self::Unknown => "unknown",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "held" => Some(Self::Held),
            "no_show" => Some(Self::NoShow),
            "cancelled_pre_start" => Some(Self::CancelledPreStart),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// What established an [`EventOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcomeBasis {
    /// Explicit machine evidence: a transcript, join telemetry, a cancellation.
    Machine,
    /// The owner answered the check-in.
    OwnerAttested,
}

impl EventOutcomeBasis {
    /// Wire token for this basis.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::OwnerAttested => "owner_attested",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "machine" => Some(Self::Machine),
            "owner_attested" => Some(Self::OwnerAttested),
            _ => None,
        }
    }
}

/// Value of a `calendar.event_outcome` claim, subject = EVENT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventOutcomeClaimValue {
    pub outcome: EventOutcome,
    pub basis: EventOutcomeBasis,
    pub recorded_at: u64,
}
