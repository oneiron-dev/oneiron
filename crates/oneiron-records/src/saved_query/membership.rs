//! Moved from `crates/oneiron/src/saved_query/membership.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a membership transition happened. A CLOSED set: an unknown cause fails
/// decoding rather than becoming an opaque token nobody can route on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipCause {
    /// The entity's own evidence moved.
    DataChange,
    /// The owner's effective reach moved.
    ScopeChange,
    /// The query definition moved.
    DefinitionChange,
}

impl MembershipCause {
    /// Every cause, in wire order.
    pub const ALL: [Self; 3] = [Self::DataChange, Self::ScopeChange, Self::DefinitionChange];

    /// Wire token for this cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataChange => "data_change",
            Self::ScopeChange => "scope_change",
            Self::DefinitionChange => "definition_change",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|cause| cause.as_str() == value)
    }
}

/// Direction of a membership transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipTransition {
    /// The entity joined the cohort.
    Entered,
    /// The entity left the cohort.
    Exited,
}

impl MembershipTransition {
    /// Wire token for this transition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entered => "entered",
            Self::Exited => "exited",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "entered" => Some(Self::Entered),
            "exited" => Some(Self::Exited),
            _ => None,
        }
    }
}
