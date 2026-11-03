//! Standing-query match verdict tokens.

use serde::{Deserialize, Serialize};

/// A stage-2 verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchVerdict {
    /// The entity is a member.
    Match,
    /// The entity is not a member.
    NoMatch,
}

impl MatchVerdict {
    /// Wire token for this verdict.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::NoMatch => "no_match",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "match" => Some(Self::Match),
            "no_match" => Some(Self::NoMatch),
            _ => None,
        }
    }
}
