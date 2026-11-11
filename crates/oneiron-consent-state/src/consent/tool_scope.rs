//! Moved from `crates/oneiron/src/consent/tool_scope.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Payload sensitivity ordered from least to most restrictive.
///
/// [`Self::Unclassified`] is the fail-closed parse result. It sorts above the
/// highest grantable ceiling, so it can never accidentally become public.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Personal,
    Secret,
    Unclassified,
}

impl DataClass {
    /// Parses a payload class. Unknown spellings stay above every grantable
    /// ceiling and therefore force escalation.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "public" => Self::Public,
            "personal" => Self::Personal,
            "secret" => Self::Secret,
            _ => Self::Unclassified,
        }
    }

    /// Stable spelling used by the standing-grant codec.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Personal => "personal",
            Self::Secret => "secret",
            Self::Unclassified => "unclassified",
        }
    }

    /// Only known classes may be persisted as grant ceilings.
    #[must_use]
    pub const fn is_grantable(self) -> bool {
        !matches!(self, Self::Unclassified)
    }
}

impl std::str::FromStr for DataClass {
    type Err = ();

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let parsed = Self::parse(value);
        parsed.is_grantable().then_some(parsed).ok_or(())
    }
}
