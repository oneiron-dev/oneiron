//! Moved from `crates/oneiron/src/authority/support_grant.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Which kind of support party a grant names: a named support person
/// (`human`) or a support agent (`agent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportHolderClass {
    Human,
    Agent,
}

impl SupportHolderClass {
    /// The actor class the slip carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
        }
    }
}

/// Where a support grant stands, as its list and the registry show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportGrantStatus {
    /// It admits its holder now.
    Active,
    /// Its wall deadline or its slip lifetime has passed.
    Expired,
    /// The customer revoked it.
    Revoked,
    /// It no longer stands for another reason: its holder is gone, or the
    /// host that minted it no longer stands.
    Ended,
}
