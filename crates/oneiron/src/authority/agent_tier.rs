//! ARCH-0028's registration-time authority tiers for an outside agent, as
//! stored authority: the credential scopes its bearer carries, the verbs its
//! owner agent grant lists, and the agent's ceiling. `oneiron token agent`
//! and the vault's OAuth sign-in (FIX 4902) both map a tier through here, so
//! one tier means the same authority on every door that admits an agent.
use serde::{Deserialize, Serialize};

use crate::store::agent_record::AgentCeiling;

/// One of ARCH-0028's three agent tiers.
///
/// Propose-only writes with `core:propose`, which only doors that hold a
/// write for review honour: `/v1/core/propose`, and the MCP verbs whose write
/// lands at the agent's `proposed` ceiling. `core:write`, which every unbound
/// write door and every MCP write that takes effect at once requires, is
/// full-access's alone. Nothing else (`core:auth`, an organization power, a
/// companion scope) is ever an agent's.
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
pub enum AgentTier {
    /// Retrieve and inspect; no write capability.
    #[serde(rename = "read")]
    ReadOnly,
    /// Write capability at ceiling `proposed`: what it writes waits for the
    /// owner's review.
    #[serde(rename = "propose")]
    ProposeOnly,
    /// Write capability at ceiling `auto`: its writes land through the same
    /// write gate as the owner's.
    #[serde(rename = "full")]
    FullAccess,
}

impl AgentTier {
    /// Every tier, narrowest first.
    pub const ALL: [Self; 3] = [Self::ReadOnly, Self::ProposeOnly, Self::FullAccess];

    /// The tier's wire name: `read`, `propose` or `full`.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ReadOnly => "read",
            Self::ProposeOnly => "propose",
            Self::FullAccess => "full",
        }
    }

    /// The tier a wire name names; `None` for any other text.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tier| tier.wire_name() == name)
    }

    /// The credential scopes a bearer of this tier carries, as the server's
    /// `/v1/core` scope vocabulary spells them.
    #[must_use]
    pub const fn core_scopes(self) -> &'static [&'static str] {
        match self {
            Self::ReadOnly => &["core:read"],
            Self::ProposeOnly => &["core:read", "core:propose"],
            Self::FullAccess => &["core:read", "core:propose", "core:write"],
        }
    }

    /// The verbs an owner agent grant of this tier lists: always `read`, so
    /// the grant confers.
    #[must_use]
    pub const fn grant_verbs(self) -> &'static [&'static str] {
        match self {
            Self::ReadOnly => &["read"],
            Self::ProposeOnly => &["read", "propose"],
            Self::FullAccess => &["read", "propose", "write"],
        }
    }

    /// The agent's ceiling at this tier: `auto` for full access, `proposed`
    /// for the other two.
    #[must_use]
    pub const fn ceiling(self) -> AgentCeiling {
        match self {
            Self::ReadOnly | Self::ProposeOnly => AgentCeiling::Proposed,
            Self::FullAccess => AgentCeiling::Auto,
        }
    }
}
