//! FIX 1380 / FIX 3899: the comm reach, whom an agent may address. A value
//! only: its order, its wire spelling and the one policy that reads a slip's
//! signed reach. The dial's relations, its defaults by role and the prompt it
//! generates stay in `oneiron::agent_dispatch`; this crate holds the value so
//! a capability slip's claims can carry it (`SlipClaims::comm`).

use serde::{Deserialize, Serialize};

/// Whom a dispatched agent may address. Declaration order is the narrowing
/// order (CALLS C1): a child's reach is never wider than its parent's.
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
pub enum CommReach {
    /// Its parent and its own children.
    Parent,
    /// Also every live dispatch below it.
    Subtree,
    /// Also its project's leader and every live dispatch in that project.
    Project,
    /// Anyone in the vault.
    Vault,
}

impl CommReach {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parent => "parent",
            Self::Subtree => "subtree",
            Self::Project => "project",
            Self::Vault => "vault",
        }
    }

    /// The reach a wire spelling names; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "parent" => Some(Self::Parent),
            "subtree" => Some(Self::Subtree),
            "project" => Some(Self::Project),
            "vault" => Some(Self::Vault),
            _ => None,
        }
    }
}

/// The ONE policy for a credential slip's signed reach (FIX 3899, CALLS
/// "FIX 3899 slip comm ceiling"): the reach the owner set at mint, or, when
/// he set none, the vault-wide reach an unbound sender has (CALLS C5). The
/// slip's reach is a ceiling, never a default: a bound run takes the narrower
/// of its own reach and this, so an absent reach never widens a child.
#[must_use]
pub const fn effective_slip_comm(comm: Option<CommReach>) -> CommReach {
    match comm {
        Some(reach) => reach,
        None => CommReach::Vault,
    }
}
