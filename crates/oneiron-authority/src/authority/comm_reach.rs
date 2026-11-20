//! FIX 1380 / FIX 3899: the comm reach, whom an agent may address. A value
//! only: its order, its wire spelling and the one policy that reads a slip's
//! signed reach. The dial's relations, its defaults by role and the prompt it
//! generates stay in `oneiron::agent_dispatch`; this crate holds the value so
//! a capability slip's claims can carry it (`SlipClaims::comm`).

use oneiron_contracts::register::Register;
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
    Register,
)]
#[serde(rename_all = "snake_case")]
#[register("comm.reach")]
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
    /// The reach a wire spelling names; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
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
