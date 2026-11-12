//! Moved from `crates/oneiron/src/agent_def/powers.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// The two powers one holder has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPowers {
    /// May start a child (`self.agents.spawn`, `self.spawn`). Absent reads ON.
    #[serde(default = "power_on")]
    pub spawn: bool,
    /// May author an agent definition (`vault.agents.put` and every other
    /// door that writes one for an agent). Absent reads ON.
    #[serde(default = "power_on")]
    pub save_agent: bool,
}

pub const fn power_on() -> bool {
    true
}

impl Default for AgentPowers {
    fn default() -> Self {
        Self::ALL
    }
}

impl AgentPowers {
    /// Both powers ON: what a holder with no row has.
    pub const ALL: Self = Self {
        spawn: true,
        save_agent: true,
    };

    /// The powers both grants hold.
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        Self {
            spawn: self.spawn && other.spawn,
            save_agent: self.save_agent && other.save_agent,
        }
    }

    fn to_byte(self) -> u8 {
        u8::from(self.spawn) | (u8::from(self.save_agent) << 1)
    }

    fn from_byte(bits: u8) -> Result<Self> {
        if bits & !0b11 != 0 {
            return Err(Error::CorruptedIndex("agent power grant"));
        }
        Ok(Self {
            spawn: bits & 0b01 != 0,
            save_agent: bits & 0b10 != 0,
        })
    }
}

/// What a spawning parent asks for its child. An absent power inherits the
/// parent's; `false` switches it off for the child; `true` above the parent's
/// own is refused (`gate.deny.agent_power.above_parent`), never asked.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ChildPowerRequest {
    #[serde(default)]
    pub spawn: Option<bool>,
    #[serde(default)]
    pub save_agent: Option<bool>,
}

impl ChildPowerRequest {
    /// Whether this request asks ON for a power `parent` does not hold.
    #[must_use]
    pub const fn asks_above(self, parent: AgentPowers) -> bool {
        matches!(self.spawn, Some(true)) && !parent.spawn
            || matches!(self.save_agent, Some(true)) && !parent.save_agent
    }
}

/// The kind of holder `vault.agents.powers.set` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPowerHolderKind {
    /// An agent definition: its root grant.
    Agent,
    /// One dispatched attempt of an agent.
    Attempt,
    /// One reader child, by its task id.
    ReaderTask,
}

/// `vault.agents.powers.set`: the holder, the grant the owner expects it to
/// hold, and the one it sets.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPowerSetRequest {
    pub holder_kind: AgentPowerHolderKind,
    /// The holder's id, 32 hex.
    pub holder_ref: String,
    pub expected: AgentPowers,
    pub powers: AgentPowers,
}
