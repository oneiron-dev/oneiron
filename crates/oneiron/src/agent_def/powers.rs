//! The two grant powers an agent holds beside its definition (ARCH-0053:20; owner
//! ruling SPAWN-KNOB = A, 2026-11-10): `spawn` starts a child, `save_agent` authors a
//! definition. Both are ON unless the owner switched one off. A parent may switch
//! either off for a child it spawns; only the owner switches one back on above the
//! parent's own.
//!
//! The powers are authority, not composition: a definition carries none, so a
//! saved or travelling definition can neither grant one nor clear an owner's OFF.
//! One side table holds them, keyed by the holder: an agent (its root grant), one
//! of its attempts, or one of its reader tasks (each a child instance's own grant,
//! staged with the child at its birth). No row reads as both powers ON.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, Raw, SideTable, SideTableDbs};
use crate::{Vault, WriteActor};

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

const fn power_on() -> bool {
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

/// Who holds a grant: an agent's root grant, or one child instance's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPowerTarget {
    /// The agent's root grant: what an instance with no grant of its own holds.
    Agent(EntityId),
    /// One dispatched attempt of an agent.
    Attempt(AttemptId),
    /// One reader child (`self.spawn`), by its task id.
    ReaderTask(EntityId),
}

impl AgentPowerTarget {
    /// The table key: a tag byte, then the holder's 16-byte id.
    pub(crate) fn key(self) -> [u8; 17] {
        let (tag, id) = match self {
            Self::Agent(id) => (0, *id.as_bytes()),
            Self::Attempt(id) => (1, *id.as_bytes()),
            Self::ReaderTask(id) => (2, *id.as_bytes()),
        };
        let mut key = [0_u8; 17];
        key[0] = tag;
        key[1..].copy_from_slice(&id);
        key
    }

    /// The key as the refusal receipt's grant reference names it.
    pub(crate) fn grant_ref(self) -> String {
        format!(
            "agent_power:{}",
            crate::entity_id::bytes_to_hex_lower(&self.key())
        )
    }
}

/// The grant table: one byte per holder, bit 0 `spawn`, bit 1 `save_agent`.
pub(crate) const POWER_GRANTS: SideTable<[u8; 17], [u8; 1], Raw> =
    SideTable::new(&side_table::AGENT_DEF_POWER_GRANT);

/// The row's byte for `powers`.
pub(crate) fn power_grant_row(powers: AgentPowers) -> [u8; 1] {
    [powers.to_byte()]
}

/// A stored row's powers. Bits outside the two powers are a corrupt row, never ON.
pub(crate) fn decode_power_grant_row(row: [u8; 1]) -> Result<AgentPowers> {
    AgentPowers::from_byte(row[0])
}

/// The grant stored for `target`, if one is.
pub(crate) fn stored_agent_powers_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    target: AgentPowerTarget,
) -> Result<Option<AgentPowers>> {
    POWER_GRANTS
        .get(dbs, txn, &target.key())?
        .map(decode_power_grant_row)
        .transpose()
}

/// The grant `target` holds: its stored row, or both powers ON.
pub(crate) fn agent_powers_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    target: AgentPowerTarget,
) -> Result<AgentPowers> {
    Ok(stored_agent_powers_in_txn(dbs, txn, target)?.unwrap_or(AgentPowers::ALL))
}

/// Stages `powers` as `target`'s grant in the caller's writer.
pub(crate) fn stage_agent_powers_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    target: AgentPowerTarget,
    powers: AgentPowers,
) -> Result<()> {
    POWER_GRANTS.put(dbs, txn, &target.key(), &power_grant_row(powers))
}

/// What one agent instance holds now, and whose grant that is: the instance's
/// own grant when one was staged at its birth, else its agent's root grant.
/// The parent's grant is not met again here: an owner's explicit ON on one
/// child stands above its parent's.
pub(crate) fn effective_agent_powers_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    instance: Option<AgentPowerTarget>,
) -> Result<(AgentPowers, AgentPowerTarget)> {
    if let Some(instance) = instance
        && let Some(powers) = stored_agent_powers_in_txn(dbs, txn, instance)?
    {
        return Ok((powers, instance));
    }
    let root = AgentPowerTarget::Agent(agent);
    Ok((agent_powers_in_txn(dbs, txn, root)?, root))
}

/// The refusal reason for a parent asking its child a power it does not hold.
pub(crate) const ABOVE_PARENT: &str = "gate.deny.agent_power.above_parent";
/// The refusal reason for a spawn by a holder whose `spawn` is off.
pub(crate) const SPAWN_OFF: &str = "gate.deny.agent_power.spawn_off";
/// The refusal reason for an authored definition by a holder whose `save_agent` is off.
pub(crate) const SAVE_AGENT_OFF: &str = "gate.deny.agent_power.save_agent_off";

/// A child's grant at its birth: the parent's powers, met with the target
/// agent's root grant and the parent's request. A request for a power the
/// parent does not hold is refused, not narrowed.
///
/// # Errors
///
/// [`ABOVE_PARENT`] when `requested` asks ON for a power `parent` lacks.
pub fn child_agent_powers(
    parent: AgentPowers,
    target: AgentPowers,
    requested: ChildPowerRequest,
) -> std::result::Result<AgentPowers, &'static str> {
    if requested.asks_above(parent) {
        return Err(ABOVE_PARENT);
    }
    Ok(parent.meet(target).meet(AgentPowers {
        spawn: requested.spawn.unwrap_or(true),
        save_agent: requested.save_agent.unwrap_or(true),
    }))
}

impl ChildPowerRequest {
    /// Whether this request asks ON for a power `parent` does not hold.
    #[must_use]
    pub const fn asks_above(self, parent: AgentPowers) -> bool {
        matches!(self.spawn, Some(true)) && !parent.spawn
            || matches!(self.save_agent, Some(true)) && !parent.save_agent
    }
}

/// The typed refusal a writer returns for a power decision.
pub(crate) fn power_refusal(reason: &'static str) -> Error {
    Error::Gate(GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec![reason],
    })
}

/// Refuses an authored definition when its author's instance holds no
/// `save_agent`. Every door that writes a definition for an agent passes here
/// before it mints one.
///
/// # Errors
///
/// [`SAVE_AGENT_OFF`] as a Gate write refusal.
pub(crate) fn ensure_save_agent_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    author: EntityId,
    instance: Option<AgentPowerTarget>,
) -> Result<()> {
    if effective_agent_powers_in_txn(dbs, txn, author, instance)?
        .0
        .save_agent
    {
        Ok(())
    } else {
        Err(power_refusal(SAVE_AGENT_OFF))
    }
}

/// The holder a writing actor is: its run's attempt when the actor carries
/// one, else none (its agent's root grant answers).
pub(crate) fn actor_instance(actor: &WriteActor) -> Option<AgentPowerTarget> {
    actor
        .run_attempt()
        .and_then(|bytes| AttemptId::from_bytes(&bytes).ok())
        .map(AgentPowerTarget::Attempt)
}

impl Vault {
    /// The grant `target` holds now: its stored row, or both powers ON.
    ///
    /// # Errors
    ///
    /// A store read error, or a corrupt row.
    pub fn agent_powers(&self, target: AgentPowerTarget) -> Result<AgentPowers> {
        if let AgentPowerTarget::ReaderTask(task) = target {
            return Ok(crate::code_run::ReaderJobs::canonical(self)
                .task_powers(task)?
                .unwrap_or(AgentPowers::ALL));
        }
        let txn = self.store.env.read_txn()?;
        agent_powers_in_txn(&self.store, &txn, target)
    }

    /// The owner sets `target`'s grant to `powers`, when it still holds
    /// `expected`. Only this door switches a power back on. It changes neither
    /// a definition nor its ceiling pin; setting an agent's root grant leaves
    /// the grants its running children already hold.
    ///
    /// # Errors
    ///
    /// An owner proof that does not revalidate, a concurrent change, and a
    /// reader task this vault holds no job for.
    pub fn set_agent_powers_as(
        &self,
        owner: &AuthenticatedOwner,
        target: AgentPowerTarget,
        expected: AgentPowers,
        powers: AgentPowers,
    ) -> Result<AgentPowers> {
        if let AgentPowerTarget::ReaderTask(task) = target {
            return crate::code_run::ReaderJobs::canonical(self)
                .set_task_powers_as(self, owner, task, expected, powers);
        }
        let mut wtxn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &wtxn)?;
        if agent_powers_in_txn(&self.store, &wtxn, target)? != expected {
            return Err(Error::ConcurrentWrite("agent power grant changed"));
        }
        stage_agent_powers_in_txn(&self.store, &mut wtxn, target, powers)?;
        wtxn.commit()?;
        Ok(powers)
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::agent_def::powers::AgentPowerHolderKind;

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

/// [`Vault::set_agent_powers_as`] from the owner door's request.
///
/// # Errors
///
/// An id that is not 32 hex, and the setter's refusals.
pub fn set_agent_powers_from_request_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentPowerSetRequest,
) -> Result<AgentPowers> {
    let id = EntityId::from_hex(&input.holder_ref)?;
    let target = match input.holder_kind {
        AgentPowerHolderKind::Agent => AgentPowerTarget::Agent(id),
        AgentPowerHolderKind::Attempt => {
            AgentPowerTarget::Attempt(AttemptId::from_bytes(id.as_bytes())?)
        }
        AgentPowerHolderKind::ReaderTask => AgentPowerTarget::ReaderTask(id),
    };
    vault.set_agent_powers_as(owner, target, input.expected, input.powers)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFF: AgentPowers = AgentPowers {
        spawn: false,
        save_agent: false,
    };

    #[test]
    fn a_row_byte_round_trips_and_stray_bits_are_corrupt() {
        for powers in [
            AgentPowers::ALL,
            OFF,
            AgentPowers {
                spawn: true,
                save_agent: false,
            },
            AgentPowers {
                spawn: false,
                save_agent: true,
            },
        ] {
            assert_eq!(
                decode_power_grant_row(power_grant_row(powers)).ok(),
                Some(powers)
            );
        }
        assert!(decode_power_grant_row([0b100]).is_err());
    }

    #[test]
    fn a_child_only_narrows_and_never_asks_above_its_parent() {
        let save_off = AgentPowers {
            spawn: true,
            save_agent: false,
        };
        let inherit = ChildPowerRequest::default();
        assert_eq!(
            child_agent_powers(save_off, AgentPowers::ALL, inherit),
            Ok(save_off)
        );
        assert_eq!(
            child_agent_powers(
                AgentPowers::ALL,
                AgentPowers::ALL,
                ChildPowerRequest {
                    spawn: Some(false),
                    save_agent: None
                }
            ),
            Ok(AgentPowers {
                spawn: false,
                save_agent: true
            })
        );
        assert_eq!(child_agent_powers(AgentPowers::ALL, OFF, inherit), Ok(OFF));
        assert_eq!(
            child_agent_powers(
                save_off,
                AgentPowers::ALL,
                ChildPowerRequest {
                    spawn: None,
                    save_agent: Some(true)
                }
            ),
            Err(ABOVE_PARENT)
        );
    }
}
