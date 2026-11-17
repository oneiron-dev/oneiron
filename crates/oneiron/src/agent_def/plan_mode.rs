//! An agent's plan mode (agent-runtime-v1.md, "Plan mode reuses built review
//! parts": "Per-agent plan_mode: required | optional | off"; Engine ruling
//! SETTING = A, Fri 13 Nov 03:05).
//!
//! The mode is the owner's authority over one agent, not part of its
//! definition: a saved, travelling or packed definition carries none, and
//! only `vault.agents.plan_mode.set` changes it. One side table holds it,
//! keyed by the agent; no row reads `optional`.
//!
//! - `required`: a run of the agent that a non-owner starts needs a plan the
//!   owner approved. A TASK for it must pin a plan-doc approved at the pinned
//!   revision, and an agent's spawn or workflow leaf of it, which pins none,
//!   is refused. The owner's own TASK for it is never refused.
//! - `optional`: the agent may propose a plan and may run without one.
//! - `off`: the agent may not propose a plan (`vault.plans.propose`).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, Raw, SideTable, SideTableDbs};

/// Whether one agent works from a plan the owner approved.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentPlanMode {
    /// A run a non-owner starts needs a plan the owner approved.
    Required,
    /// The agent may propose a plan and may run without one. An agent with
    /// no row has this mode.
    #[default]
    Optional,
    /// The agent may not propose a plan.
    Off,
}

impl AgentPlanMode {
    fn to_byte(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Optional => 1,
            Self::Required => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(Self::Off),
            1 => Ok(Self::Optional),
            2 => Ok(Self::Required),
            _ => Err(Error::CorruptedIndex("agent plan mode")),
        }
    }
}

/// The mode table: one byte per agent, 0 `off`, 1 `optional`, 2 `required`.
const PLAN_MODES: SideTable<EntityId, [u8; 1], Raw> =
    SideTable::new(&side_table::AGENT_DEF_PLAN_MODE);

/// The refusal reason for a run of a `required` agent with no approved plan.
pub(crate) const PLAN_MODE_REQUIRED: &str = "gate.deny.plan_mode.required";
/// The refusal reason for a plan an `off` agent proposes.
pub(crate) const PLAN_MODE_OFF: &str = "gate.deny.plan_mode.off";

/// The mode `agent` has: its stored row, or `optional`.
pub(crate) fn agent_plan_mode_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<AgentPlanMode> {
    PLAN_MODES
        .get(dbs, txn, &agent)?
        .map_or(Ok(AgentPlanMode::Optional), |row| {
            AgentPlanMode::from_byte(row[0])
        })
}

/// The typed refusal a writer returns for a plan-mode decision.
pub(crate) fn plan_mode_refusal(reason: &'static str) -> Error {
    Error::Gate(GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec![reason],
    })
}

/// Refuses a run of `agent` that pins no approved plan when its mode is
/// `required`. The caller has already passed the owner's own acts.
///
/// # Errors
///
/// [`PLAN_MODE_REQUIRED`] as a Gate write refusal.
pub(crate) fn refuse_unplanned_run_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<()> {
    if agent_plan_mode_in_txn(dbs, txn, agent)? == AgentPlanMode::Required {
        return Err(plan_mode_refusal(PLAN_MODE_REQUIRED));
    }
    Ok(())
}

/// Refuses a plan proposed by `proposer` when its mode is `off`.
///
/// # Errors
///
/// [`PLAN_MODE_OFF`] as a Gate write refusal.
pub(crate) fn refuse_plan_from_off_agent_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    proposer: EntityId,
) -> Result<()> {
    if agent_plan_mode_in_txn(dbs, txn, proposer)? == AgentPlanMode::Off {
        return Err(plan_mode_refusal(PLAN_MODE_OFF));
    }
    Ok(())
}

/// `vault.agents.plan_mode.set`: the agent, the mode the owner expects it to
/// have, and the mode it sets.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPlanModeSetRequest {
    pub agent_def_ref: EntityId,
    pub expected: AgentPlanMode,
    pub plan_mode: AgentPlanMode,
    /// Another asker's approved check-in for this exact change, 32 hex: the
    /// owner applies it on their own proof, and the setter's writer spends
    /// it (ROLES-CHECKIN 2k8). Omitted: the owner's own set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

/// One agent's plan mode, as the setter left it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPlanModeView {
    pub agent_def_ref: EntityId,
    pub plan_mode: AgentPlanMode,
    /// The decision a set that changed the mode ran on: the owner's own
    /// proof, naming the asker's approved check-in it applied
    /// (ROLES-CHECKIN 2k8). Absent when the mode stayed as it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
}

impl Vault {
    /// The plan mode `agent` has now: its stored row, or `optional`.
    ///
    /// # Errors
    ///
    /// A store read error, or a corrupt row.
    pub fn agent_plan_mode(&self, agent: EntityId) -> Result<AgentPlanMode> {
        let txn = self.store.env.read_txn()?;
        agent_plan_mode_in_txn(&self.store, &txn, agent)
    }

    /// The owner sets agent definition `agent`'s plan mode to `plan_mode`,
    /// when it still has `expected`. It changes neither the definition nor a
    /// run already started.
    ///
    /// # Errors
    ///
    /// An owner proof that does not revalidate, an id that names no agent
    /// definition, and a concurrent change.
    pub fn set_agent_plan_mode_as(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        expected: AgentPlanMode,
        plan_mode: AgentPlanMode,
    ) -> Result<AgentPlanModeView> {
        self.set_agent_plan_mode_with_check_in(owner, agent, expected, plan_mode, None)
    }

    /// [`Self::set_agent_plan_mode_as`] applying `applied`. A set that
    /// changes the mode is the owner's own act on their own proof, and the
    /// view records that decision; with `applied` they apply another asker's
    /// approved check-in for this exact change, spent in the same writer
    /// after every check (ROLES-CHECKIN 2k8; Engine RULING P25-2K8-SCOPE Q1
    /// = A: every changed set spends, since the modes have no order). A set
    /// to the mode the agent has spends nothing and records none.
    pub(crate) fn set_agent_plan_mode_with_check_in(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        expected: AgentPlanMode,
        plan_mode: AgentPlanMode,
        applied: Option<&crate::check_in::AppliedCheckIn<'_>>,
    ) -> Result<AgentPlanModeView> {
        let mut wtxn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &wtxn)?;
        crate::task_verb::TaskAssignee::AgentDef {
            agent_def_ref: agent,
        }
        .validate_in(self, &wtxn)?;
        if agent_plan_mode_in_txn(&self.store, &wtxn, agent)? != expected {
            return Err(Error::ConcurrentWrite("agent plan mode changed"));
        }
        let check_in = if plan_mode == expected {
            None
        } else {
            Some(crate::check_in::owner_act_decision_in_txn(
                self,
                &mut wtxn,
                crate::check_in::ActClass::GrantWiden,
                applied,
            )?)
        };
        PLAN_MODES.put(&self.store, &mut wtxn, &agent, &[plan_mode.to_byte()])?;
        wtxn.commit()?;
        Ok(AgentPlanModeView {
            agent_def_ref: agent,
            plan_mode,
            check_in,
        })
    }
}

/// [`Vault::set_agent_plan_mode_as`] from the owner door's request, applying
/// with `check_in_ref` another asker's approved check-in for this exact
/// change (2k8).
///
/// # Errors
///
/// A `check_in_ref` that is no 32-hex id; the setter's refusals; a
/// check-in that is not an approved ask for this change.
pub fn set_agent_plan_mode_from_request_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentPlanModeSetRequest,
) -> Result<AgentPlanModeView> {
    let applied = match input.check_in_ref.as_deref() {
        Some(hex) => Some(crate::check_in::AppliedCheckIn {
            id: EntityId::from_hex(hex)
                .map_err(|_| Error::InvalidConfig("check_in_ref is not a check-in id".into()))?,
            verb: "vault.agents.plan_mode.set",
            effect_digest: agent_plan_mode_set_effect_digest(&input)?,
        }),
        None => None,
    };
    vault.set_agent_plan_mode_with_check_in(
        owner,
        input.agent_def_ref,
        input.expected,
        input.plan_mode,
        applied.as_ref(),
    )
}

/// The digest of the owner's plan mode `request`: the effect an asker's
/// `vault.check_in.open` names for `vault.agents.plan_mode.set`, and the one
/// the owner's set spends (2k8; P25-2K8-SCOPE Q1 = A). BLAKE3, key derived
/// from `oneiron check_in agent plan mode set v1`, over the request's
/// MessagePack encoding with field names, without its `check_in_ref`: the
/// agent, the mode expected and the mode set.
///
/// # Errors
///
/// The request does not encode.
pub fn agent_plan_mode_set_effect_digest(request: &AgentPlanModeSetRequest) -> Result<[u8; 32]> {
    let set = AgentPlanModeSetRequest {
        check_in_ref: None,
        ..request.clone()
    };
    let encoded = rmp_serde::to_vec_named(&set)
        .map_err(|_| Error::InvariantViolation("agent plan mode set encode"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron check_in agent plan mode set v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::AgentPlanMode;

    #[test]
    fn a_mode_byte_round_trips_and_a_stray_byte_is_corrupt() {
        for mode in [
            AgentPlanMode::Required,
            AgentPlanMode::Optional,
            AgentPlanMode::Off,
        ] {
            assert_eq!(AgentPlanMode::from_byte(mode.to_byte()).ok(), Some(mode));
        }
        assert!(AgentPlanMode::from_byte(3).is_err());
    }
}
