//! An agent's plan mode (agent-runtime-v1.md, "Plan mode reuses built review
//! parts": "Per-agent plan_mode: required | optional | off"; Engine ruling
//! SETTING = A, Fri 13 Nov 03:05).
//!
//! The mode is the owner's authority over one agent, not part of its
//! definition: a saved, travelling or packed definition carries none. It is
//! the setting `agents.plan_mode` (`super::setting_keys::PLAN_MODE`), one row
//! per agent and a vault row for every agent without one, and only the owner
//! changes it (`vault.settings.set`). With no row an agent is `optional`.
//!
//! - `required`: a run of the agent that a non-owner starts needs a plan the
//!   owner approved. A TASK for it must pin a plan-doc approved at the pinned
//!   revision, and an agent's spawn or workflow leaf of it, which pins none,
//!   is refused. The owner's own TASK for it is never refused.
//! - `optional`: the agent may propose a plan and may run without one.
//! - `off`: the agent may not propose a plan (`vault.plans.propose`).

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::setting::{SettingScope, SettingValue};
use crate::side_table::SideTableDbs;

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

impl SettingValue for AgentPlanMode {}

/// The refusal reason for a run of a `required` agent with no approved plan.
pub(crate) const PLAN_MODE_REQUIRED: &str = "gate.deny.plan_mode.required";
/// The refusal reason for a plan an `off` agent proposes.
pub(crate) const PLAN_MODE_OFF: &str = "gate.deny.plan_mode.off";

/// The mode `agent` has: its row, the vault's, or `optional`.
pub(crate) fn agent_plan_mode_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<AgentPlanMode> {
    Ok(super::setting_keys::PLAN_MODE
        .read_in_dbs_txn(dbs, txn, &[SettingScope::Agent(agent)], None)?
        .value)
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

impl Vault {
    /// The plan mode `agent` has now: its row, the vault's, or `optional`.
    ///
    /// # Errors
    ///
    /// A store read error, or a corrupt row.
    pub fn agent_plan_mode(&self, agent: EntityId) -> Result<AgentPlanMode> {
        let txn = self.store.env.read_txn()?;
        agent_plan_mode_in_txn(&self.store, &txn, agent)
    }
}
