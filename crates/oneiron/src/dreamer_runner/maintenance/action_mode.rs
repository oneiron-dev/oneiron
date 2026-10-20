//! Action modes (OF-335): the owner's bands over the composite state index,
//! each naming a mode in the owner's own words. Each night the Dreamer
//! refreshes every owner's index from their own records and, when the fresh
//! index falls in a band, files the band's mode as an advisory finding. It
//! applies at once with a receipt the owner reverts (OF-023), and the inbox's
//! finding notice tells the owner; one the Gate parks waits in the run tray.
//! A mode is advice: it grants nothing and changes no consent, and a missing
//! input selects no mode. A band may name one explicit agent-ceiling patch
//! (FIX 1786); its finding freezes the patch, and only the owner's
//! [`Vault::apply_action_mode`] puts it on the agent's definition, with an
//! inverse the owner's revert runs. A finding landing, even at Auto, applies
//! no patch.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::applied::{self, AppliedMaintenance, MaintenanceInverse, MaintenanceRevert};
use super::{MAINTENANCE_QUEUE_KIND, invalid, proposals, validate_owner_in_txn};
use crate::affect::state_inputs::StateWindow;
use crate::agent_def::AgentCeiling;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::edge::EdgeActorClass;
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    ClaimApprovalStatus, ClaimLifecycleStatus, EntityId, Error, Result, Vault, WriteActor,
};

pub const ACTION_MODE_FACET: &str = "dreamer.action_mode";
/// Predicate of an advisory action-mode finding.
pub const ACTION_MODE_PROPOSAL_PREDICATE: &str = "dreamer.action_mode.proposal";
const POLICY: SideTable<(), ActionModePolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_ACTION_MODE_POLICY);

/// One band: an index in `[min_index, max_index)` selects `mode`; a band
/// whose upper bound is 1 includes 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionModeRule {
    pub mode: String,
    pub min_index: f32,
    pub max_index: f32,
    /// The explicit agent-ceiling patch an approved mode applies (FIX
    /// 1786). `None` keeps the mode advice only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<ActionModeEffect>,
}

/// One band's explicit patch (FIX 1786): the agent whose definition ceiling
/// the mode sets, and that ceiling. It names no grant, scope or connector;
/// the ceiling still meets the preset and the owner's manifest at every gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionModeEffect {
    pub agent: EntityId,
    pub ceiling: ActionModeCeiling,
}

/// An agent definition's ceiling as a patch names it: ask first, or eligible
/// to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionModeCeiling {
    Proposed,
    Auto,
}

impl ActionModeCeiling {
    const fn agent_ceiling(self) -> AgentCeiling {
        match self {
            Self::Proposed => AgentCeiling::Proposed,
            Self::Auto => AgentCeiling::Auto,
        }
    }

    const fn of(ceiling: AgentCeiling) -> Self {
        match ceiling {
            AgentCeiling::Proposed => Self::Proposed,
            AgentCeiling::Auto => Self::Auto,
        }
    }
}

/// A patch as its finding froze it: with the agent's definition version the
/// night read, which the owner's apply is fenced on; `None` when no
/// definition stood at that id then.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenEffect {
    agent: EntityId,
    ceiling: ActionModeCeiling,
    agent_version: Option<String>,
}

/// The part of an action-mode finding's value the apply reads.
#[derive(Deserialize)]
struct FrozenFinding {
    #[serde(default)]
    effect: Option<FrozenEffect>,
}

/// The owner's action-mode policy: the window each index is measured over,
/// with its targets, and ascending bands that do not overlap. A gap selects
/// no mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionModePolicy {
    pub window: StateWindow,
    pub rules: Vec<ActionModeRule>,
}

/// The measured, non-clinical state and the mode the configured policy selects.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActionModeProjection {
    pub policy: Option<ActionModePolicy>,
    pub state_index: crate::affect::state_index::StateIndex,
    pub mode: Option<ActionModeRule>,
}

impl ActionModePolicy {
    fn validate(&self) -> Result<()> {
        self.window.validate()?;
        let band = |rule: &ActionModeRule| {
            !rule.mode.trim().is_empty()
                && (0.0..=1.0).contains(&rule.min_index)
                && (0.0..=1.0).contains(&rule.max_index)
                && rule.min_index < rule.max_index
        };
        if self.rules.is_empty()
            || !self.rules.iter().all(band)
            || self
                .rules
                .windows(2)
                .any(|pair| pair[0].max_index > pair[1].min_index)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Measures the policy against its `[limits]` rows (OF-520): its window,
    /// its bands and its longest mode. Past one the vault's port asks, and
    /// the policy is kept whole.
    fn measure(&self, vault: &Vault) {
        let _ = vault.measure_limit(EngineLimit::StateWindowSeconds, self.window.window_secs);
        let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, self.rules.len() as u64);
        if let Some(longest) = self.rules.iter().map(|rule| rule.mode.len()).max() {
            let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
        }
    }

    fn mode_for(&self, value: f32) -> Option<&ActionModeRule> {
        self.rules.iter().find(|rule| {
            rule.min_index <= value
                && (value < rule.max_index || (rule.max_index == 1.0 && value == 1.0))
        })
    }
}

impl Vault {
    /// The owner's action-mode policy; `None` when none is set, and then no
    /// night refreshes an index for it.
    pub fn action_mode_policy(&self) -> Result<Option<ActionModePolicy>> {
        let txn = self.store.env.read_txn()?;
        POLICY.get(&self.store, &txn, &())
    }

    /// The same measurement and band selection used by the nightly run, for one subject.
    pub(crate) fn project_action_mode_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        subject: &EntityId,
        now: u64,
        refresh: bool,
    ) -> Result<ActionModeProjection> {
        let policy = POLICY.get(&self.store, txn, &())?;
        let state_index = if refresh {
            match &policy {
                Some(policy) => self
                    .refresh_state_index_in_txn(txn, subject, &policy.window, now)?
                    .map(|(_, index)| index)
                    .unwrap_or_default(),
                None => Default::default(),
            }
        } else {
            self.state_index_in_txn(txn, subject, now)?
        };
        let mode = state_index.inputs.as_ref().and_then(|_| {
            policy
                .as_ref()
                .and_then(|policy| policy.mode_for(state_index.value))
                .cloned()
        });
        Ok(ActionModeProjection {
            policy,
            state_index,
            mode,
        })
    }

    /// Replaces the owner's action-mode policy; `None` clears it.
    pub fn set_action_mode_policy(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        policy: Option<ActionModePolicy>,
    ) -> Result<Option<ActionModePolicy>> {
        if let Some(policy) = &policy {
            policy.validate()?;
            policy.measure(self);
        }
        self.with_write_txn_grouped(|txn| {
            validate_owner_in_txn(self, txn, owner)?;
            match &policy {
                Some(policy) => POLICY.put(&self.store, txn, &(), policy)?,
                None => {
                    POLICY.delete(&self.store, txn, &())?;
                }
            }
            Ok(policy.clone())
        })
    }

    /// The owner's apply of one action-mode finding's ceiling patch (FIX
    /// 1786), in ONE transaction. `approved` is the patch the owner was
    /// shown and must be the one the finding froze. The agent's ceiling moves
    /// to it through the owner's definition writer, fenced on the definition
    /// version the finding read, and the finding's applied row takes the
    /// inverse under the owner's receipt, so the owner's revert of the
    /// finding puts the ceiling back. A second apply returns the first.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds; a finding that is no live action-mode
    /// finding the Dreamer applied or the owner approved, or that carries no
    /// patch or another one than `approved`; [`Error::ConcurrentWrite`] when
    /// the agent's definition moved since the finding read it; the
    /// definition writer's own refusals; storage errors.
    pub fn apply_action_mode(
        &self,
        owner: &AuthenticatedOwner,
        finding: EntityId,
        approved: &ActionModeEffect,
        now: u64,
    ) -> Result<AppliedMaintenance> {
        let applied = self.with_write_txn_grouped(|txn| {
            let actor = validate_owner_in_txn(self, txn, owner)?;
            let effect = frozen_patch_in_txn(self, txn, &finding)?;
            if effect.agent != approved.agent || effect.ceiling != approved.ceiling {
                return Err(invalid());
            }
            if let Some(done) = applied::action_mode_applied_in_txn(self, txn, finding)? {
                return Ok(done);
            }
            let version = effect.agent_version.ok_or_else(invalid)?;
            let before = self
                .read_agent_definition_in_txn(txn, &effect.agent)?
                .ceiling;
            let patched = self.patch_agent_ceiling_at_version_in_txn(
                txn,
                owner,
                &effect.agent,
                &version,
                effect.ceiling.agent_ceiling(),
                now,
            )?;
            applied::record_action_mode_in_txn(
                self,
                txn,
                finding,
                WriteActor::new(actor, EdgeActorClass::Human),
                MaintenanceInverse::ActionMode {
                    agent: effect.agent,
                    before_ceiling: ActionModeCeiling::of(before),
                    applied_ceiling: effect.ceiling,
                    applied_version: patched.version,
                },
                now,
            )
        })?;
        self.store.notify_proactivity_changes();
        Ok(applied)
    }
}

/// The patch action-mode `finding` froze, from a live finding the Dreamer
/// applied at Auto or the owner approved in the run tray.
fn frozen_patch_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    finding: &EntityId,
) -> Result<FrozenEffect> {
    let body = vault
        .get_claim_in_txn(txn, finding)?
        .ok_or(Error::EntityNotFound)?;
    if body.predicate != ACTION_MODE_PROPOSAL_PREDICATE
        || body.lifecycle != ClaimLifecycleStatus::Active
        || !matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
    {
        return Err(invalid());
    }
    let frozen: FrozenFinding =
        serde_json::from_str(body.value.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    frozen.effect.ok_or_else(invalid)
}

/// A band's patch as its finding freezes it, with the agent's definition
/// version as it stands in this write.
fn frozen_effect_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    effect: &ActionModeEffect,
) -> Result<serde_json::Value> {
    let agent_version = match vault.read_agent_definition_in_txn(txn, &effect.agent) {
        Ok(definition) => Some(definition.version),
        Err(Error::EntityNotFound | Error::Artifact(_)) => None,
        Err(error) => return Err(error),
    };
    serde_json::to_value(FrozenEffect {
        agent: effect.agent,
        ceiling: effect.ceiling,
        agent_version,
    })
    .map_err(|_| invalid())
}

/// Undoes the owner's apply of a ceiling patch (FIX 1786), as the owner,
/// through the same definition writer: the agent's ceiling goes back to
/// `before` while the revision the apply wrote still stands. A definition a
/// later write moved, or one gone, is left alone.
#[expect(
    clippy::too_many_arguments,
    reason = "one applied patch's agent, prior ceiling and revision, and the revert's writer"
)]
pub(super) fn revert_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    agent: EntityId,
    before: ActionModeCeiling,
    applied_version: &str,
    now: u64,
    out: &mut MaintenanceRevert,
) -> Result<()> {
    let current = match vault.read_agent_definition_in_txn(txn, &agent) {
        Ok(definition) => definition,
        Err(Error::EntityNotFound) => {
            out.left_alone.push(agent.to_hex());
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if current.version != applied_version {
        out.left_alone.push(agent.to_hex());
        return Ok(());
    }
    if current.ceiling != before.agent_ceiling() {
        vault.patch_agent_ceiling_at_version_in_txn(
            txn,
            owner,
            &agent,
            applied_version,
            before.agent_ceiling(),
            now,
        )?;
    }
    out.restored.push(agent);
    Ok(())
}

impl DreamerRunnerStore<'_> {
    /// One action-mode run per owner per wake key, while a policy is set.
    pub(super) fn enqueue_action_mode_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        if POLICY.get(&self.vault.store, &*txn, &())?.is_none() {
            return Ok(());
        }
        for owner in crate::policy_model::owners_in_txn(self.vault, &*txn)? {
            let owner = owner.to_hex();
            self.enqueue_kind_in_txn(
                txn,
                MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: ACTION_MODE_FACET.into(),
                    input: Value::from(owner.as_str()),
                    parent_attempt,
                },
                wake_key.map(|key| {
                    format!(
                        "{ACTION_MODE_FACET}:{}",
                        blake3::hash(format!("{key}:{owner}").as_bytes()).to_hex()
                    )
                }),
                run_id.clone(),
                now,
            )?;
        }
        Ok(())
    }
}

/// Refreshes one owner's index and files the mode its band names. Returns
/// the finding, or `None` when no policy is set, an input is missing or the
/// index falls in no band. The finding applies at once; its revert retracts
/// it, and the refreshed index stays, as a measurement.
pub(super) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<Option<EntityId>> {
    let subject = EntityId::from_hex(attempt.status.payload.input.as_str().ok_or_else(invalid)?)?;
    let attempt = attempt.status.attempt.id;
    proposals::land(vault, ACTION_MODE_FACET, attempt, |landing| {
        vault.with_write_txn_grouped(|txn| {
            let projection = vault.project_action_mode_in_txn(txn, &subject, now, true)?;
            let Some(rule) = projection.mode else {
                return Ok(None);
            };
            let index = projection.state_index;
            let claim = EntityId::from_hex(index.claim.as_deref().ok_or_else(invalid)?)?;
            let mut value = serde_json::json!({
                "mode": rule.mode,
                "band": [rule.min_index, rule.max_index],
                "state_index": index,
            });
            if let Some(effect) = &rule.effect {
                value["effect"] = frozen_effect_in_txn(vault, txn, effect)?;
            }
            landing
                .land_in_txn(
                    vault,
                    txn,
                    &proposals::Finding {
                        subject,
                        predicate: ACTION_MODE_PROPOSAL_PREDICATE,
                        value: &value,
                        evidence: &[claim],
                    },
                    now,
                    |_| Ok(MaintenanceInverse::Finding),
                )
                .map(Some)
        })
    })
}
