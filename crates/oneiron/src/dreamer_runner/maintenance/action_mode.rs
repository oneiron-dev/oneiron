//! Action modes (OF-335): the owner's bands over the composite state index,
//! each naming a mode in the owner's own words. Each night the Dreamer
//! refreshes every owner's index from their own records and, when the fresh
//! index falls in a band, files the band's mode as a proposal in the run
//! tray, which the next digest carries. A mode is a proposal only: it grants
//! nothing and changes no consent, and a missing input selects no mode.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{MAINTENANCE_QUEUE_KIND, invalid, proposals, validate_owner_in_txn};
use crate::affect::state_inputs::StateWindow;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Result, Vault};

pub const ACTION_MODE_FACET: &str = "dreamer.action_mode";
/// Predicate of a proposed action mode.
pub const ACTION_MODE_PROPOSAL_PREDICATE: &str = "dreamer.action_mode.proposal";
const POLICY: SideTable<(), ActionModePolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_ACTION_MODE_POLICY);
const MAX_RULES: usize = 16;
const MAX_MODE_BYTES: usize = 128;

/// One band: an index in `[min_index, max_index)` selects `mode`; a band
/// whose upper bound is 1 includes 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionModeRule {
    pub mode: String,
    pub min_index: f32,
    pub max_index: f32,
}

/// The owner's action-mode policy: the window each index is measured over,
/// with its targets, and ascending bands that do not overlap. A gap selects
/// no mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionModePolicy {
    pub window: StateWindow,
    pub rules: Vec<ActionModeRule>,
}

impl ActionModePolicy {
    fn validate(&self) -> Result<()> {
        self.window.validate()?;
        let band = |rule: &ActionModeRule| {
            !rule.mode.trim().is_empty()
                && rule.mode.len() <= MAX_MODE_BYTES
                && (0.0..=1.0).contains(&rule.min_index)
                && (0.0..=1.0).contains(&rule.max_index)
                && rule.min_index < rule.max_index
        };
        if self.rules.is_empty()
            || self.rules.len() > MAX_RULES
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

    /// Replaces the owner's action-mode policy; `None` clears it.
    pub fn set_action_mode_policy(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        policy: Option<ActionModePolicy>,
    ) -> Result<Option<ActionModePolicy>> {
        if let Some(policy) = &policy {
            policy.validate()?;
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
/// the proposal, or `None` when no policy is set, an input is missing or the
/// index falls in no band.
pub(super) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<Option<EntityId>> {
    let subject = EntityId::from_hex(attempt.status.payload.input.as_str().ok_or_else(invalid)?)?;
    let envelope =
        proposals::run_tray_envelope(vault, ACTION_MODE_FACET, attempt.status.attempt.id)?;
    vault.with_write_txn_grouped(|txn| {
        let Some(policy) = POLICY.get(&vault.store, &*txn, &())? else {
            return Ok(None);
        };
        let Some((claim, index)) =
            vault.refresh_state_index_in_txn(txn, &subject, &policy.window, now)?
        else {
            return Ok(None);
        };
        let Some(rule) = policy.mode_for(index.value) else {
            return Ok(None);
        };
        let value = serde_json::json!({
            "mode": rule.mode,
            "band": [rule.min_index, rule.max_index],
            "state_index": index,
        });
        proposals::emit_in_txn(
            vault,
            txn,
            subject,
            ACTION_MODE_PROPOSAL_PREDICATE,
            &value,
            &[claim],
            &envelope,
            now,
        )
        .map(Some)
    })
}
