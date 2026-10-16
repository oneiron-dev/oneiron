//! Composite-index-gated action-mode proposals on the existing Dreamer lane.
//! Mode identifiers, score bands, cadence and timing come from host policy.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::super::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use super::{MAINTENANCE_QUEUE_KIND, invalid, proposals, validate_owner_in_txn};
use crate::affect::state_inputs::StateIndexSources;
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Result, Vault};

pub const ACTION_MODE_FACET: &str = "dreamer.action_mode";
const PREDICATE: &str = "dreamer.action_mode.proposal";

/// A policy-supplied identifier, not an engine-authored label or a grant.
/// Bands are [min_index, max_index), except that an upper bound of 1 includes 1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionModeRule {
    pub mode: String,
    pub min_index: f32,
    pub max_index: f32,
    pub delay_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionModeRecipe {
    pub cadence_secs: u64,
    /// Ascending, non-overlapping bands. Gaps mean no action-mode proposal.
    pub rules: Vec<ActionModeRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionModeRequest {
    #[serde(with = "crate::serialize::entity_ref")]
    pub subject: EntityId,
    pub sources: StateIndexSources,
    pub recipe: ActionModeRecipe,
}

impl ActionModeRequest {
    fn validate(&self) -> Result<()> {
        self.sources.validate()?;
        if self.recipe.cadence_secs == 0
            || self.recipe.rules.is_empty()
            || self.recipe.rules.iter().any(|rule| {
                rule.mode.trim().is_empty()
                    || !rule.min_index.is_finite()
                    || !rule.max_index.is_finite()
                    || !(0.0..=1.0).contains(&rule.min_index)
                    || !(0.0..=1.0).contains(&rule.max_index)
                    || rule.min_index >= rule.max_index
            })
            || self
                .recipe
                .rules
                .windows(2)
                .any(|pair| pair[0].max_index > pair[1].min_index)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Vault {
    /// Queue an owner-authored mode policy. It can produce only a proposal;
    /// a high composite value never expands an actor's consent or capabilities.
    pub fn schedule_action_mode(
        &self,
        owner: &AuthenticatedOwner,
        request: &ActionModeRequest,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        request.validate()?;
        let input = serde_json::to_string(request).map_err(|_| invalid())?;
        let dedupe = format!(
            "action-mode:{}:{}",
            blake3::hash(input.as_bytes()).to_hex(),
            now / request.recipe.cadence_secs,
        );
        self.with_write_txn_grouped(|txn| {
            validate_owner_in_txn(self, txn, owner)?;
            DreamerRunnerStore::new(self).enqueue_kind_in_txn(
                txn,
                MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: ACTION_MODE_FACET.into(),
                    input: Value::from(input.clone()),
                    parent_attempt: None,
                },
                Some(dedupe.clone()),
                None,
                now,
            )
        })
    }
}

pub(super) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<Option<EntityId>> {
    let request: ActionModeRequest =
        serde_json::from_str(attempt.status.payload.input.as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    request.validate()?;
    let envelope = vault.dreamer_proposal_envelope(ACTION_MODE_FACET, attempt.status.attempt.id)?;
    vault.with_write_txn_grouped(|txn| {
        let index =
            vault.refresh_state_index_in_txn(txn, &request.subject, &request.sources, now)?;
        // Neutral absence is not a measured 0.5 and cannot select a mode.
        if index.claim.is_none() || index.inputs.is_none() {
            return Ok(None);
        }
        let Some(rule) = request.recipe.rules.iter().find(|rule| {
            rule.min_index <= index.value
                && (index.value < rule.max_index || (rule.max_index == 1.0 && index.value == 1.0))
        }) else {
            return Ok(None);
        };
        let not_before = now.checked_add(rule.delay_secs).ok_or_else(invalid)?;
        let value = serde_json::json!({
            "mode": rule.mode,
            "not_before": not_before,
            "state_index": index,
            "recipe": request.recipe,
        });
        proposals::emit_in_txn(
            vault,
            txn,
            request.subject,
            PREDICATE,
            &value,
            &envelope,
            now,
        )
        .map(Some)
    })
}
