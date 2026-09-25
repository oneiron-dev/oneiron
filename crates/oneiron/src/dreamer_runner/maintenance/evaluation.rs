//! Eval-schedule observations over actual immutable config artifact versions.
use super::super::{DreamerAdmittedAttempt, DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use super::{HARNESS_FACET, invalid, load_row, proposals};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Owner-set retune-decision thresholds dial.
const THRESHOLDS: SideTable<(), RetuneThresholds, LegacyJson> =
    SideTable::new(&side_table::DREAMER_HARNESS_THRESHOLDS);
/// Prior tuning-harness evaluation baseline for a config artifact.
const BASELINE: SideTable<EntityId, Baseline, LegacyJson> =
    SideTable::new(&side_table::DREAMER_HARNESS_EVAL_BASELINE);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerTuningConfig {
    pub backbone: String,
    pub prompts: Vec<String>,
    pub weights: BTreeMap<String, f64>,
    pub manifest_thresholds: BTreeMap<String, f64>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessEvaluation {
    #[serde(with = "crate::serialize::entity_ref")]
    pub artifact: EntityId,
    pub version: u64,
    pub score: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetuneThresholds {
    pub score_regression: f64,
}
impl RetuneThresholds {
    fn validate(&self) -> Result<()> {
        if !self.score_regression.is_finite() || !(0.0..=1.0).contains(&self.score_regression) {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    version: u64,
    score: f64,
    backbone: String,
    observed_at: u64,
}
fn config(vault: &Vault, evaluation: &HarnessEvaluation) -> Result<DreamerTuningConfig> {
    if !evaluation.score.is_finite() || !(0.0..=1.0).contains(&evaluation.score) {
        return Err(invalid());
    }
    let artifact = vault
        .get_blob_artifact(&evaluation.artifact)?
        .ok_or_else(invalid)?;
    if artifact.media_type != "application/json" {
        return Err(invalid());
    }
    let bytes = vault
        .read_blob_artifact_version(&evaluation.artifact, evaluation.version)?
        .ok_or_else(invalid)?;
    let config: DreamerTuningConfig = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if config.backbone.trim().is_empty()
        || config
            .weights
            .values()
            .chain(config.manifest_thresholds.values())
            .any(|x| !x.is_finite())
    {
        return Err(invalid());
    }
    Ok(config)
}
impl Vault {
    pub fn set_retune_thresholds(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        thresholds: &RetuneThresholds,
    ) -> Result<()> {
        thresholds.validate()?;
        self.with_write_txn(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            THRESHOLDS.put(&self.store, txn, &(), thresholds)?;
            Ok(())
        })
    }
    pub fn schedule_harness_evaluation(
        &self,
        evaluation: &HarnessEvaluation,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        config(self, evaluation)?;
        let bytes = serde_json::to_string(evaluation).map_err(|_| invalid())?;
        let key = blake3::hash(bytes.as_bytes()).to_hex().to_string();
        DreamerRunnerStore::new(self).enqueue_maintenance(
            HARNESS_FACET,
            rmpv::Value::from(bytes),
            key,
            now,
        )
    }
}
pub(super) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<Option<EntityId>> {
    let evaluation: HarnessEvaluation =
        serde_json::from_str(attempt.status.payload.input.as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    let current = config(vault, &evaluation)?;
    let thresholds: RetuneThresholds =
        load_row(vault, THRESHOLDS, include_str!("retune_defaults.json"))?;
    thresholds.validate()?;
    // Resolve the bound envelope before taking the writer. Baseline comparison,
    // proposal, receipt and new baseline then commit as one serializable decision.
    let envelope = vault.dreamer_proposal_envelope(HARNESS_FACET, attempt.status.attempt.id)?;
    vault.with_write_txn(|txn| {
        let prior = BASELINE.get(&vault.store, &*txn, &evaluation.artifact)?;
        if prior.as_ref().is_some_and(|p| p.version > evaluation.version || p.observed_at > now) {
            return Ok(None);
        }
        let proposal = if let Some(prior) = prior {
            let backbone_changed = prior.backbone != current.backbone;
            let regressed = prior.score - evaluation.score > thresholds.score_regression;
            if backbone_changed || regressed {
                let value = serde_json::json!({"artifact":evaluation.artifact.to_hex(),"version":evaluation.version,"backbone_changed":backbone_changed,"score_regressed":regressed,"targets":["prompts","weights","manifest_thresholds"],"previous_score":prior.score,"score":evaluation.score});
                Some(proposals::emit_in_txn(vault, txn, evaluation.artifact,
                    "dreamer.harness.retune_proposal", &value, &envelope, now)?)
            } else { None }
        } else { None };
        let baseline = Baseline { version: evaluation.version, score: evaluation.score,
            backbone: current.backbone, observed_at: now };
        BASELINE.put(&vault.store, txn, &evaluation.artifact, &baseline)?;
        Ok(proposal)
    })
}
