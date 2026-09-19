//! Eval-schedule observations over actual immutable config artifact versions.
use super::super::{DreamerAdmittedAttempt, DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use super::{HARNESS_FACET, invalid, load_row, proposals};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
const THRESHOLDS_KEY: &[u8] = b"settings:dreamer:harness:thresholds:v1";
const BASELINE_PREFIX: &[u8] = b"dreamer:harness:eval-baseline:v1:";
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
        _owner: &crate::consent::AuthenticatedOwner,
        thresholds: &RetuneThresholds,
    ) -> Result<()> {
        thresholds.validate()?;
        let bytes = serde_json::to_vec(thresholds).map_err(|_| invalid())?;
        self.with_write_txn(|txn| {
            self.store.vault_meta.put(txn, THRESHOLDS_KEY, &bytes)?;
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
        load_row(vault, THRESHOLDS_KEY, include_str!("retune_defaults.json"))?;
    thresholds.validate()?;
    let key = [BASELINE_PREFIX, evaluation.artifact.as_bytes()].concat();
    let txn = vault.store.env.read_txn()?;
    let prior: Option<Baseline> = vault
        .store
        .vault_meta
        .get(&txn, &key)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| invalid()))
        .transpose()?;
    drop(txn);
    if prior
        .as_ref()
        .is_some_and(|p| p.version > evaluation.version || p.observed_at > now)
    {
        return Ok(None);
    }
    let proposal = if let Some(prior) = prior {
        let backbone_changed = prior.backbone != current.backbone;
        let regressed = prior.score - evaluation.score > thresholds.score_regression;
        if backbone_changed || regressed {
            let value = serde_json::json!({"artifact":evaluation.artifact.to_hex(),"version":evaluation.version,"backbone_changed":backbone_changed,"score_regressed":regressed,"targets":["prompts","weights","manifest_thresholds"],"previous_score":prior.score,"score":evaluation.score});
            Some(proposals::emit(
                vault,
                attempt.status.attempt.id,
                HARNESS_FACET,
                evaluation.artifact,
                "dreamer.harness.retune_proposal",
                &value,
                now,
            )?)
        } else {
            None
        }
    } else {
        None
    };
    let baseline = Baseline {
        version: evaluation.version,
        score: evaluation.score,
        backbone: current.backbone,
        observed_at: now,
    };
    let bytes = serde_json::to_vec(&baseline).map_err(|_| invalid())?;
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(txn, &key, &bytes)?;
        Ok(())
    })?;
    Ok(proposal)
}
