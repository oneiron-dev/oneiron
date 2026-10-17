//! Eval-schedule observations over actual immutable config artifact versions.
//! The host records the Dreamer's tuning config as a versioned artifact; each
//! night the self-audit evaluates its head and flags the surfaces a backbone
//! change or a score regression implicates. The retune finding applies at once
//! (OF-023) with a receipt the owner reverts; it is a diagnosis, never a
//! deployed change.
use super::super::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use super::applied::MaintenanceInverse;
use super::{HARNESS_FACET, MAINTENANCE_QUEUE_KIND, invalid, load_row, proposals};
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{ClaimApprovalStatus, ClaimSource, EntityId, Result, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The tuning config artifact's media type.
pub const DREAMER_TUNING_CONFIG_MEDIA_TYPE: &str = "application/json";
/// The owner reviews the self-audit scores: the trailing window of the
/// Dreamer's reviewed proposals.
const AUDIT_WINDOW_SECS: u64 = 30 * 86_400;

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
    pub prompts_score_regression: f64,
    pub weights_score_regression: f64,
    pub manifest_thresholds_score_regression: f64,
}
impl RetuneThresholds {
    fn validate(&self) -> Result<()> {
        if [
            self.prompts_score_regression,
            self.weights_score_regression,
            self.manifest_thresholds_score_regression,
        ]
        .iter()
        .any(|x| !x.is_finite() || !(0.0..=1.0).contains(x))
        {
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
    config: DreamerTuningConfig,
    observed_at: u64,
}
fn config(vault: &Vault, evaluation: &HarnessEvaluation) -> Result<DreamerTuningConfig> {
    if !evaluation.score.is_finite() || !(0.0..=1.0).contains(&evaluation.score) {
        return Err(invalid());
    }
    let artifact = vault
        .get_blob_artifact(&evaluation.artifact)?
        .ok_or_else(invalid)?;
    if artifact.media_type != DREAMER_TUNING_CONFIG_MEDIA_TYPE {
        return Err(invalid());
    }
    let bytes = vault
        .read_blob_artifact_version(&evaluation.artifact, evaluation.version)?
        .ok_or_else(invalid)?;
    let config: DreamerTuningConfig = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    config.validate()?;
    Ok(config)
}
impl DreamerTuningConfig {
    fn validate(&self) -> Result<()> {
        if self.backbone.trim().is_empty()
            || self
                .weights
                .values()
                .chain(self.manifest_thresholds.values())
                .any(|x| !x.is_finite())
        {
            return Err(invalid());
        }
        Ok(())
    }
}
/// The vault's one Dreamer tuning config artifact.
fn tuning_artifact() -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(b"oneiron:dreamer-tuning-config:v1", &[])
}
impl Vault {
    pub fn set_retune_thresholds(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        thresholds: &RetuneThresholds,
    ) -> Result<()> {
        thresholds.validate()?;
        self.with_write_txn_grouped(|txn| {
            super::validate_owner_in_txn(self, txn, owner)?;
            THRESHOLDS.put(&self.store, txn, &(), thresholds)?;
            Ok(())
        })
    }
    /// Records the host's Dreamer tuning config as the next version of the
    /// vault's tuning artifact. The retrieval blend weights the Coach tunes
    /// join its weights as `retrieval.*`, so a weight change is attributed
    /// like any other. The same bytes as the head are no new version, so a
    /// host may record on every start.
    pub fn record_dreamer_tuning_config(
        &self,
        config: &DreamerTuningConfig,
        now: u64,
    ) -> Result<HarnessEvaluationTarget> {
        let mut config = config.clone();
        let blend = self.retrieval_blend_weight_table()?.weights;
        for (key, weight) in [
            ("retrieval.recency", blend.recency),
            ("retrieval.salience", blend.salience),
            ("retrieval.confidence", blend.confidence),
            ("retrieval.gravity", blend.gravity),
        ] {
            config.weights.insert(key.into(), f64::from(weight));
        }
        config.validate()?;
        let artifact = tuning_artifact()?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        if self.get_blob_artifact(&artifact)?.is_none() {
            self.put_blob_artifact(
                &artifact,
                &BlobArtifactBody::new(
                    "dreamer-tuning-config.json",
                    DREAMER_TUNING_CONFIG_MEDIA_TYPE,
                ),
                at,
                now,
            )?;
        }
        let bytes = serde_json::to_vec(&config).map_err(|_| invalid())?;
        let version = self.append_blob_artifact_version(
            &artifact,
            &bytes,
            &BlobVersionProvenance::AgentRun {
                run_ref: HARNESS_FACET.into(),
            },
            self.dreamer_authority()?,
            at,
            now,
        )?;
        Ok(HarnessEvaluationTarget {
            artifact,
            version: version.version,
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
/// The artifact version a recorded tuning config landed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HarnessEvaluationTarget {
    pub artifact: EntityId,
    pub version: u64,
}
impl DreamerRunnerStore<'_> {
    /// The nightly self-audit: a harness attempt with no evaluation input
    /// evaluates the tuning artifact's head itself. One per wake key.
    pub(super) fn enqueue_harness_audit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: HARNESS_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{HARNESS_FACET}:audit:{}",
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id,
            now,
        )
    }
}
/// The self-audit's evaluation of the tuning artifact's head, or `None`
/// before a host has recorded one. The head is recorded again first, so the
/// retrieval weights the Coach tuned since land as a new version.
fn audit(vault: &Vault, now: u64) -> Result<Option<HarnessEvaluation>> {
    let artifact = tuning_artifact()?;
    let Some(head) = vault.blob_artifact_head(&artifact)? else {
        return Ok(None);
    };
    let current = config(
        vault,
        &HarnessEvaluation {
            artifact,
            version: head.version,
            score: 0.0,
        },
    )?;
    let version = vault.record_dreamer_tuning_config(&current, now)?.version;
    Ok(Some(HarnessEvaluation {
        artifact,
        version,
        score: owner_acceptance(vault, now)?,
    }))
}
/// The self-audit's score: how often the owner accepted the Dreamer's own
/// reviewed proposals in the trailing window, Laplace-smoothed so an empty
/// window scores 0.5 rather than nothing. Maintenance findings (`dreamer.*`,
/// `coach.*`) grade the past, not this config's output, and are left out.
fn owner_acceptance(vault: &Vault, now: u64) -> Result<f64> {
    let actor = vault.dreamer_authority()?.entity_ref();
    let since = now.saturating_sub(AUDIT_WINDOW_SECS);
    let (mut accepted, mut reviewed) = (0_u64, 0_u64);
    let txn = vault.store.env.read_txn()?;
    for row in crate::ports::EntityStoreRead::port_entity_raw_records(&vault.store, &txn)? {
        let (_, bytes) = row?;
        let header = EntityMetadataHeader::parse(&bytes).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || bytes.len() == ENTITY_METADATA_HEADER_LEN
            || header.learned_at < since
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&bytes[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.source != Some(ClaimSource::Generated)
            || body.predicate.starts_with("dreamer.")
            || body.predicate.starts_with("coach.")
            || crate::claim::session_claim_producer(&body) != Some(actor)
        {
            continue;
        }
        match body.approval {
            ClaimApprovalStatus::Approved => {
                accepted += 1;
                reviewed += 1;
            }
            ClaimApprovalStatus::Rejected => reviewed += 1,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed => {}
        }
    }
    #[allow(clippy::cast_precision_loss, reason = "a count of claims")]
    Ok((accepted as f64 + 1.0) / (reviewed as f64 + 2.0))
}
pub(super) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<Option<EntityId>> {
    let input = &attempt.status.payload.input;
    let evaluation: HarnessEvaluation = if input.is_nil() {
        match audit(vault, now)? {
            Some(evaluation) => evaluation,
            None => return Ok(None),
        }
    } else {
        serde_json::from_str(input.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?
    };
    let current = config(vault, &evaluation)?;
    let thresholds: RetuneThresholds =
        load_row(vault, THRESHOLDS, include_str!("retune_defaults.json"))?;
    thresholds.validate()?;
    // Resolve the bound envelope before taking the writer. Baseline comparison,
    // finding, receipt and new baseline then commit as one serializable decision.
    // The finding is a diagnosis: it applies at once (OF-023) and deploys nothing.
    proposals::land(vault, HARNESS_FACET, attempt.status.attempt.id, |landing| {
        vault.with_write_txn_grouped(|txn| {
            let prior = BASELINE.get(&vault.store, &*txn, &evaluation.artifact)?;
            if prior.as_ref().is_some_and(|p| p.version > evaluation.version || p.observed_at > now) {
                return Ok(None);
            }
            let proposal = if let Some(prior) = prior {
                let backbone_changed = prior.config.backbone != current.backbone;
                let score_drop = prior.score - evaluation.score;
                let surfaces = [
                    ("prompts", score_drop > thresholds.prompts_score_regression,
                        prior.config.prompts != current.prompts),
                    ("weights", score_drop > thresholds.weights_score_regression,
                        prior.config.weights != current.weights),
                    ("manifest_thresholds", score_drop > thresholds.manifest_thresholds_score_regression,
                        prior.config.manifest_thresholds != current.manifest_thresholds),
                ];
                // Attribute a changed configuration only to the surfaces that
                // changed. An unchanged configuration needs score-only diagnosis.
                let unchanged = surfaces.iter().all(|(_, _, changed)| !changed);
                let targets: Vec<_> = surfaces.into_iter()
                    .filter_map(|(name, regressed, changed)|
                        (backbone_changed || (regressed && (unchanged || changed))).then_some(name))
                    .collect();
                if !targets.is_empty() {
                    let score_regressed = score_drop > thresholds.prompts_score_regression
                        || score_drop > thresholds.weights_score_regression
                        || score_drop > thresholds.manifest_thresholds_score_regression;
                    let value = serde_json::json!({"artifact":evaluation.artifact.to_hex(),"version":evaluation.version,"backbone_changed":backbone_changed,"score_regressed":score_regressed,"targets":targets,"previous_score":prior.score,"score":evaluation.score,"thresholds":thresholds});
                    Some(landing.land_in_txn(vault, txn, &proposals::Finding {
                        subject: evaluation.artifact, predicate: "dreamer.harness.retune_proposal",
                        value: &value, evidence: &[evaluation.artifact] },
                        now, |_| Ok(MaintenanceInverse::Finding))?)
                } else { None }
            } else { None };
            let baseline = Baseline { version: evaluation.version, score: evaluation.score,
                config: current.clone(), observed_at: now };
            BASELINE.put(&vault.store, txn, &evaluation.artifact, &baseline)?;

            Ok(proposal)
        })
    })
}
