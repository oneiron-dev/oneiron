//! Owner-selected native OF360 metrics over the supplied, digest-pinned inputs.
//! The engine computes the metric; the owner supplies the graded run and its
//! association with a tuning version. Neither is independent execution proof.

use super::{HarnessEvaluation, config_target_in_txn, invalid};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use crate::extraction_eval::{
    Of360ExtractionRun, Of360GoldDataset, Of360MetricDirection, Of360ParsedMetrics,
    Of360RateMetric, of360_ar3_metric_tier,
};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub(super) use oneiron_records::dreamer_runner::maintenance::evaluation::of360::QueuedOf360Evaluation;
#[doc(hidden)]
pub use oneiron_records::dreamer_runner::maintenance::evaluation::of360::{
    HarnessOf360Evaluation, HarnessOf360Metric, HarnessOf360Observation,
};

#[derive(Debug)]
pub struct HarnessOf360Scheduled {
    /// None means the selected metric had no denominator, not a passing score.
    pub attempt: Option<AttemptId>,
    pub observation: HarnessOf360Observation,
}

pub(super) struct Prepared {
    pub evaluation: Option<HarnessEvaluation>,
    pub observation: HarnessOf360Observation,
    pub baseline_key: EntityId,
}

pub(super) fn prepare(input: &HarnessOf360Evaluation) -> Result<Prepared> {
    let tier = of360_ar3_metric_tier(&input.dataset, &input.run).map_err(|_| invalid())?;
    let metric_id = serde_json::to_value(input.metric).map_err(|_| invalid())?;
    let definition = tier
        .metric_definitions
        .metrics
        .iter()
        .find(|definition| Some(definition.metric_id.as_str()) == metric_id.as_str())
        .ok_or_else(invalid)?;
    let rate = input.metric.rate(&tier.report.metrics);
    let score = rate.value.map(|value| match definition.direction {
        Of360MetricDirection::HigherIsBetter => value,
        Of360MetricDirection::LowerIsBetter => 1.0 - value,
    });
    if score.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
        return Err(invalid());
    }
    let dataset_bytes = serde_json::to_vec(&input.dataset).map_err(|_| invalid())?;
    let run_bytes = serde_json::to_vec(&input.run).map_err(|_| invalid())?;
    let definition_bytes = serde_json::to_vec(&tier.metric_definitions).map_err(|_| invalid())?;
    let dataset_digest = blake3::hash(&dataset_bytes).to_hex().to_string();
    let metric_definition_digest = blake3::hash(&definition_bytes).to_hex().to_string();
    // Run/config versions vary within one comparison; gold, metric and its
    // definition must not. Existing owner/audit baselines keep their old keys.
    let identity = serde_json::to_vec(&(
        input.artifact.to_hex(),
        &dataset_digest,
        input.metric,
        &metric_definition_digest,
    ))
    .map_err(|_| invalid())?;
    let baseline_key = crate::codebase::entity_id_from_hash_material(
        b"oneiron:dreamer-harness-of360-baseline:v1",
        &[identity.as_slice()],
    )?;
    Ok(Prepared {
        evaluation: score.map(|score| HarnessEvaluation {
            artifact: input.artifact,
            version: input.version,
            score,
        }),
        observation: HarnessOf360Observation {
            dataset_id: tier.report.dataset_id,
            dataset_revision: tier.report.dataset_revision,
            dataset_digest,
            run_id: tier.report.run_id,
            system_id: tier.report.system_id,
            run_digest: blake3::hash(&run_bytes).to_hex().to_string(),
            metric: input.metric,
            metric_definition_digest,
            direction: definition.direction.clone(),
            rate,
            score,
            warnings: tier.report.warnings,
        },
        baseline_key,
    })
}

impl Vault {
    /// Computes the native selected metric from supplied gold/run inputs, then
    /// validates the real owner and config version in the enqueue writer.
    /// Pure evaluation does no vault I/O and runs outside that writer.
    pub fn schedule_harness_of360_evaluation_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        input: &HarnessOf360Evaluation,
        now: u64,
    ) -> Result<HarnessOf360Scheduled> {
        let prepared = prepare(input)?;
        let attempt = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            config_target_in_txn(self, &*txn, input.artifact, input.version)?;
            if prepared.evaluation.is_none() {
                return Ok(None);
            }
            let bytes = serde_json::to_string(&QueuedOf360Evaluation {
                of360: input.clone(),
            })
            .map_err(|_| invalid())?;
            let key = blake3::hash(bytes.as_bytes()).to_hex().to_string();
            let outcome = DreamerRunnerStore::new(self).enqueue_maintenance_in_txn(
                txn,
                super::HARNESS_FACET,
                rmpv::Value::from(bytes),
                key,
                now,
            )?;
            let (EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
            Ok(Some(status.attempt.id))
        })?;
        Ok(HarnessOf360Scheduled {
            attempt,
            observation: prepared.observation,
        })
    }
}
