//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/evaluation/of360.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::extraction_eval::Of360ExtractionRun;
use oneiron_base::extraction_eval::Of360GoldDataset;
use oneiron_base::extraction_eval::Of360MetricDirection;
use oneiron_base::extraction_eval::Of360ParsedMetrics;
use oneiron_base::extraction_eval::Of360RateMetric;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Selects one existing native metric, never an average across metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessOf360Metric {
    UpdatingAccuracy,
    QaAccuracy,
    OmissionRate,
    HalumemRecall,
    HalumemWeightedRecall,
    TargetPrecision,
    HalumemF1,
    FaithfulnessRate,
    HallucinationRate,
    OverreachRate,
    TemporalCorrectness,
    RedundancyRate,
}

impl HarnessOf360Metric {
    fn rate(self, metrics: &Of360ParsedMetrics) -> Of360RateMetric {
        match self {
            Self::UpdatingAccuracy => metrics.updating_accuracy,
            Self::QaAccuracy => metrics.qa_accuracy,
            Self::OmissionRate => metrics.omission_rate,
            Self::HalumemRecall => metrics.halumem_recall,
            Self::HalumemWeightedRecall => metrics.halumem_weighted_recall,
            Self::TargetPrecision => metrics.target_precision,
            Self::HalumemF1 => metrics.halumem_f1,
            Self::FaithfulnessRate => metrics.faithfulness_rate,
            Self::HallucinationRate => metrics.hallucination_rate,
            Self::OverreachRate => metrics.overreach_rate,
            Self::TemporalCorrectness => metrics.temporal_correctness,
            Self::RedundancyRate => metrics.redundancy_rate,
        }
    }
}

/// The owner selects the gold, graded run, metric and immutable config version.
/// There is deliberately no submitted scalar or claim that this config ran.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessOf360Evaluation {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub artifact: EntityId,
    pub version: u64,
    pub metric: HarnessOf360Metric,
    pub dataset: Of360GoldDataset,
    pub run: Of360ExtractionRun,
}

/// Native arithmetic and the exact canonical typed inputs it used. Labels and
/// digests identify supplied inputs; they do not authenticate gold or execution.
#[derive(Debug, Clone, Serialize)]
pub struct HarnessOf360Observation {
    pub dataset_id: String,
    pub dataset_revision: String,
    pub dataset_digest: String,
    pub run_id: String,
    pub system_id: String,
    pub run_digest: String,
    pub metric: HarnessOf360Metric,
    pub metric_definition_digest: String,
    pub direction: Of360MetricDirection,
    pub rate: Of360RateMetric,
    /// Higher is better: raw value, or 1 - raw value for a lower-is-better rate.
    pub score: Option<f64>,
    pub warnings: Vec<String>,
}

/// A distinct current producer, alongside the existing three-field owner input.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedOf360Evaluation {
    pub of360: HarnessOf360Evaluation,
}
