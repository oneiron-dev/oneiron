use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Of360EvalError {
    #[error("invalid OF-360 metric definitions JSON: {0}")]
    InvalidMetricDefinitions(#[source] serde_json::Error),
    #[error("invalid OF-360 gold dataset JSON: {0}")]
    InvalidGoldDataset(#[source] serde_json::Error),
    #[error("unsupported OF-360 metric definition schema version `{actual}`")]
    UnsupportedMetricDefinitionSchemaVersion { actual: u32 },
    #[error("unsupported OF-360 gold dataset schema version `{actual}`")]
    UnsupportedGoldDatasetSchemaVersion { actual: u32 },
    #[error("unsupported OF-360 extraction run schema version `{actual}`")]
    UnsupportedExtractionRunSchemaVersion { actual: u32 },
    #[error(
        "OF-360 extraction run dataset mismatch: expected {expected_id}@{expected_revision}, got {actual_id}@{actual_revision}"
    )]
    DatasetMismatch {
        expected_id: String,
        expected_revision: String,
        actual_id: String,
        actual_revision: String,
    },
    #[error("OF-360 gold dataset `{dataset_id}` has duplicate case id `{case_id}`")]
    DuplicateGoldCase { dataset_id: String, case_id: String },
    #[error("OF-360 case `{case_id}` has duplicate turn id `{turn_id}`")]
    DuplicateGoldTurn { case_id: String, turn_id: String },
    #[error("OF-360 case `{case_id}` has duplicate gold memory id `{memory_id}`")]
    DuplicateGoldMemory { case_id: String, memory_id: String },
    #[error("OF-360 case `{case_id}` references unknown evidence turn `{turn_id}`")]
    UnknownEvidenceTurn { case_id: String, turn_id: String },
    #[error("OF-360 case `{case_id}` has invalid gold memory `{memory_id}`: {reason}")]
    InvalidGoldMemory {
        case_id: String,
        memory_id: String,
        reason: &'static str,
    },
    #[error("OF-360 extraction run `{run_id}` has duplicate case output `{case_id}`")]
    DuplicateRunCase { run_id: String, case_id: String },
    #[error("OF-360 extraction run `{run_id}` references unknown case `{case_id}`")]
    UnknownCase { run_id: String, case_id: String },
    #[error("OF-360 case output `{case_id}` has duplicate extraction id `{extraction_id}`")]
    DuplicateExtraction {
        case_id: String,
        extraction_id: String,
    },
    #[error("OF-360 case output `{case_id}` references unknown gold memory `{memory_id}`")]
    UnknownGoldMemory { case_id: String, memory_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Of360MetricDirection {
    HigherIsBetter,
    LowerIsBetter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Of360DerivationEnvelope {
    pub content_hash: String,
    pub model_id: String,
    pub version: String,
    pub params_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360MetricDefinitionSet {
    pub schema_version: u32,
    pub set_id: String,
    pub revision: String,
    pub source_refs: Vec<String>,
    pub derivation_envelope: Of360DerivationEnvelope,
    pub metrics: Vec<Of360MetricDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360MetricDefinition {
    pub metric_id: String,
    pub label: String,
    pub definition: String,
    pub formula: String,
    pub direction: Of360MetricDirection,
    pub primary: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Of360DatasetCompleteness {
    SeedSubset,
    FullOwnerCorpus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Of360Speaker {
    User,
    Assistant,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Of360MemoryKind {
    Persona,
    Preference,
    Event,
    Relationship,
    Plan,
    Constraint,
    Correction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360GoldDataset {
    pub schema_version: u32,
    pub dataset_id: String,
    pub revision: String,
    pub description: String,
    pub completeness: Of360DatasetCompleteness,
    pub seed: u64,
    pub target_full_memory_points: usize,
    pub owner_corpus_missing: bool,
    pub source_refs: Vec<String>,
    pub cases: Vec<Of360GoldCase>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360GoldCase {
    pub case_id: String,
    pub title: String,
    pub turns: Vec<Of360ConversationTurn>,
    pub gold_memory_points: Vec<Of360GoldMemoryPoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distractor_memories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360ConversationTurn {
    pub turn_id: String,
    pub speaker: Of360Speaker,
    pub timestamp: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360GoldMemoryPoint {
    pub memory_id: String,
    pub claim: String,
    pub kind: Of360MemoryKind,
    pub importance: u8,
    pub weight: f64,
    pub is_update: bool,
    pub temporal_required: bool,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub evidence_turn_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360ExtractionRun {
    pub schema_version: u32,
    pub run_id: String,
    pub system_id: String,
    pub dataset_id: String,
    pub dataset_revision: String,
    pub cases: Vec<Of360CaseExtractionOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360CaseExtractionOutput {
    pub case_id: String,
    pub extracted_claims: Vec<Of360ExtractedClaim>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360ExtractedClaim {
    pub extraction_id: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_gold: Vec<Of360GoldMatch>,
    pub temporal_correct: Option<bool>,
    pub overreach: bool,
    pub dedup_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360GoldMatch {
    pub memory_id: String,
    pub score: Of360ExtractionScore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Of360ExtractionScore {
    Omitted,
    Partial,
    Full,
}

impl Of360ExtractionScore {
    #[must_use]
    pub const fn halumem_value(self) -> f64 {
        match self {
            Self::Omitted => 0.0,
            Self::Partial => 0.5,
            Self::Full => 1.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360Ar3MetricTier {
    pub interface_version: u32,
    pub metric_definitions: Of360MetricDefinitionSet,
    pub report: Of360EvalReport,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360EvalReport {
    pub schema_version: u32,
    pub metric_set_id: String,
    pub metric_definition_envelope: Of360DerivationEnvelope,
    pub dataset_id: String,
    pub dataset_revision: String,
    pub run_id: String,
    pub system_id: String,
    pub metrics: Of360ParsedMetrics,
    pub cases: Vec<Of360CaseEvalReport>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360CaseEvalReport {
    pub case_id: String,
    pub metrics: Of360ParsedMetrics,
    pub omitted_gold_memory_ids: Vec<String>,
    pub partial_gold_memory_ids: Vec<String>,
    pub hallucinated_extraction_ids: Vec<String>,
    pub overreach_extraction_ids: Vec<String>,
    pub redundant_extraction_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360ParsedMetrics {
    pub halumem_recall: Of360RateMetric,
    pub halumem_weighted_recall: Of360RateMetric,
    pub target_precision: Of360RateMetric,
    pub halumem_f1: Of360RateMetric,
    pub faithfulness_rate: Of360RateMetric,
    pub hallucination_rate: Of360RateMetric,
    pub overreach_rate: Of360RateMetric,
    pub temporal_correctness: Of360RateMetric,
    pub redundancy_rate: Of360RateMetric,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Of360RateMetric {
    pub value: Option<f64>,
    pub numerator: f64,
    pub denominator: f64,
}

impl Of360RateMetric {
    #[must_use]
    pub fn new(numerator: f64, denominator: f64) -> Self {
        let value = if denominator > 0.0 {
            Some(numerator / denominator)
        } else {
            None
        };
        Self {
            value,
            numerator,
            denominator,
        }
    }

    #[must_use]
    pub fn f1(precision: Self, recall: Self) -> Self {
        let value = match (precision.value, recall.value) {
            (Some(precision), Some(recall)) if precision + recall > 0.0 => {
                Some(2.0 * precision * recall / (precision + recall))
            }
            (Some(_), Some(_)) => Some(0.0),
            _ => None,
        };
        Self {
            value,
            numerator: value.unwrap_or(0.0),
            denominator: f64::from(value.is_some()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Of360SeededSubsetConfig {
    pub seed: u64,
    pub max_cases: usize,
}

impl Default for Of360SeededSubsetConfig {
    fn default() -> Self {
        Self {
            seed: 0x0f36_0001,
            max_cases: usize::MAX,
        }
    }
}
