use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

const OF360_GOLD_SUBSET_JSON: &str = include_str!("data/of360_gold_subset.v1.json");
const OF360_METRIC_DEFINITIONS_JSON: &str = include_str!("data/of360_metric_definitions.v1.json");

pub const OF360_AR3_METRIC_TIER_INTERFACE_VERSION: u32 = 1;
pub const OF360_SCHEMA_VERSION: u32 = 1;
pub const OF360_METRIC_DEFINITION_SET_ID: &str = "of360-halumem-extraction-quality.v1";
pub const OF360_METRIC_DEFINITION_SET_REVISION: &str = "2026-07-07.one-1524";
pub const OF360_GOLD_DATASET_ID: &str = "of360-halumem-gold-subset.v1";
pub const OF360_GOLD_DATASET_REVISION: &str = "seed-subset.2026-07-07";

type Of360Result<T> = Result<T, Of360EvalError>;

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

#[must_use]
pub const fn of360_metric_definitions_json() -> &'static str {
    OF360_METRIC_DEFINITIONS_JSON
}

#[must_use]
pub const fn of360_gold_subset_json() -> &'static str {
    OF360_GOLD_SUBSET_JSON
}

pub fn of360_metric_definitions() -> Of360Result<Of360MetricDefinitionSet> {
    let definitions = serde_json::from_str(OF360_METRIC_DEFINITIONS_JSON)
        .map_err(Of360EvalError::InvalidMetricDefinitions)?;
    validate_metric_definitions(&definitions)?;
    Ok(definitions)
}

pub fn of360_gold_subset() -> Of360Result<Of360GoldDataset> {
    let dataset =
        serde_json::from_str(OF360_GOLD_SUBSET_JSON).map_err(Of360EvalError::InvalidGoldDataset)?;
    validate_dataset(&dataset)?;
    Ok(dataset)
}

pub fn generate_of360_seeded_gold_subset(
    config: Of360SeededSubsetConfig,
) -> Of360Result<Of360GoldDataset> {
    let mut dataset = of360_gold_subset()?;
    dataset.seed = config.seed;
    dataset
        .cases
        .sort_by_key(|case| seeded_rank(config.seed, &case.case_id));
    dataset
        .cases
        .truncate(config.max_cases.min(dataset.cases.len()));
    dataset.revision = format!(
        "{}.seed-{:016x}.n{}",
        OF360_GOLD_DATASET_REVISION,
        config.seed,
        dataset.cases.len()
    );
    dataset
        .description
        .push_str(" Generated by deterministic subset selection from the versioned seed subset.");
    Ok(dataset)
}

pub fn evaluate_of360_extraction(
    dataset: &Of360GoldDataset,
    run: &Of360ExtractionRun,
) -> Of360Result<Of360EvalReport> {
    let metric_definitions = of360_metric_definitions()?;
    evaluate_with_metric_definitions(dataset, run, &metric_definitions)
}

pub fn of360_ar3_metric_tier(
    dataset: &Of360GoldDataset,
    run: &Of360ExtractionRun,
) -> Of360Result<Of360Ar3MetricTier> {
    let metric_definitions = of360_metric_definitions()?;
    let report = evaluate_with_metric_definitions(dataset, run, &metric_definitions)?;
    Ok(Of360Ar3MetricTier {
        interface_version: OF360_AR3_METRIC_TIER_INTERFACE_VERSION,
        metric_definitions,
        report,
    })
}

pub fn of360_builtin_ar3_metric_tier(run: &Of360ExtractionRun) -> Of360Result<Of360Ar3MetricTier> {
    let dataset = of360_gold_subset()?;
    of360_ar3_metric_tier(&dataset, run)
}

fn evaluate_with_metric_definitions(
    dataset: &Of360GoldDataset,
    run: &Of360ExtractionRun,
    metric_definitions: &Of360MetricDefinitionSet,
) -> Of360Result<Of360EvalReport> {
    validate_metric_definitions(metric_definitions)?;
    validate_dataset(dataset)?;
    validate_run_schema(run)?;
    if dataset.dataset_id != run.dataset_id || dataset.revision != run.dataset_revision {
        return Err(Of360EvalError::DatasetMismatch {
            expected_id: dataset.dataset_id.clone(),
            expected_revision: dataset.revision.clone(),
            actual_id: run.dataset_id.clone(),
            actual_revision: run.dataset_revision.clone(),
        });
    }

    let index = DatasetIndex::new(dataset)?;
    let mut outputs_by_case = HashMap::new();
    let mut aggregate = MetricAccumulator::default();
    let mut case_reports = Vec::with_capacity(dataset.cases.len());

    for output in &run.cases {
        if outputs_by_case
            .insert(output.case_id.as_str(), output)
            .is_some()
        {
            return Err(Of360EvalError::DuplicateRunCase {
                run_id: run.run_id.clone(),
                case_id: output.case_id.clone(),
            });
        }
        if index.case(&output.case_id).is_none() {
            return Err(Of360EvalError::UnknownCase {
                run_id: run.run_id.clone(),
                case_id: output.case_id.clone(),
            });
        }
    }

    for case in &dataset.cases {
        let empty_output;
        let output = if let Some(output) = outputs_by_case.get(case.case_id.as_str()) {
            *output
        } else {
            empty_output = Of360CaseExtractionOutput {
                case_id: case.case_id.clone(),
                extracted_claims: Vec::new(),
            };
            &empty_output
        };
        let case_report = evaluate_case(case, output)?;
        aggregate.merge(&MetricAccumulator::from_case_report(&case_report));
        case_reports.push(case_report);
    }

    Ok(Of360EvalReport {
        schema_version: 1,
        metric_set_id: metric_definitions.set_id.clone(),
        metric_definition_envelope: metric_definitions.derivation_envelope.clone(),
        dataset_id: dataset.dataset_id.clone(),
        dataset_revision: dataset.revision.clone(),
        run_id: run.run_id.clone(),
        system_id: run.system_id.clone(),
        metrics: aggregate.metrics(),
        cases: case_reports,
        warnings: corpus_warnings(dataset),
    })
}

fn evaluate_case(
    case: &Of360GoldCase,
    output: &Of360CaseExtractionOutput,
) -> Of360Result<Of360CaseEvalReport> {
    let mut seen_extractions = HashSet::new();
    let gold_by_id: HashMap<&str, &Of360GoldMemoryPoint> = case
        .gold_memory_points
        .iter()
        .map(|memory| (memory.memory_id.as_str(), memory))
        .collect();
    let mut best_scores: HashMap<&str, f64> = gold_by_id
        .keys()
        .copied()
        .map(|memory_id| (memory_id, 0.0))
        .collect();
    let redundant_extraction_ids = redundant_extraction_ids(&output.extracted_claims);
    let mut accumulator = MetricAccumulator {
        gold_points: case.gold_memory_points.len() as f64,
        weighted_gold_points: case
            .gold_memory_points
            .iter()
            .map(|memory| memory.weight)
            .sum(),
        extracted_claims: output.extracted_claims.len() as f64,
        redundant_claims: redundant_extraction_ids.len() as f64,
        ..MetricAccumulator::default()
    };
    let mut hallucinated_extraction_ids = Vec::new();
    let mut overreach_extraction_ids = Vec::new();

    for extracted in &output.extracted_claims {
        if !seen_extractions.insert(extracted.extraction_id.clone()) {
            return Err(Of360EvalError::DuplicateExtraction {
                case_id: output.case_id.clone(),
                extraction_id: extracted.extraction_id.clone(),
            });
        }

        let mut has_positive_match = false;
        let mut temporal_required = false;
        for matched in &extracted.matched_gold {
            let memory = gold_by_id.get(matched.memory_id.as_str()).ok_or_else(|| {
                Of360EvalError::UnknownGoldMemory {
                    case_id: output.case_id.clone(),
                    memory_id: matched.memory_id.clone(),
                }
            })?;
            let score = matched.score.halumem_value();
            if score > 0.0 {
                has_positive_match = true;
                temporal_required |= memory.temporal_required;
            }
            best_scores
                .entry(memory.memory_id.as_str())
                .and_modify(|best| *best = best.max(score));
        }

        if has_positive_match {
            accumulator.matched_extracted_claims += 1.0;
        } else {
            accumulator.hallucinated_claims += 1.0;
            hallucinated_extraction_ids.push(extracted.extraction_id.clone());
        }
        if extracted.overreach {
            accumulator.overreach_claims += 1.0;
            overreach_extraction_ids.push(extracted.extraction_id.clone());
        }
        if temporal_required {
            accumulator.temporal_claims += 1.0;
            if extracted.temporal_correct == Some(true) {
                accumulator.temporal_correct_claims += 1.0;
            }
        }
    }

    let mut omitted_gold_memory_ids = Vec::new();
    let mut partial_gold_memory_ids = Vec::new();
    for memory in &case.gold_memory_points {
        let score = best_scores
            .get(memory.memory_id.as_str())
            .copied()
            .unwrap_or(0.0);
        accumulator.halumem_score_sum += score;
        accumulator.weighted_halumem_score_sum += score * memory.weight;
        if score == 0.0 {
            omitted_gold_memory_ids.push(memory.memory_id.clone());
        } else if score < 1.0 {
            partial_gold_memory_ids.push(memory.memory_id.clone());
        }
    }

    Ok(Of360CaseEvalReport {
        case_id: output.case_id.clone(),
        metrics: accumulator.metrics(),
        omitted_gold_memory_ids,
        partial_gold_memory_ids,
        hallucinated_extraction_ids,
        overreach_extraction_ids,
        redundant_extraction_ids,
    })
}

fn validate_metric_definitions(metric_definitions: &Of360MetricDefinitionSet) -> Of360Result<()> {
    if metric_definitions.schema_version != OF360_SCHEMA_VERSION {
        return Err(Of360EvalError::UnsupportedMetricDefinitionSchemaVersion {
            actual: metric_definitions.schema_version,
        });
    }
    Ok(())
}

fn validate_dataset(dataset: &Of360GoldDataset) -> Of360Result<()> {
    if dataset.schema_version != OF360_SCHEMA_VERSION {
        return Err(Of360EvalError::UnsupportedGoldDatasetSchemaVersion {
            actual: dataset.schema_version,
        });
    }

    let mut seen_cases = HashSet::new();
    for case in &dataset.cases {
        if !seen_cases.insert(case.case_id.clone()) {
            return Err(Of360EvalError::DuplicateGoldCase {
                dataset_id: dataset.dataset_id.clone(),
                case_id: case.case_id.clone(),
            });
        }
        let mut turn_ids = HashSet::new();
        for turn in &case.turns {
            if !turn_ids.insert(turn.turn_id.as_str()) {
                return Err(Of360EvalError::DuplicateGoldTurn {
                    case_id: case.case_id.clone(),
                    turn_id: turn.turn_id.clone(),
                });
            }
        }

        let mut seen_memory_ids = HashSet::new();
        for memory in &case.gold_memory_points {
            if !seen_memory_ids.insert(memory.memory_id.clone()) {
                return Err(Of360EvalError::DuplicateGoldMemory {
                    case_id: case.case_id.clone(),
                    memory_id: memory.memory_id.clone(),
                });
            }
            if !(1..=5).contains(&memory.importance) {
                return Err(Of360EvalError::InvalidGoldMemory {
                    case_id: case.case_id.clone(),
                    memory_id: memory.memory_id.clone(),
                    reason: "importance must be in 1..=5",
                });
            }
            if !memory.weight.is_finite() || memory.weight <= 0.0 {
                return Err(Of360EvalError::InvalidGoldMemory {
                    case_id: case.case_id.clone(),
                    memory_id: memory.memory_id.clone(),
                    reason: "weight must be finite and positive",
                });
            }
            for turn_id in &memory.evidence_turn_ids {
                if !turn_ids.contains(turn_id.as_str()) {
                    return Err(Of360EvalError::UnknownEvidenceTurn {
                        case_id: case.case_id.clone(),
                        turn_id: turn_id.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_run_schema(run: &Of360ExtractionRun) -> Of360Result<()> {
    if run.schema_version != OF360_SCHEMA_VERSION {
        return Err(Of360EvalError::UnsupportedExtractionRunSchemaVersion {
            actual: run.schema_version,
        });
    }
    Ok(())
}

fn redundant_extraction_ids(extracted_claims: &[Of360ExtractedClaim]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut redundant = Vec::new();
    for extracted in extracted_claims {
        let key = extracted
            .dedup_key
            .clone()
            .unwrap_or_else(|| normalized_dedup_key(&extracted.text));
        if !seen.insert(key) {
            redundant.push(extracted.extraction_id.clone());
        }
    }
    redundant
}

fn normalized_dedup_key(text: &str) -> String {
    text.split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

fn corpus_warnings(dataset: &Of360GoldDataset) -> Vec<String> {
    if dataset.owner_corpus_missing {
        vec![format!(
            "full {}-point owner-authored OF-360 gold corpus is not present; report is over {} seed-subset case(s)",
            dataset.target_full_memory_points,
            dataset.cases.len()
        )]
    } else {
        Vec::new()
    }
}

fn seeded_rank(seed: u64, value: &str) -> u64 {
    let mut hash = seed ^ 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

struct DatasetIndex<'a> {
    cases: HashMap<&'a str, &'a Of360GoldCase>,
}

impl<'a> DatasetIndex<'a> {
    fn new(dataset: &'a Of360GoldDataset) -> Of360Result<Self> {
        validate_dataset(dataset)?;
        Ok(Self {
            cases: dataset
                .cases
                .iter()
                .map(|case| (case.case_id.as_str(), case))
                .collect(),
        })
    }

    fn case(&self, case_id: &str) -> Option<&'a Of360GoldCase> {
        self.cases.get(case_id).copied()
    }
}

#[derive(Debug, Clone, Default)]
struct MetricAccumulator {
    gold_points: f64,
    weighted_gold_points: f64,
    halumem_score_sum: f64,
    weighted_halumem_score_sum: f64,
    extracted_claims: f64,
    matched_extracted_claims: f64,
    hallucinated_claims: f64,
    overreach_claims: f64,
    temporal_claims: f64,
    temporal_correct_claims: f64,
    redundant_claims: f64,
}

impl MetricAccumulator {
    fn from_case_report(report: &Of360CaseEvalReport) -> Self {
        Self {
            gold_points: report.metrics.halumem_recall.denominator,
            weighted_gold_points: report.metrics.halumem_weighted_recall.denominator,
            halumem_score_sum: report.metrics.halumem_recall.numerator,
            weighted_halumem_score_sum: report.metrics.halumem_weighted_recall.numerator,
            extracted_claims: report.metrics.target_precision.denominator,
            matched_extracted_claims: report.metrics.target_precision.numerator,
            hallucinated_claims: report.metrics.hallucination_rate.numerator,
            overreach_claims: report.metrics.overreach_rate.numerator,
            temporal_claims: report.metrics.temporal_correctness.denominator,
            temporal_correct_claims: report.metrics.temporal_correctness.numerator,
            redundant_claims: report.metrics.redundancy_rate.numerator,
        }
    }

    fn merge(&mut self, other: &Self) {
        self.gold_points += other.gold_points;
        self.weighted_gold_points += other.weighted_gold_points;
        self.halumem_score_sum += other.halumem_score_sum;
        self.weighted_halumem_score_sum += other.weighted_halumem_score_sum;
        self.extracted_claims += other.extracted_claims;
        self.matched_extracted_claims += other.matched_extracted_claims;
        self.hallucinated_claims += other.hallucinated_claims;
        self.overreach_claims += other.overreach_claims;
        self.temporal_claims += other.temporal_claims;
        self.temporal_correct_claims += other.temporal_correct_claims;
        self.redundant_claims += other.redundant_claims;
    }

    fn metrics(&self) -> Of360ParsedMetrics {
        let recall = Of360RateMetric::new(self.halumem_score_sum, self.gold_points);
        let precision = Of360RateMetric::new(self.matched_extracted_claims, self.extracted_claims);
        Of360ParsedMetrics {
            halumem_recall: recall,
            halumem_weighted_recall: Of360RateMetric::new(
                self.weighted_halumem_score_sum,
                self.weighted_gold_points,
            ),
            target_precision: precision,
            halumem_f1: Of360RateMetric::f1(precision, recall),
            faithfulness_rate: Of360RateMetric::new(
                self.extracted_claims - self.hallucinated_claims,
                self.extracted_claims,
            ),
            hallucination_rate: Of360RateMetric::new(
                self.hallucinated_claims,
                self.extracted_claims,
            ),
            overreach_rate: Of360RateMetric::new(self.overreach_claims, self.extracted_claims),
            temporal_correctness: Of360RateMetric::new(
                self.temporal_correct_claims,
                self.temporal_claims,
            ),
            redundancy_rate: Of360RateMetric::new(self.redundant_claims, self.extracted_claims),
        }
    }
}

#[cfg(test)]
mod tests;
