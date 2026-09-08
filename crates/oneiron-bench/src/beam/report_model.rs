//! Report and contract output types.

use super::model::{ArmKind, BeamFixture, CompetitorCardConfig, FixtureCase, FixtureClass};
use super::ppr_vad::{PprVadCaseSample, PprVadSubset, PprVadSweepReport};
use super::util::default_fixture_cost_source;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ComparatorMetadata {
    pub(super) comparator_id: String,
    pub(super) version: String,
    pub(super) baseline_competitor_id: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TokenAccountingSource {
    TokenizerCount,
    ProviderUsage,
    FixtureDeclaredZero,
    NotApplicable,
    CharCountEstimate,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TokenAccountingDeclaration {
    pub(super) source: TokenAccountingSource,
    pub(super) notes: String,
}
impl Default for TokenAccountingDeclaration {
    fn default() -> Self {
        Self {
            source: TokenAccountingSource::NotApplicable,
            notes: String::new(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CostComponentInput {
    #[serde(default = "default_fixture_cost_source")]
    pub(super) token_source: TokenAccountingSource,
    #[serde(default)]
    pub(super) input_tokens: u64,
    #[serde(default)]
    pub(super) output_tokens: u64,
    #[serde(default)]
    pub(super) target_tokens: u64,
    #[serde(default)]
    pub(super) elapsed_us: u64,
    #[serde(default)]
    pub(super) cost_usd: f64,
}
impl Default for CostComponentInput {
    fn default() -> Self {
        Self {
            token_source: default_fixture_cost_source(),
            input_tokens: 0,
            output_tokens: 0,
            target_tokens: 0,
            elapsed_us: 0,
            cost_usd: 0.0,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReportFormat {
    Json,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NotReadyState {
    pub(super) component: String,
    pub(super) reason: String,
    pub(super) retryable: bool,
}
impl std::fmt::Display for NotReadyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} not ready: {}", self.component, self.reason)
    }
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BeamReport {
    pub(super) schema_version: u32,
    pub(super) run_id: String,
    pub(super) fixture_id: String,
    pub(super) fixture_description: String,
    pub(super) dataset: DatasetLoadReport,
    pub(super) scorer: ScorerReport,
    pub(super) report_format: String,
    pub(super) cases: Vec<CaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ppr_vad_sweep: Option<PprVadSweepReport>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DatasetLoadReport {
    pub(super) dataset_id: String,
    pub(super) source_kind: String,
    pub(super) records_loaded: usize,
    pub(super) text_fields_indexed: usize,
    pub(super) pending_vectors: usize,
}
pub(super) struct LoadedDataset {
    pub(super) ppr_vad_fixture: Option<BeamFixture>,
    pub(super) report: DatasetLoadReport,
    pub(super) fixture_id: String,
    pub(super) fixture_description: String,
    pub(super) cases: Vec<FixtureCase>,
    pub(super) contract_records: BTreeMap<String, RunContractRecord>,
    pub(super) source_id_by_entity_id: BTreeMap<String, String>,
    pub(super) query_vector_by_case_id: BTreeMap<String, Vec<f32>>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ContractRecordType {
    Run,
    ContextPack,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct ContractDataset {
    pub(super) id: String,
    pub(super) revision: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct ContractArm {
    pub(super) id: String,
    pub(super) kind: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct ContractBudget {
    pub(super) currency: String,
    pub(super) limit: usize,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct ContractGold {
    pub(super) answers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) labels: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Deserialize)]
pub(super) struct RunContractRecord {
    pub(super) contract_version: String,
    pub(super) record_type: ContractRecordType,
    pub(super) run_id: String,
    pub(super) question_id: String,
    pub(super) dataset: ContractDataset,
    pub(super) arm: ContractArm,
    pub(super) budget: ContractBudget,
    pub(super) question: String,
    #[serde(default, alias = "queryEmbedding")]
    pub(super) query_embedding: Option<ContractEmbeddingState>,
    pub(super) corpus: Vec<ContractCorpusRecord>,
    #[serde(default)]
    pub(super) gold: Option<ContractGold>,
}
#[derive(Debug, Clone, Deserialize)]
pub(super) struct ContractCorpusRecord {
    pub(super) id: String,
    pub(super) text: String,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) embedding: Option<ContractEmbeddingState>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(super) enum ContractEmbeddingState {
    Pending {
        #[serde(rename = "status")]
        _status: ContractEmbeddingStatus,
    },
    Ready(ContractVector),
}
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ContractEmbeddingStatus {
    Pending,
}
#[derive(Debug, Clone, Deserialize)]
pub(super) struct ContractVector {
    pub(super) encoding: String,
    pub(super) dimensions: usize,
    pub(super) data: String,
}
#[derive(Debug, Serialize)]
pub(super) struct ContextPackContractRecord {
    pub(super) contract_version: &'static str,
    pub(super) record_type: ContractRecordType,
    pub(super) run_id: String,
    pub(super) question_id: String,
    pub(super) dataset: ContractDataset,
    pub(super) arm: ContractArm,
    pub(super) budget: ContractBudget,
    pub(super) question: String,
    pub(super) pack: ContractPack,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) gold: Option<ContractGold>,
}
#[derive(Debug, Serialize)]
pub(super) struct ContractPack {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) token_count: Option<u64>,
    pub(super) corpus_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) config: Option<ContractPackConfig>,
    pub(super) contexts: Vec<ContractPackContext>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContractPackConfig {
    pub(super) kind: &'static str,
    pub(super) version: &'static str,
    pub(super) top_k: usize,
    pub(super) chunking: &'static str,
    pub(super) fusion: &'static str,
    pub(super) signals: Vec<&'static str>,
    pub(super) embedder_id: &'static str,
    pub(super) vector_dimensions: usize,
    pub(super) token_budget_source: &'static str,
    pub(super) structure: &'static str,
}
#[derive(Debug, Serialize)]
pub(super) struct ContractPackContext {
    pub(super) id: String,
    pub(super) text: String,
    pub(super) score: f32,
    pub(super) source_turn_ids: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CaseReport {
    pub(super) case_id: String,
    pub(super) query: String,
    pub(super) limit: usize,
    pub(super) token_budget: usize,
    pub(super) expected_min_results: usize,
    pub(super) fixture_class: FixtureClass,
    pub(super) offline_amortized_cost: CostComponentReport,
    pub(super) arms: Vec<ArmReport>,
    pub(super) competitors: Vec<CompetitorReport>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ArmReport {
    pub(super) arm: ArmKind,
    pub(super) outcome: ArmOutcome,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(super) enum ArmOutcome {
    Completed {
        context_pack: Box<ContextPackReport>,
    },
    NotReady {
        not_ready: NotReadyState,
    },
    RetrievalSweep {
        subset: PprVadSubset,
        samples: Vec<PprVadCaseSample>,
    },
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContextPackReport {
    pub(super) token_budget: usize,
    pub(super) limit: usize,
    pub(super) serialized_format: String,
    pub(super) serialized_bytes: usize,
    pub(super) serialized_tokens: u64,
    pub(super) tokenizer_id: String,
    pub(super) query_cost: CostComponentReport,
    pub(super) result_count: usize,
    pub(super) neighbor_count: usize,
    pub(super) results: Vec<ContextEntityReport>,
    pub(super) neighbors: Vec<ContextEntityReport>,
    pub(super) stats: PackStatsReport,
    pub(super) empty: Option<EmptyContextReport>,
    #[serde(skip)]
    pub(super) temporal_result_ids: BTreeSet<String>,
    #[serde(skip)]
    pub(super) budgeted_text_by_entity_id: BTreeMap<String, String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScorerReport {
    pub(super) scorer_id: String,
    pub(super) version: String,
    pub(super) comparator_version: String,
    pub(super) abilities: Vec<AbilityKind>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AbilityKind {
    RetrievalCoverage,
    BudgetDiscipline,
    Readiness,
    AbstentionGate,
    NoRegressionGate,
}
impl AbilityKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::RetrievalCoverage => "retrieval_coverage",
            Self::BudgetDiscipline => "budget_discipline",
            Self::Readiness => "readiness",
            Self::AbstentionGate => "abstention_gate",
            Self::NoRegressionGate => "no_regression_gate",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CompetitorReport {
    pub(super) competitor_id: String,
    pub(super) arm: ArmKind,
    pub(super) card: CompetitorCardConfig,
    pub(super) costs: CostBreakdownReport,
    pub(super) scoring: ScoreReport,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CostBreakdownReport {
    pub(super) query: CostComponentReport,
    pub(super) offline: CostComponentReport,
    pub(super) judge: CostComponentReport,
    pub(super) total_cost_usd: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CostComponentReport {
    pub(super) token_source: TokenAccountingSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) tokenizer_id: Option<String>,
    pub(super) input_tokens: u64,
    pub(super) output_tokens: u64,
    pub(super) target_tokens: u64,
    pub(super) elapsed_us: u64,
    pub(super) cost_usd: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScoreReport {
    pub(super) scorer_version: String,
    pub(super) overall_score: Option<f32>,
    pub(super) abilities: Vec<AbilityScoreReport>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AbilityScoreReport {
    pub(super) ability: AbilityKind,
    pub(super) score: Option<f32>,
    pub(super) passed: Option<bool>,
    pub(super) detail: String,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContextEntityReport {
    pub(super) id: String,
    pub(super) short_id: String,
    pub(super) entity_type: u8,
    pub(super) score: f32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PackStatsReport {
    pub(super) candidates_considered: usize,
    pub(super) signals_used: Vec<String>,
    pub(super) query_time_us: u64,
    pub(super) entities_hydrated: usize,
    pub(super) neighbors_hydrated: usize,
    pub(super) cosine_ghosts_dampened: usize,
    pub(super) claims_suppressed: usize,
    pub(super) tokenizer_id: String,
    pub(super) total_tokens: usize,
    pub(super) section_tokens: Vec<PackSectionTokenReport>,
    pub(super) item_tokens: Vec<PackItemTokenReport>,
    pub(super) items_truncated: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) items_truncated_reasons: Vec<String>,
    pub(super) items_dropped: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) items_dropped_reasons: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PackSectionTokenReport {
    pub(super) section: String,
    pub(super) tokens: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PackItemTokenReport {
    pub(super) section: String,
    pub(super) id: String,
    pub(super) entity_type: u8,
    pub(super) tokens: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EmptyContextReport {
    pub(super) reason: String,
    pub(super) total_in_scope: usize,
    pub(super) hint: String,
}
