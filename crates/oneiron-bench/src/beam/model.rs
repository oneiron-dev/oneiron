//! Fixture, manifest, and arm input types.

use super::judge::{AnswerPromptPin, single_judge_vote};
use super::ppr_vad::{PprVadFixtureEdge, PprVadQuery};
use super::report_model::{
    ComparatorMetadata, ContractEmbeddingState, CostComponentInput, ReportFormat,
    TokenAccountingDeclaration,
};
use super::util::default_jsonl_retrieval_limit;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BeamFixture {
    pub(super) schema_version: u32,
    pub(super) fixture_id: String,
    pub(super) description: String,
    pub(super) records: Vec<FixtureRecord>,
    pub(super) cases: Vec<FixtureCase>,
    #[serde(default)]
    pub(super) ppr_vad_edges: Vec<PprVadFixtureEdge>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct FixtureRecord {
    pub(super) id: String,
    pub(super) entity_type: u8,
    pub(super) occurred: FixtureTimeRange,
    pub(super) learned_at: u64,
    pub(super) fields: serde_json::Value,
    #[serde(default)]
    pub(super) text: Vec<TextField>,
    #[serde(default)]
    pub(super) embedding: Option<ContractEmbeddingState>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct FixtureTimeRange {
    pub(super) start: u64,
    pub(super) end: u64,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TextField {
    pub(super) field: String,
    pub(super) value: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FixtureCase {
    pub(super) case_id: String,
    pub(super) query: String,
    pub(super) limit: usize,
    pub(super) token_budget: usize,
    pub(super) expected_min_results: usize,
    #[serde(default)]
    pub(super) pending_vector_count: usize,
    #[serde(default)]
    pub(super) query_embedding: Option<ContractEmbeddingState>,
    #[serde(default)]
    pub(super) fixture_class: FixtureClass,
    #[serde(default)]
    pub(super) temporal_search: Option<FixtureTimeRange>,
    #[serde(default)]
    pub(super) temporal_evidence_ids: Vec<String>,
    #[serde(default)]
    pub(super) opposing_evidence: Option<OpposingEvidence>,
    #[serde(default)]
    pub(super) offline_amortized_cost: CostComponentInput,
    #[serde(default)]
    pub(super) ppr_vad_query: Option<PprVadQuery>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct OpposingEvidence {
    pub(super) field: String,
    pub(super) record_ids: Vec<String>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FixtureClass {
    #[default]
    EvidenceSupported,
    EmptyMemory,
    LowConfidence,
    AdversarialContradiction,
    TemporalStaleness,
}
impl FixtureClass {
    pub(super) const fn expects_abstention(self) -> bool {
        !matches!(self, Self::EvidenceSupported)
    }

    pub(super) const fn gate_label(self) -> &'static str {
        match self {
            Self::EvidenceSupported => "score_publication",
            Self::EmptyMemory => "empty_memory_abstention",
            Self::LowConfidence => "low_confidence_abstention",
            Self::AdversarialContradiction => "adversarial_contradiction_abstention",
            Self::TemporalStaleness => "temporal_staleness_abstention",
        }
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RunManifest {
    pub(super) schema_version: u32,
    pub(super) run_id: String,
    pub(super) dataset: DatasetSource,
    pub(super) case_ids: Vec<String>,
    pub(super) arms: Vec<ArmKind>,
    pub(super) competitors: Vec<CompetitorConfig>,
    pub(super) report: ReportConfig,
    #[serde(default)]
    pub(super) outputs: Option<RunOutputs>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SchemaHeader {
    pub(super) schema_version: u32,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(super) enum DatasetSource {
    Fixture {
        fixture_id: String,
        /// Optional only for callers supplying an in-memory fixture. The CLI
        /// loads this JSON path relative to the run manifest.
        #[serde(default)]
        path: Option<PathBuf>,
    },
    Jsonl {
        path: PathBuf,
        #[serde(default)]
        arm_id: Option<String>,
        #[serde(default = "default_jsonl_retrieval_limit")]
        limit: usize,
        #[serde(default)]
        expected_min_results: usize,
    },
    Miracl {
        dataset: String,
    },
    MrTydi {
        dataset: String,
    },
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RunOutputs {
    pub(super) packs_jsonl: PathBuf,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArmKind {
    Deterministic,
    VanillaRag,
    PprVadSweep,
    BackboneSolo,
    Agentic,
    Chat,
}
impl ArmKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::VanillaRag => "vanilla_rag",
            Self::PprVadSweep => "ppr_vad_sweep",
            Self::BackboneSolo => "backbone_solo",
            Self::Agentic => "agentic",
            Self::Chat => "chat",
        }
    }

    pub(super) const fn is_completed(self) -> bool {
        matches!(self, Self::Deterministic | Self::VanillaRag)
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ReportConfig {
    pub(super) format: ReportFormat,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CompetitorConfig {
    pub(super) competitor_id: String,
    pub(super) arm: ArmKind,
    pub(super) card: Option<CompetitorCardConfig>,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CompetitorCardConfig {
    pub(super) display_name: String,
    pub(super) public_parity_status: PublicParityStatus,
    pub(super) judge: JudgeMetadata,
    pub(super) comparator: ComparatorMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) token_accounting: Option<TokenAccountingDeclaration>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PublicParityStatus {
    PublicParity,
    FixtureOnly,
    NotPublicComparable,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JudgeMetadata {
    pub(super) judge_id: String,
    pub(super) version: String,
    pub(super) notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) answer_prompt: Option<AnswerPromptPin>,
    #[serde(default = "single_judge_vote")]
    pub(super) vote_count: u8,
}
