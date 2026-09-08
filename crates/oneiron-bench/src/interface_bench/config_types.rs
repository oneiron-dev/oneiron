//! Campaign, task, and report DTOs plus RunSettings.

use super::cli_and_pinned_config::{PinnedAttestation, PinnedRun};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
pub(super) const CAMPAIGN_ID: &str = "interface-bench-1";

pub(super) const KIND: &str = "comparative-bench";

pub(super) const SCHEMA_VERSION: u32 = 1;

pub(super) const FIXTURE_ID: &str = "interface-bench-1-seeded-vault";

pub(super) const DETERMINISTIC_SEED: u64 = 0x15_71_1F_AC_E5;

pub(super) const CLAIM_COUNT: usize = 5_000;

pub(super) const PERSON_COUNT: usize = 50;

pub(super) const TOPIC_COUNT: usize = 100;

pub(super) const FULL_TASK_COUNT: usize = 80;

pub(super) const SMOKE_TASK_COUNT: usize = 8;

pub(super) const OWNER_SPOTCHECK_COUNT: usize = 8;

pub(super) const FULL_REP_COUNT: u32 = 2;

pub(super) const MAX_FULL_REPS: u32 = 8;

pub(super) const TOOL_CALL_CAP: u32 = 25;

pub(super) const WALL_CLOCK_CAP_S: u32 = 600;

pub(super) const PER_TASK_TOKEN_CEILING: u32 = 10_000;

pub(super) const SMOKE_TOKEN_CEILING: u32 = 250_000;

pub(super) const FULL_TOKEN_CEILING: u32 = 5_000_000;

pub(super) const MODEL: &str = "z-ai/glm-5.2";

pub(super) const DEFAULT_PROVIDER: &str = "wandb";

pub(super) const DEFAULT_OUT_DIR: &str = "target/interface-bench/interface-bench-1";

pub(super) const OPENROUTER_CHAT_COMPLETIONS: &str =
    "https://openrouter.ai/api/v1/chat/completions";

pub(super) const REQUEST_TEMPERATURE: f64 = 0.2;

pub(super) const SCORER_VERSION: &str = "interface-bench-scorer-v2";

pub(super) const BROWSE_JUDGE_PROMPT_VERSION: &str = "interface-bench-blind-browse-judge-v2";

pub(super) const STANCES: [&str; 8] = [
    "prefers indexed search before synthesis",
    "trusts filesystem browsing for auditability",
    "wants explicit citations before acting",
    "keeps provenance fields visible",
    "asks for a second relation hop",
    "optimizes for low token burn",
    "checks source recency first",
    "uses hybrid query paths for broad lookup",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ArmId {
    #[serde(rename = "arm_sdk")]
    Sdk,
    #[serde(rename = "arm_fs")]
    Fs,
    #[serde(rename = "arm_hybrid")]
    Hybrid,
}

impl ArmId {
    pub(super) const ALL: [Self; 3] = [Self::Sdk, Self::Fs, Self::Hybrid];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Sdk => "arm_sdk",
            Self::Fs => "arm_fs",
            Self::Hybrid => "arm_hybrid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) enum TaskClass {
    #[serde(rename = "retrieval-QA")]
    RetrievalQa,
    #[serde(rename = "multi-hop")]
    MultiHop,
    #[serde(rename = "provenance")]
    Provenance,
    #[serde(rename = "browse-then-answer")]
    BrowseThenAnswer,
}

impl TaskClass {
    pub(super) const ALL: [Self; 4] = [
        Self::RetrievalQa,
        Self::MultiHop,
        Self::Provenance,
        Self::BrowseThenAnswer,
    ];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::RetrievalQa => "retrieval-QA",
            Self::MultiHop => "multi-hop",
            Self::Provenance => "provenance",
            Self::BrowseThenAnswer => "browse-then-answer",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct CampaignConfig {
    pub(super) campaign: String,
    pub(super) kind: String,
    pub(super) nodes: Vec<ArmId>,
    pub(super) search_axes: String,
    pub(super) metric_set: MetricSet,
    pub(super) eval_corpus: EvalCorpusConfig,
    pub(super) sacred_set: Option<String>,
    pub(super) budget_lease: BudgetLeaseConfig,
    pub(super) proposer: Option<String>,
    pub(super) runner: RunnerConfig,
    pub(super) decide: DecideConfig,
    pub(super) model_binding: ModelBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct MetricSet {
    pub(super) parsed: Vec<String>,
    pub(super) taste: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct EvalCorpusConfig {
    pub(super) fixture: String,
    pub(super) seed: u64,
    pub(super) generated_claims: usize,
    pub(super) full_tasks: usize,
    pub(super) smoke_tasks: usize,
    pub(super) holdout: HoldoutPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct HoldoutPolicy {
    pub(super) fraction_per_class: f64,
    pub(super) freeze_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct BudgetLeaseConfig {
    pub(super) discipline: String,
    pub(super) per_task_token_ceiling: u32,
    pub(super) smoke_token_ceiling: u32,
    pub(super) full_token_ceiling: u32,
    pub(super) tool_call_cap: u32,
    pub(super) wall_clock_cap_s: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct RunnerConfig {
    pub(super) kind: String,
    pub(super) call_purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct DecideConfig {
    pub(super) mode: String,
    pub(super) verdict_band: String,
    pub(super) arm_promotion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct ModelBinding {
    pub(super) model: String,
    pub(super) route: ProviderRoute,
    pub(super) browse_judge_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct ProviderRoute {
    pub(super) provider: ProviderLock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct ProviderLock {
    pub(super) order: Vec<String>,
    pub(super) allow_fallbacks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FixtureVault {
    pub(super) schema_version: u32,
    pub(super) fixture_id: String,
    pub(super) campaign: String,
    pub(super) seed: u64,
    pub(super) claim_count: usize,
    pub(super) claims: Vec<FixtureClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FixtureClaim {
    pub(super) claim_id: String,
    pub(super) topic_id: String,
    pub(super) topic: String,
    pub(super) person_id: String,
    pub(super) person: String,
    pub(super) owned_object_id: String,
    pub(super) owned_object: String,
    pub(super) organization_id: String,
    pub(super) organization: String,
    pub(super) stance: String,
    pub(super) source_ref: String,
    pub(super) learned_at_epoch_s: u64,
    pub(super) learned_at_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) superseded_by: Option<String>,
    pub(super) text: String,
    pub(super) relations: BTreeMap<String, Vec<String>>,
    pub(super) provenance: ClaimProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ClaimProvenance {
    pub(super) source_ref: String,
    pub(super) learned_at_epoch_s: u64,
    pub(super) changed_after: String,
    pub(super) source_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BenchTask {
    pub(super) task_id: String,
    pub(super) class: TaskClass,
    pub(super) prompt: String,
    pub(super) gold: GoldLabel,
    pub(super) scorer: ScorerConfig,
    pub(super) supporting_claim_ids: Vec<String>,
    pub(super) holdout: bool,
    pub(super) smoke: bool,
    pub(super) generation: GenerationProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(super) enum GoldLabel {
    #[serde(rename = "retrieval-QA")]
    RetrievalQa {
        #[serde(rename = "relevantClaimIds")]
        relevant_claim_ids: Vec<String>,
    },
    #[serde(rename = "multi-hop")]
    MultiHop {
        #[serde(rename = "exactAnswer")]
        exact_answer: String,
        #[serde(rename = "supportingIds")]
        supporting_ids: Vec<String>,
    },
    #[serde(rename = "provenance")]
    Provenance {
        field: String,
        value: String,
        #[serde(rename = "supportingIds")]
        supporting_ids: Vec<String>,
    },
    #[serde(rename = "browse-then-answer")]
    BrowseThenAnswer {
        topic: String,
        #[serde(rename = "requiredClaimIds")]
        required_claim_ids: Vec<String>,
        rubric: BrowseRubric,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BrowseRubric {
    pub(super) coverage: String,
    pub(super) faithfulness: String,
    pub(super) citation_validity: String,
    pub(super) scale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScorerConfig {
    pub(super) scorer: String,
    pub(super) blind_judge: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GenerationProof {
    pub(super) recipe: String,
    pub(super) selected_subgraph: Vec<String>,
    pub(super) verified_by_construction: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct HoldoutFreeze {
    pub(super) campaign: String,
    pub(super) frozen_on: String,
    pub(super) policy: HoldoutPolicy,
    pub(super) per_class: BTreeMap<String, HoldoutClassFreeze>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct HoldoutClassFreeze {
    pub(super) total: usize,
    pub(super) holdout: usize,
    pub(super) task_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TaskgenReport {
    pub(super) campaign: String,
    pub(super) fixture_id: String,
    pub(super) generated_claims: usize,
    pub(super) full_tasks: usize,
    pub(super) smoke_tasks: usize,
    pub(super) holdout_by_class: BTreeMap<String, usize>,
    pub(super) smoke_task_ids: Vec<String>,
    pub(super) owner_spotcheck_sample_ids: Vec<String>,
    pub(super) output_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub(super) struct TaskBundle {
    pub(super) config: CampaignConfig,
    pub(super) fixture: FixtureVault,
    pub(super) full_tasks: Vec<BenchTask>,
    pub(super) smoke_tasks: Vec<BenchTask>,
    pub(super) holdout: HoldoutFreeze,
    pub(super) spotcheck: Vec<BenchTask>,
}

#[derive(Debug, Clone)]
pub(super) struct ArmContext {
    pub(super) tool_calls: u32,
    pub(super) transcript: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SmokeReport {
    pub(super) campaign: String,
    pub(super) model: String,
    pub(super) provider: ProviderLock,
    pub(super) run_id: String,
    pub(super) task_count: usize,
    pub(super) runs: Vec<SmokeRunRow>,
    pub(super) aggregates: Vec<ArmAggregate>,
    pub(super) full_run_token_burn_extrapolation: TokenBurnExtrapolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FullRunReport {
    pub(super) campaign: String,
    pub(super) model: String,
    pub(super) provider: ProviderLock,
    pub(super) run_id: String,
    pub(super) task_count: usize,
    pub(super) reps_per_task_arm: u32,
    pub(super) expected_runs: usize,
    pub(super) completed_runs: usize,
    pub(super) scorer_version: String,
    pub(super) browse_judge_prompt_version: String,
    pub(super) runs: Vec<SmokeRunRow>,
    pub(super) aggregates: Vec<ArmAggregate>,
    pub(super) class_arm_table: Vec<ClassArmSummary>,
    pub(super) pareto_frontier: Vec<ParetoPoint>,
    pub(super) arm_verdict_claims: Vec<ArmVerdictClaim>,
    pub(super) falsification_verdict: FalsificationVerdict,
    pub(super) budget: BudgetSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MemoProbeReport {
    pub(super) campaign: String,
    pub(super) model: String,
    pub(super) provider: ProviderLock,
    pub(super) task_id: String,
    pub(super) arm: ArmId,
    pub(super) reps: Vec<SmokeRunRow>,
    pub(super) memo_keys_distinct: bool,
    pub(super) request_hashes_distinct: bool,
    pub(super) generation_ids_distinct: bool,
    pub(super) passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SmokeRunRow {
    pub(super) task_id: String,
    pub(super) class: TaskClass,
    pub(super) arm: ArmId,
    pub(super) rep_index: u32,
    pub(super) memo_key: String,
    pub(super) request_hash: String,
    pub(super) request_nonce: String,
    /// Pin attestation (ONE-1344): present exactly when the run that wrote this
    /// row transmitted under `--pinned-config`, absent on unpinned rows — which
    /// keeps unpinned row JSON byte-identical to pre-pin campaigns. A pinned run
    /// refuses to reuse a row whose attestation is not its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pinned: Option<PinnedAttestation>,
    pub(super) generation_id: Option<String>,
    pub(super) judge_generation_id: Option<String>,
    pub(super) accuracy: f64,
    pub(super) tokens_total: u32,
    pub(super) tool_calls: u32,
    pub(super) wall_clock_s: f64,
    pub(super) answer: String,
    pub(super) score_detail: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ArmAggregate {
    pub(super) arm: ArmId,
    pub(super) runs: usize,
    pub(super) mean_accuracy: f64,
    pub(super) tokens_total: u32,
    pub(super) mean_tool_calls: f64,
    pub(super) mean_wall_clock_s: f64,
    pub(super) accuracy_per_class: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ClassArmSummary {
    pub(super) class: String,
    pub(super) arm: ArmId,
    pub(super) runs: usize,
    pub(super) reps: u32,
    pub(super) accuracy_mean: f64,
    pub(super) accuracy_range: f64,
    pub(super) tokens_mean: f64,
    pub(super) tokens_range: u32,
    pub(super) tool_calls_mean: f64,
    pub(super) wall_clock_mean_s: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ParetoPoint {
    pub(super) arm: ArmId,
    pub(super) mean_accuracy: f64,
    pub(super) tokens_total: u32,
    pub(super) dominated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ArmVerdictClaim {
    pub(super) band: String,
    pub(super) arm: ArmId,
    pub(super) claim_id: String,
    pub(super) claim: String,
    pub(super) mean_accuracy: f64,
    pub(super) tokens_total: u32,
    pub(super) pareto_dominated: bool,
    pub(super) evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FalsificationVerdict {
    pub(super) band: String,
    pub(super) class: String,
    pub(super) arm_fs_accuracy: f64,
    pub(super) arm_sdk_accuracy: f64,
    pub(super) arm_fs_tokens: u32,
    pub(super) arm_sdk_tokens: u32,
    pub(super) token_ratio: f64,
    pub(super) matches_accuracy: bool,
    pub(super) within_token_bound: bool,
    pub(super) falsifies_sdk_necessity_premise: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BudgetSummary {
    pub(super) per_task_token_ceiling: u32,
    pub(super) run_token_ceiling: u32,
    pub(super) tokens_total: u32,
    pub(super) max_row_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenBurnExtrapolation {
    pub(super) smoke_tokens: u32,
    pub(super) full_run_equivalent_runs: usize,
    pub(super) observed_runs: usize,
    pub(super) extrapolated_full_tokens: u32,
}

#[derive(Debug, Clone)]
pub(super) struct ChatResponse {
    pub(super) content: String,
    pub(super) tokens_total: u32,
    pub(super) generation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct RunSettings {
    pub(super) model: String,
    pub(super) provider: String,
    pub(super) full_reps: u32,
    /// Opt-in pinned-model admission policy (ONE-1344), populated only by an
    /// explicit `--pinned-config`. None means the run is unpinned, exactly as
    /// before the flag existed. When present it carries the resolved pinned
    /// revision for every wire id this run transmits: each request is checked
    /// against it before transmit, and the resolved pin is bound into the
    /// request hash, the memo key, and the stored row.
    pub(super) pinned: Option<PinnedRun>,
}

impl Default for RunSettings {
    fn default() -> Self {
        Self {
            model: MODEL.to_owned(),
            provider: DEFAULT_PROVIDER.to_owned(),
            full_reps: FULL_REP_COUNT,
            pinned: None,
        }
    }
}

impl RunSettings {
    pub(super) fn provider_lock(&self) -> ProviderLock {
        ProviderLock {
            order: vec![self.provider.clone()],
            allow_fallbacks: false,
        }
    }

    pub(super) fn full_run_count(&self) -> usize {
        FULL_TASK_COUNT * ArmId::ALL.len() * self.full_reps as usize
    }

    pub(super) fn full_token_ceiling(&self) -> u32 {
        let scaled =
            u64::from(FULL_TOKEN_CEILING) * u64::from(self.full_reps) / u64::from(FULL_REP_COUNT);
        u32::try_from(scaled).unwrap_or(u32::MAX)
    }
}
