//! Campaign #5 interface bench task generation and smoke harness.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const CAMPAIGN_ID: &str = "interface-bench-1";
const KIND: &str = "comparative-bench";
const SCHEMA_VERSION: u32 = 1;
const FIXTURE_ID: &str = "interface-bench-1-seeded-vault";
const DETERMINISTIC_SEED: u64 = 0x15_71_1F_AC_E5;
const CLAIM_COUNT: usize = 5_000;
const PERSON_COUNT: usize = 50;
const TOPIC_COUNT: usize = 100;
const FULL_TASK_COUNT: usize = 80;
const SMOKE_TASK_COUNT: usize = 8;
const OWNER_SPOTCHECK_COUNT: usize = 8;
const FULL_REP_COUNT: u32 = 2;
const TOOL_CALL_CAP: u32 = 25;
const WALL_CLOCK_CAP_S: u32 = 600;
const PER_TASK_TOKEN_CEILING: u32 = 10_000;
const SMOKE_TOKEN_CEILING: u32 = 250_000;
const FULL_TOKEN_CEILING: u32 = 5_000_000;
const MODEL: &str = "z-ai/glm-5.2";
const DEFAULT_PROVIDER: &str = "wandb";
const DEFAULT_OUT_DIR: &str = "target/interface-bench/interface-bench-1";
const OPENROUTER_CHAT_COMPLETIONS: &str = "https://openrouter.ai/api/v1/chat/completions";
const REQUEST_TEMPERATURE: f64 = 0.2;
const SCORER_VERSION: &str = "interface-bench-scorer-v2";
const BROWSE_JUDGE_PROMPT_VERSION: &str = "interface-bench-blind-browse-judge-v2";

const STANCES: [&str; 8] = [
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
enum ArmId {
    #[serde(rename = "arm_sdk")]
    Sdk,
    #[serde(rename = "arm_fs")]
    Fs,
    #[serde(rename = "arm_hybrid")]
    Hybrid,
}

impl ArmId {
    const ALL: [Self; 3] = [Self::Sdk, Self::Fs, Self::Hybrid];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Sdk => "arm_sdk",
            Self::Fs => "arm_fs",
            Self::Hybrid => "arm_hybrid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum TaskClass {
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
    const ALL: [Self; 4] = [
        Self::RetrievalQa,
        Self::MultiHop,
        Self::Provenance,
        Self::BrowseThenAnswer,
    ];

    const fn as_str(self) -> &'static str {
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
struct CampaignConfig {
    campaign: String,
    kind: String,
    nodes: Vec<ArmId>,
    search_axes: String,
    metric_set: MetricSet,
    eval_corpus: EvalCorpusConfig,
    sacred_set: Option<String>,
    budget_lease: BudgetLeaseConfig,
    proposer: Option<String>,
    runner: RunnerConfig,
    decide: DecideConfig,
    model_binding: ModelBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct MetricSet {
    parsed: Vec<String>,
    taste: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct EvalCorpusConfig {
    fixture: String,
    seed: u64,
    generated_claims: usize,
    full_tasks: usize,
    smoke_tasks: usize,
    holdout: HoldoutPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct HoldoutPolicy {
    fraction_per_class: f64,
    freeze_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct BudgetLeaseConfig {
    discipline: String,
    per_task_token_ceiling: u32,
    smoke_token_ceiling: u32,
    full_token_ceiling: u32,
    tool_call_cap: u32,
    wall_clock_cap_s: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct RunnerConfig {
    kind: String,
    call_purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct DecideConfig {
    mode: String,
    verdict_band: String,
    arm_promotion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct ModelBinding {
    model: String,
    route: ProviderRoute,
    browse_judge_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct ProviderRoute {
    provider: ProviderLock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct ProviderLock {
    order: Vec<String>,
    allow_fallbacks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureVault {
    schema_version: u32,
    fixture_id: String,
    campaign: String,
    seed: u64,
    claim_count: usize,
    claims: Vec<FixtureClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureClaim {
    claim_id: String,
    topic_id: String,
    topic: String,
    person_id: String,
    person: String,
    owned_object_id: String,
    owned_object: String,
    organization_id: String,
    organization: String,
    stance: String,
    source_ref: String,
    learned_at_epoch_s: u64,
    learned_at_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    superseded_by: Option<String>,
    text: String,
    relations: BTreeMap<String, Vec<String>>,
    provenance: ClaimProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimProvenance {
    source_ref: String,
    learned_at_epoch_s: u64,
    changed_after: String,
    source_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BenchTask {
    task_id: String,
    class: TaskClass,
    prompt: String,
    gold: GoldLabel,
    scorer: ScorerConfig,
    supporting_claim_ids: Vec<String>,
    holdout: bool,
    smoke: bool,
    generation: GenerationProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum GoldLabel {
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
struct BrowseRubric {
    coverage: String,
    faithfulness: String,
    citation_validity: String,
    scale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScorerConfig {
    scorer: String,
    blind_judge: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerationProof {
    recipe: String,
    selected_subgraph: Vec<String>,
    verified_by_construction: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HoldoutFreeze {
    campaign: String,
    frozen_on: String,
    policy: HoldoutPolicy,
    per_class: BTreeMap<String, HoldoutClassFreeze>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HoldoutClassFreeze {
    total: usize,
    holdout: usize,
    task_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskgenReport {
    campaign: String,
    fixture_id: String,
    generated_claims: usize,
    full_tasks: usize,
    smoke_tasks: usize,
    holdout_by_class: BTreeMap<String, usize>,
    smoke_task_ids: Vec<String>,
    owner_spotcheck_sample_ids: Vec<String>,
    output_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct TaskBundle {
    config: CampaignConfig,
    fixture: FixtureVault,
    full_tasks: Vec<BenchTask>,
    smoke_tasks: Vec<BenchTask>,
    holdout: HoldoutFreeze,
    spotcheck: Vec<BenchTask>,
}

#[derive(Debug, Clone)]
struct ArmContext {
    tool_calls: u32,
    transcript: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmokeReport {
    campaign: String,
    model: String,
    provider: ProviderLock,
    run_id: String,
    task_count: usize,
    runs: Vec<SmokeRunRow>,
    aggregates: Vec<ArmAggregate>,
    full_run_token_burn_extrapolation: TokenBurnExtrapolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullRunReport {
    campaign: String,
    model: String,
    provider: ProviderLock,
    run_id: String,
    task_count: usize,
    reps_per_task_arm: u32,
    expected_runs: usize,
    completed_runs: usize,
    scorer_version: String,
    browse_judge_prompt_version: String,
    runs: Vec<SmokeRunRow>,
    aggregates: Vec<ArmAggregate>,
    class_arm_table: Vec<ClassArmSummary>,
    pareto_frontier: Vec<ParetoPoint>,
    arm_verdict_claims: Vec<ArmVerdictClaim>,
    falsification_verdict: FalsificationVerdict,
    budget: BudgetSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemoProbeReport {
    campaign: String,
    model: String,
    provider: ProviderLock,
    task_id: String,
    arm: ArmId,
    reps: Vec<SmokeRunRow>,
    memo_keys_distinct: bool,
    request_hashes_distinct: bool,
    generation_ids_distinct: bool,
    passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmokeRunRow {
    task_id: String,
    class: TaskClass,
    arm: ArmId,
    rep_index: u32,
    memo_key: String,
    request_hash: String,
    request_nonce: String,
    generation_id: Option<String>,
    judge_generation_id: Option<String>,
    accuracy: f64,
    tokens_total: u32,
    tool_calls: u32,
    wall_clock_s: f64,
    answer: String,
    score_detail: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArmAggregate {
    arm: ArmId,
    runs: usize,
    mean_accuracy: f64,
    tokens_total: u32,
    mean_tool_calls: f64,
    mean_wall_clock_s: f64,
    accuracy_per_class: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClassArmSummary {
    class: String,
    arm: ArmId,
    runs: usize,
    reps: u32,
    accuracy_mean: f64,
    accuracy_range: f64,
    tokens_mean: f64,
    tokens_range: u32,
    tool_calls_mean: f64,
    wall_clock_mean_s: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParetoPoint {
    arm: ArmId,
    mean_accuracy: f64,
    tokens_total: u32,
    dominated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArmVerdictClaim {
    band: String,
    arm: ArmId,
    claim_id: String,
    claim: String,
    mean_accuracy: f64,
    tokens_total: u32,
    pareto_dominated: bool,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FalsificationVerdict {
    band: String,
    class: String,
    arm_fs_accuracy: f64,
    arm_sdk_accuracy: f64,
    arm_fs_tokens: u32,
    arm_sdk_tokens: u32,
    token_ratio: f64,
    matches_accuracy: bool,
    within_token_bound: bool,
    falsifies_sdk_necessity_premise: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetSummary {
    per_task_token_ceiling: u32,
    run_token_ceiling: u32,
    tokens_total: u32,
    max_row_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenBurnExtrapolation {
    smoke_tokens: u32,
    full_run_equivalent_runs: usize,
    observed_runs: usize,
    extrapolated_full_tokens: u32,
}

#[derive(Debug, Clone)]
struct ChatResponse {
    content: String,
    tokens_total: u32,
    generation_id: Option<String>,
}

#[derive(Debug, Clone)]
struct RunSettings {
    model: String,
    provider: String,
    full_reps: u32,
}

impl Default for RunSettings {
    fn default() -> Self {
        Self {
            model: MODEL.to_owned(),
            provider: DEFAULT_PROVIDER.to_owned(),
            full_reps: FULL_REP_COUNT,
        }
    }
}

impl RunSettings {
    fn provider_lock(&self) -> ProviderLock {
        ProviderLock {
            order: vec![self.provider.clone()],
            allow_fallbacks: false,
        }
    }

    fn full_run_count(&self) -> usize {
        FULL_TASK_COUNT * ArmId::ALL.len() * self.full_reps as usize
    }

    fn full_token_ceiling(&self) -> u32 {
        let scaled =
            u64::from(FULL_TOKEN_CEILING) * u64::from(self.full_reps) / u64::from(FULL_REP_COUNT);
        u32::try_from(scaled).unwrap_or(u32::MAX)
    }
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        [sub] if sub == "config" => print_config(),
        [sub, rest @ ..] if sub == "taskgen" => run_taskgen_cli(rest),
        [sub, rest @ ..] if sub == "smoke" => run_smoke_cli(rest),
        [sub, rest @ ..] if sub == "probe" => run_probe_cli(rest),
        [sub, rest @ ..] if sub == "full" => run_full_cli(rest),
        _ => {
            eprintln!("unknown interface-bench invocation: {args:?}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "usage: oneiron-bench interface-bench <subcommand> [flags]\n\
         \n\
         subcommands:\n\
           config                 print the interface-bench-1 CampaignConfig JSON\n\
           taskgen [--out DIR]    generate seeded fixture vault, full/smoke tasks,\n\
                                  frozen holdout metadata, and owner spot-check sample\n\
           smoke [flags]          run the 8-task x 3-arm smoke through OpenRouter\n\
                                  using OPENROUTER_API_KEY and provider-locked routing\n\
           probe [flags]          run one task x arm_sdk x 2 reps and verify\n\
                                  distinct memo keys, request hashes, and generation ids\n\
           full [flags]           run/resume the full 80-task x 3-arm x N-rep\n\
                                  campaign (default {FULL_REP_COUNT} reps, 480 rows exactly)\n\
         \n\
         flags (smoke/probe/full):\n\
           --out DIR              output directory (default {DEFAULT_OUT_DIR})\n\
           --model ID             OpenRouter model id (default {MODEL})\n\
           --provider NAME        single locked provider; fallbacks always stay disabled\n\
                                  (default {DEFAULT_PROVIDER})\n\
           --reps N               reps per task+arm for full runs (default {FULL_REP_COUNT};\n\
                                  probe always runs 2 reps)\n\
         \n\
         default output dir: {DEFAULT_OUT_DIR}"
    );
}

fn print_config() -> ExitCode {
    match serde_json::to_string_pretty(&interface_bench_1_config()) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to serialize config: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_taskgen_cli(args: &[String]) -> ExitCode {
    match parse_out_dir(args).and_then(|out| write_taskgen_outputs(&out, &RunSettings::default())) {
        Ok(report) => {
            println!(
                "generated {} claims, {} full tasks, {} smoke tasks in {}",
                report.generated_claims,
                report.full_tasks,
                report.smoke_tasks,
                report
                    .output_files
                    .get("directory")
                    .map_or("<unknown>", String::as_str)
            );
            println!(
                "owner spot-check sample: {}",
                report.owner_spotcheck_sample_ids.join(", ")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("interface-bench taskgen failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_smoke_cli(args: &[String]) -> ExitCode {
    match parse_run_flags(args).and_then(|(out, settings)| run_smoke(&out, &settings)) {
        Ok(report_path) => {
            println!("interface-bench smoke report: {}", report_path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("interface-bench smoke failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_probe_cli(args: &[String]) -> ExitCode {
    match parse_run_flags(args).and_then(|(out, settings)| run_memo_probe(&out, &settings)) {
        Ok(report_path) => {
            println!(
                "interface-bench memo probe report: {}",
                report_path.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("interface-bench memo probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_full_cli(args: &[String]) -> ExitCode {
    match parse_run_flags(args).and_then(|(out, settings)| run_full(&out, &settings)) {
        Ok(report_path) => {
            println!("interface-bench full report: {}", report_path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("interface-bench full run failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_out_dir(args: &[String]) -> Result<PathBuf, String> {
    let mut out_dir = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--out requires a directory".to_owned())?;
                out_dir = Some(PathBuf::from(value));
                index += 2;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }

    Ok(out_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_OUT_DIR)))
}

fn parse_run_flags(args: &[String]) -> Result<(PathBuf, RunSettings), String> {
    let mut out_dir = None;
    let mut settings = RunSettings::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--out requires a directory".to_owned())?;
                out_dir = Some(PathBuf::from(value));
                index += 2;
            }
            "--model" => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "--model requires a non-empty OpenRouter model id".to_owned())?;
                settings.model = value.clone();
                index += 2;
            }
            "--provider" => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "--provider requires a non-empty provider name".to_owned())?;
                settings.provider = value.clone();
                index += 2;
            }
            "--reps" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--reps requires a count".to_owned())?;
                let reps = value
                    .parse::<u32>()
                    .map_err(|error| format!("--reps expects an integer: {error}"))?;
                if reps == 0 {
                    return Err("--reps must be at least 1".to_owned());
                }
                settings.full_reps = reps;
                index += 2;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }

    Ok((
        out_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_OUT_DIR)),
        settings,
    ))
}

fn interface_bench_1_config() -> CampaignConfig {
    campaign_config_for(&RunSettings::default())
}

fn campaign_config_for(settings: &RunSettings) -> CampaignConfig {
    CampaignConfig {
        campaign: CAMPAIGN_ID.to_owned(),
        kind: KIND.to_owned(),
        nodes: ArmId::ALL.to_vec(),
        search_axes: "NONE".to_owned(),
        metric_set: MetricSet {
            parsed: vec![
                "accuracy_per_class".to_owned(),
                "tokens_total".to_owned(),
                "tool_calls".to_owned(),
                "wall_clock_s".to_owned(),
            ],
            taste: vec!["browse_rubric".to_owned()],
        },
        eval_corpus: EvalCorpusConfig {
            fixture: FIXTURE_ID.to_owned(),
            seed: DETERMINISTIC_SEED,
            generated_claims: CLAIM_COUNT,
            full_tasks: FULL_TASK_COUNT,
            smoke_tasks: SMOKE_TASK_COUNT,
            holdout: HoldoutPolicy {
                fraction_per_class: 0.20,
                freeze_after: "first_smoke".to_owned(),
            },
        },
        sacred_set: None,
        budget_lease: BudgetLeaseConfig {
            discipline: "reserve-then-sum-then-reject".to_owned(),
            per_task_token_ceiling: PER_TASK_TOKEN_CEILING,
            smoke_token_ceiling: SMOKE_TOKEN_CEILING,
            full_token_ceiling: settings.full_token_ceiling(),
            tool_call_cap: TOOL_CALL_CAP,
            wall_clock_cap_s: WALL_CLOCK_CAP_S,
        },
        proposer: None,
        runner: RunnerConfig {
            kind: "eval_executor_only".to_owned(),
            call_purpose: "Eval".to_owned(),
        },
        decide: DecideConfig {
            mode: "report-only".to_owned(),
            verdict_band: "Proposed".to_owned(),
            arm_promotion: "OWNER CALL".to_owned(),
        },
        model_binding: ModelBinding {
            model: settings.model.clone(),
            route: ProviderRoute {
                provider: settings.provider_lock(),
            },
            browse_judge_model: settings.model.clone(),
        },
    }
}

fn build_task_bundle() -> TaskBundle {
    let fixture = FixtureVault {
        schema_version: SCHEMA_VERSION,
        fixture_id: FIXTURE_ID.to_owned(),
        campaign: CAMPAIGN_ID.to_owned(),
        seed: DETERMINISTIC_SEED,
        claim_count: CLAIM_COUNT,
        claims: generate_claims(),
    };
    let mut full_tasks = generate_tasks(&fixture);
    mark_holdout_and_smoke(&mut full_tasks);
    let smoke_tasks = full_tasks
        .iter()
        .filter(|task| task.smoke)
        .cloned()
        .collect::<Vec<_>>();
    let holdout = freeze_holdout(&full_tasks);
    let spotcheck = owner_spotcheck_sample(&full_tasks);

    TaskBundle {
        config: interface_bench_1_config(),
        fixture,
        full_tasks,
        smoke_tasks,
        holdout,
        spotcheck,
    }
}

fn generate_claims() -> Vec<FixtureClaim> {
    let mut claims = Vec::with_capacity(CLAIM_COUNT);
    for person_index in 0..PERSON_COUNT {
        for topic_index in 0..TOPIC_COUNT {
            claims.push(claim_for_indices(person_index, topic_index));
        }
    }
    claims
}

fn claim_for_indices(person_index: usize, topic_index: usize) -> FixtureClaim {
    let claim_id = claim_id_for(person_index, topic_index);
    let topic_id_value = topic_id(topic_index);
    let person_id = person_id(person_index);
    let object_id = object_id(person_index);
    let organization_id = organization_id(person_index);
    let source_ref = source_ref(person_index, topic_index);
    let learned_at_epoch_s = learned_at(person_index, topic_index);
    let learned_at_label = format!("day-{}", learned_at_epoch_s / 86_400);
    let stance = stance_for(person_index, topic_index);
    let topic = topic_name(topic_index);
    let person = person_name(person_index);
    let owned_object = object_name(person_index);
    let organization = organization_name(person_index);
    let changed_after = format!("after-{}", topic_id(topic_index / 10));
    let superseded_by = superseded_by_for(person_index, topic_index);
    let mut relations = BTreeMap::new();
    relations.insert("owner_of".to_owned(), vec![object_id.clone()]);
    relations.insert("employed_by".to_owned(), vec![organization_id.clone()]);
    relations.insert("has_topic".to_owned(), vec![topic_id_value.clone()]);
    relations.insert("cites_source".to_owned(), vec![source_ref.clone()]);

    FixtureClaim {
        claim_id,
        topic_id: topic_id_value,
        topic: topic.clone(),
        person_id,
        person: person.clone(),
        owned_object_id: object_id,
        owned_object: owned_object.clone(),
        organization_id,
        organization: organization.clone(),
        stance: stance.clone(),
        source_ref: source_ref.clone(),
        learned_at_epoch_s,
        learned_at_label: learned_at_label.clone(),
        superseded_by,
        text: format!(
            "{person} at {organization} {stance} about {topic}; {person} owns {owned_object}. Source {source_ref} learned {learned_at_label}."
        ),
        relations,
        provenance: ClaimProvenance {
            source_ref,
            learned_at_epoch_s,
            changed_after,
            source_kind: "seeded_fixture".to_owned(),
        },
    }
}

fn generate_tasks(fixture: &FixtureVault) -> Vec<BenchTask> {
    let mut tasks = Vec::with_capacity(FULL_TASK_COUNT);
    tasks.extend((0..30).map(|ordinal| retrieval_task(fixture, ordinal)));
    tasks.extend((0..20).map(|ordinal| multi_hop_task(fixture, ordinal)));
    tasks.extend((0..20).map(|ordinal| provenance_task(fixture, ordinal)));
    tasks.extend((0..10).map(|ordinal| browse_task(fixture, ordinal)));
    tasks
}

fn retrieval_task(_fixture: &FixtureVault, ordinal: usize) -> BenchTask {
    let topic_index = ordinal;
    let topic = topic_name(topic_index);
    let relevant_claim_ids = (0..PERSON_COUNT)
        .map(|person_index| claim_id_for(person_index, topic_index))
        .collect::<Vec<_>>();
    let task_id = format!("retrieval-qa-{ordinal:03}");
    BenchTask {
        task_id,
        class: TaskClass::RetrievalQa,
        prompt: format!("Find the claims about {topic}. Cite the claim ids you used."),
        gold: GoldLabel::RetrievalQa {
            relevant_claim_ids: relevant_claim_ids.clone(),
        },
        scorer: ScorerConfig {
            scorer: "set_f1(relevant_claim_ids)".to_owned(),
            blind_judge: false,
        },
        supporting_claim_ids: relevant_claim_ids.clone(),
        holdout: false,
        smoke: false,
        generation: GenerationProof {
            recipe: "topic sweep selected from seeded fixture topic index".to_owned(),
            selected_subgraph: relevant_claim_ids,
            verified_by_construction: true,
        },
    }
}

fn multi_hop_task(fixture: &FixtureVault, ordinal: usize) -> BenchTask {
    let person_index = (ordinal * 7) % PERSON_COUNT;
    let topic_index = 30 + (ordinal * 3) % 60;
    let claim = fixture_claim(fixture, person_index, topic_index);
    let task_id = format!("multi-hop-{ordinal:03}");
    BenchTask {
        task_id,
        class: TaskClass::MultiHop,
        prompt: format!(
            "What does the person who owns {} think about {}? Cite the supporting claim id.",
            claim.owned_object, claim.topic
        ),
        gold: GoldLabel::MultiHop {
            exact_answer: claim.stance.clone(),
            supporting_ids: vec![claim.claim_id.clone()],
        },
        scorer: ScorerConfig {
            scorer: "exact_answer + supporting_ids_f1".to_owned(),
            blind_judge: false,
        },
        supporting_claim_ids: vec![claim.claim_id.clone()],
        holdout: false,
        smoke: false,
        generation: GenerationProof {
            recipe: "object owner relation plus topic claim selected from fixture graph".to_owned(),
            selected_subgraph: vec![
                claim.person_id.clone(),
                claim.owned_object_id.clone(),
                claim.topic_id.clone(),
                claim.claim_id.clone(),
            ],
            verified_by_construction: true,
        },
    }
}

fn provenance_task(fixture: &FixtureVault, ordinal: usize) -> BenchTask {
    let person_index = (ordinal * 11) % PERSON_COUNT;
    let topic_index = 55 + (ordinal * 2) % 40;
    let claim = fixture_claim(fixture, person_index, topic_index);
    let (field, value, question) = match ordinal % 3 {
        0 => (
            "source_ref",
            claim.source_ref.clone(),
            format!(
                "Which source said what {} thinks about {}?",
                claim.person, claim.topic
            ),
        ),
        1 => (
            "learned_at_epoch_s",
            claim.learned_at_epoch_s.to_string(),
            format!(
                "What learned_at_epoch_s value records when we learned what {} thinks about {}?",
                claim.person, claim.topic
            ),
        ),
        _ => (
            "changed_after",
            claim.provenance.changed_after.clone(),
            format!(
                "What changed-after marker is attached to the claim about {} and {}?",
                claim.person, claim.topic
            ),
        ),
    };
    let task_id = format!("provenance-{ordinal:03}");
    BenchTask {
        task_id,
        class: TaskClass::Provenance,
        prompt: format!("{question} Cite the claim id."),
        gold: GoldLabel::Provenance {
            field: field.to_owned(),
            value,
            supporting_ids: vec![claim.claim_id.clone()],
        },
        scorer: ScorerConfig {
            scorer: "field_match + supporting_ids_f1".to_owned(),
            blind_judge: false,
        },
        supporting_claim_ids: vec![claim.claim_id.clone()],
        holdout: false,
        smoke: false,
        generation: GenerationProof {
            recipe: "provenance field selected from constructed claim metadata".to_owned(),
            selected_subgraph: vec![claim.claim_id.clone(), claim.source_ref.clone()],
            verified_by_construction: true,
        },
    }
}

fn browse_task(_fixture: &FixtureVault, ordinal: usize) -> BenchTask {
    let topic_index = 80 + ordinal * 2;
    let topic = topic_name(topic_index);
    let required_claim_ids = (0..10)
        .map(|person_index| claim_id_for(person_index, topic_index))
        .collect::<Vec<_>>();
    let task_id = format!("browse-then-answer-{ordinal:03}");
    BenchTask {
        task_id,
        class: TaskClass::BrowseThenAnswer,
        prompt: format!("Summarize what the vault knows about {topic}. Cite claim ids."),
        gold: GoldLabel::BrowseThenAnswer {
            topic,
            required_claim_ids: required_claim_ids.clone(),
            rubric: BrowseRubric {
                coverage: "mentions multiple fixture claims for the topic".to_owned(),
                faithfulness: "uses only facts present in cited claims".to_owned(),
                citation_validity: "claim ids must exist and support the summary".to_owned(),
                scale: "1-5".to_owned(),
            },
        },
        scorer: ScorerConfig {
            scorer: "blind browse_rubric judge".to_owned(),
            blind_judge: true,
        },
        supporting_claim_ids: required_claim_ids.clone(),
        holdout: false,
        smoke: false,
        generation: GenerationProof {
            recipe: "topic synthesis task selected from fixture topic cluster".to_owned(),
            selected_subgraph: required_claim_ids,
            verified_by_construction: true,
        },
    }
}

fn mark_holdout_and_smoke(tasks: &mut [BenchTask]) {
    for class in TaskClass::ALL {
        let indices = tasks
            .iter()
            .enumerate()
            .filter_map(|(index, task)| (task.class == class).then_some(index))
            .collect::<Vec<_>>();
        let holdout_start = indices.len() - indices.len() / 5;
        for (class_position, task_index) in indices.iter().enumerate() {
            if class_position >= holdout_start {
                tasks[*task_index].holdout = true;
            }
            if class_position < 2 {
                tasks[*task_index].smoke = true;
            }
        }
    }
}

fn freeze_holdout(tasks: &[BenchTask]) -> HoldoutFreeze {
    let mut per_class = BTreeMap::new();
    for class in TaskClass::ALL {
        let class_tasks = tasks
            .iter()
            .filter(|task| task.class == class)
            .collect::<Vec<_>>();
        let task_ids = class_tasks
            .iter()
            .filter(|task| task.holdout)
            .map(|task| task.task_id.clone())
            .collect::<Vec<_>>();
        per_class.insert(
            class.as_str().to_owned(),
            HoldoutClassFreeze {
                total: class_tasks.len(),
                holdout: task_ids.len(),
                task_ids,
            },
        );
    }

    HoldoutFreeze {
        campaign: CAMPAIGN_ID.to_owned(),
        frozen_on: "2026-07-07-after-first-smoke".to_owned(),
        policy: HoldoutPolicy {
            fraction_per_class: 0.20,
            freeze_after: "first_smoke".to_owned(),
        },
        per_class,
    }
}

fn owner_spotcheck_sample(tasks: &[BenchTask]) -> Vec<BenchTask> {
    let mut sample = Vec::with_capacity(OWNER_SPOTCHECK_COUNT);
    for class in TaskClass::ALL {
        let class_tasks = tasks
            .iter()
            .filter(|task| task.class == class)
            .collect::<Vec<_>>();
        if let Some(first) = class_tasks.first() {
            sample.push((*first).clone());
        }
        if let Some(holdout) = class_tasks.iter().find(|task| task.holdout) {
            sample.push((*holdout).clone());
        }
    }
    sample
}

fn write_taskgen_outputs(out_dir: &Path, settings: &RunSettings) -> Result<TaskgenReport, String> {
    let mut bundle = build_task_bundle();
    bundle.config = campaign_config_for(settings);
    fs::create_dir_all(out_dir).map_err(|error| format!("create output dir: {error}"))?;

    let files = BTreeMap::from([
        (
            "directory".to_owned(),
            out_dir
                .canonicalize()
                .unwrap_or_else(|_| out_dir.to_path_buf())
                .display()
                .to_string(),
        ),
        (
            "campaign_config".to_owned(),
            out_dir.join("campaign_config.json").display().to_string(),
        ),
        (
            "fixture_vault".to_owned(),
            out_dir.join("fixture_vault.json").display().to_string(),
        ),
        (
            "tasks_full".to_owned(),
            out_dir.join("tasks_full.json").display().to_string(),
        ),
        (
            "tasks_smoke".to_owned(),
            out_dir.join("tasks_smoke.json").display().to_string(),
        ),
        (
            "holdout_freeze".to_owned(),
            out_dir.join("holdout_freeze.json").display().to_string(),
        ),
        (
            "owner_spotcheck_sample".to_owned(),
            out_dir
                .join("owner_spotcheck_sample.json")
                .display()
                .to_string(),
        ),
        (
            "taskgen_report".to_owned(),
            out_dir.join("taskgen_report.json").display().to_string(),
        ),
    ]);

    write_json(&out_dir.join("campaign_config.json"), &bundle.config)?;
    write_json(&out_dir.join("fixture_vault.json"), &bundle.fixture)?;
    write_json(&out_dir.join("tasks_full.json"), &bundle.full_tasks)?;
    write_json(&out_dir.join("tasks_smoke.json"), &bundle.smoke_tasks)?;
    write_json(&out_dir.join("holdout_freeze.json"), &bundle.holdout)?;
    write_json(
        &out_dir.join("owner_spotcheck_sample.json"),
        &bundle.spotcheck,
    )?;

    let report = TaskgenReport {
        campaign: CAMPAIGN_ID.to_owned(),
        fixture_id: FIXTURE_ID.to_owned(),
        generated_claims: bundle.fixture.claims.len(),
        full_tasks: bundle.full_tasks.len(),
        smoke_tasks: bundle.smoke_tasks.len(),
        holdout_by_class: bundle
            .holdout
            .per_class
            .iter()
            .map(|(class, freeze)| (class.clone(), freeze.holdout))
            .collect(),
        smoke_task_ids: bundle
            .smoke_tasks
            .iter()
            .map(|task| task.task_id.clone())
            .collect(),
        owner_spotcheck_sample_ids: bundle
            .spotcheck
            .iter()
            .map(|task| task.task_id.clone())
            .collect(),
        output_files: files,
    };
    write_json(&out_dir.join("taskgen_report.json"), &report)?;

    Ok(report)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let file = File::create(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let tmp_path = path.with_extension("json.tmp");
    write_json(&tmp_path, value)?;
    fs::rename(&tmp_path, path).map_err(|error| {
        format!(
            "rename {} to {}: {error}",
            tmp_path.display(),
            path.display()
        )
    })
}

fn read_json<T>(path: &Path) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    serde_json::from_reader(file).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn validate_loaded_row(
    row: &SmokeRunRow,
    task: &BenchTask,
    arm: ArmId,
    rep_index: u32,
    memo_key: &str,
    request_hash: &str,
    request_nonce: &str,
) -> Result<(), String> {
    if row.task_id != task.task_id
        || row.class != task.class
        || row.arm != arm
        || row.rep_index != rep_index
        || row.memo_key != memo_key
        || row.request_hash != request_hash
        || row.request_nonce != request_nonce
    {
        return Err(format!(
            "memo row mismatch for task={} arm={} rep={} key={memo_key}",
            task.task_id,
            arm.as_str(),
            rep_index
        ));
    }
    enforce_row_budget(row)
}

fn enforce_row_budget(row: &SmokeRunRow) -> Result<(), String> {
    if row.tokens_total > PER_TASK_TOKEN_CEILING {
        return Err(format!(
            "row task={} arm={} rep={} used {} tokens, above per-task ceiling {PER_TASK_TOKEN_CEILING}",
            row.task_id,
            row.arm.as_str(),
            row.rep_index,
            row.tokens_total
        ));
    }
    Ok(())
}

fn enforce_budget(rows: &[SmokeRunRow], run_ceiling: u32) -> Result<(), String> {
    for row in rows {
        enforce_row_budget(row)?;
    }
    let tokens_total = rows.iter().map(|row| row.tokens_total).sum::<u32>();
    if tokens_total > run_ceiling {
        return Err(format!(
            "run used {tokens_total} tokens, above run ceiling {run_ceiling}"
        ));
    }
    Ok(())
}

fn run_smoke(out_dir: &Path, settings: &RunSettings) -> Result<PathBuf, String> {
    let api_key = openrouter_api_key("smoke")?;
    write_taskgen_outputs(out_dir, settings)?;
    let bundle = build_task_bundle();
    let rows = run_eval_rows(
        &api_key,
        out_dir,
        "smoke_rows",
        &bundle,
        &bundle.smoke_tasks,
        &ArmId::ALL,
        &[0],
        settings,
    )?;
    enforce_budget(&rows, SMOKE_TOKEN_CEILING)?;

    let report = SmokeReport {
        campaign: CAMPAIGN_ID.to_owned(),
        model: settings.model.clone(),
        provider: settings.provider_lock(),
        run_id: format!("interface-bench-1-smoke-{}", unix_now()),
        task_count: bundle.smoke_tasks.len(),
        aggregates: aggregate_rows(&rows),
        full_run_token_burn_extrapolation: token_burn_extrapolation(&rows, settings.full_reps),
        runs: rows,
    };
    let report_path = out_dir.join("smoke_report.json");
    write_json_atomic(&report_path, &report)?;
    Ok(report_path)
}

fn run_memo_probe(out_dir: &Path, settings: &RunSettings) -> Result<PathBuf, String> {
    let api_key = openrouter_api_key("memo probe")?;
    write_taskgen_outputs(out_dir, settings)?;
    let bundle = build_task_bundle();
    let task = bundle
        .full_tasks
        .iter()
        .find(|task| task.class == TaskClass::RetrievalQa)
        .ok_or_else(|| "no retrieval-QA task available for memo probe".to_owned())?;
    let rows = run_eval_rows(
        &api_key,
        out_dir,
        "full_rows",
        &bundle,
        std::slice::from_ref(task),
        &[ArmId::Sdk],
        &[0, 1],
        settings,
    )?;
    let memo_keys_distinct = rows[0].memo_key != rows[1].memo_key;
    let request_hashes_distinct = rows[0].request_hash != rows[1].request_hash;
    let generation_ids_distinct = match (&rows[0].generation_id, &rows[1].generation_id) {
        (Some(left), Some(right)) => left != right,
        _ => false,
    };
    let passed = memo_keys_distinct && request_hashes_distinct && generation_ids_distinct;
    let report = MemoProbeReport {
        campaign: CAMPAIGN_ID.to_owned(),
        model: settings.model.clone(),
        provider: settings.provider_lock(),
        task_id: task.task_id.clone(),
        arm: ArmId::Sdk,
        reps: rows,
        memo_keys_distinct,
        request_hashes_distinct,
        generation_ids_distinct,
        passed,
    };
    let report_path = out_dir.join("memo_probe_report.json");
    write_json_atomic(&report_path, &report)?;
    if !passed {
        return Err(format!(
            "memo probe failed; report written to {}",
            report_path.display()
        ));
    }
    Ok(report_path)
}

fn run_full(out_dir: &Path, settings: &RunSettings) -> Result<PathBuf, String> {
    run_memo_probe(out_dir, settings)?;
    let api_key = openrouter_api_key("full run")?;
    write_taskgen_outputs(out_dir, settings)?;
    let bundle = build_task_bundle();
    let reps = (0..settings.full_reps).collect::<Vec<_>>();
    let rows = run_eval_rows(
        &api_key,
        out_dir,
        "full_rows",
        &bundle,
        &bundle.full_tasks,
        &ArmId::ALL,
        &reps,
        settings,
    )?;
    let expected_runs = settings.full_run_count();
    if rows.len() != expected_runs {
        return Err(format!(
            "full campaign produced {} rows, expected {expected_runs}",
            rows.len()
        ));
    }
    enforce_budget(&rows, settings.full_token_ceiling())?;
    let report = full_run_report(&bundle, rows, settings);
    let report_path = out_dir.join("full_report.json");
    write_json_atomic(&report_path, &report)?;
    Ok(report_path)
}

fn openrouter_api_key(run_label: &str) -> Result<String, String> {
    std::env::var("OPENROUTER_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("OPENROUTER_API_KEY is not present; {run_label} not run"))
}

#[allow(clippy::too_many_arguments)]
fn run_eval_rows(
    api_key: &str,
    out_dir: &Path,
    row_dir_name: &str,
    bundle: &TaskBundle,
    tasks: &[BenchTask],
    arms: &[ArmId],
    reps: &[u32],
    settings: &RunSettings,
) -> Result<Vec<SmokeRunRow>, String> {
    let row_dir = out_dir.join(row_dir_name);
    fs::create_dir_all(&row_dir).map_err(|error| format!("create row dir: {error}"))?;
    let mut rows = Vec::with_capacity(tasks.len() * arms.len() * reps.len());
    for task in tasks {
        for arm in arms {
            for rep_index in reps {
                let row = run_or_load_eval_row(
                    api_key,
                    &row_dir,
                    task,
                    *arm,
                    *rep_index,
                    &bundle.fixture,
                    settings,
                )?;
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

fn run_or_load_eval_row(
    api_key: &str,
    row_dir: &Path,
    task: &BenchTask,
    arm: ArmId,
    rep_index: u32,
    fixture: &FixtureVault,
    settings: &RunSettings,
) -> Result<SmokeRunRow, String> {
    let context = arm_context(arm, task, fixture)?;
    if context.tool_calls > TOOL_CALL_CAP {
        return Err(format!(
            "task={} arm={} rep={} would use {} tool calls, above cap {TOOL_CALL_CAP}",
            task.task_id,
            arm.as_str(),
            rep_index,
            context.tool_calls
        ));
    }
    let messages = vec![
        chat_message("system", shared_system_prompt(arm)),
        chat_message("user", eval_user_prompt(task, &context)),
    ];
    let request_nonce = request_nonce(task, arm, rep_index);
    let request = openrouter_request_body(&messages, 900, &request_nonce, settings);
    let request_hash = blake3_hex(request.to_string().as_bytes());
    let judge_cache_key = judge_cache_key(task);
    let memo_key = eval_memo_key(
        task,
        arm,
        rep_index,
        &request_nonce,
        &request_hash,
        judge_cache_key.as_deref(),
    );
    let row_path = row_dir.join(format!("{memo_key}.json"));
    if row_path.exists() {
        let row = read_json::<SmokeRunRow>(&row_path)?;
        validate_loaded_row(
            &row,
            task,
            arm,
            rep_index,
            &memo_key,
            &request_hash,
            &request_nonce,
        )?;
        return Ok(row);
    }

    let started = Instant::now();
    let response = call_openrouter(api_key, &messages, 900, &request_nonce, settings)?;
    let candidate_wall_clock_s = started.elapsed().as_secs_f64();
    let (base_accuracy, base_detail) = score_task(task, &response.content);
    let (accuracy, detail, judge_tokens, judge_generation_id) =
        if task.class == TaskClass::BrowseThenAnswer {
            judge_browse_answer(
                api_key,
                task,
                fixture,
                &response.content,
                base_accuracy,
                base_detail,
                rep_index,
                settings,
            )?
        } else {
            (base_accuracy, base_detail, 0, None)
        };
    let row = SmokeRunRow {
        task_id: task.task_id.clone(),
        class: task.class,
        arm,
        rep_index,
        memo_key,
        request_hash,
        request_nonce,
        generation_id: response.generation_id,
        judge_generation_id,
        accuracy,
        tokens_total: response.tokens_total.saturating_add(judge_tokens),
        tool_calls: context.tool_calls,
        wall_clock_s: candidate_wall_clock_s,
        answer: response.content,
        score_detail: detail,
    };
    enforce_row_budget(&row)?;
    write_json_atomic(&row_path, &row)?;
    Ok(row)
}

fn shared_system_prompt(arm: ArmId) -> String {
    let affordance = match arm {
        ArmId::Sdk => {
            "You have typed tools: search(query, k), traverse(claim_id, relation), and get(claim_id). Prefer search for topics, traverse for connected facts, and get for provenance."
        }
        ArmId::Fs => {
            "You have a bash shell over the vault filesystem: claims live under /claims/, entities under /entities/, sources under /sources/; grep -r is index-accelerated; ls -t sorts by time. Navigate and cite claim paths."
        }
        ArmId::Hybrid => {
            "You have the filesystem shell plus ranked retrieval as paths: cat '/q/<your query>' returns a ranked listing of claim paths. Use query paths when browsing is slower than asking."
        }
    };
    format!(
        "You are answering questions against a personal-memory vault. Answer ONLY from what you retrieve; if the vault does not contain it, say so. Cite claim ids or paths. You have a budget of {TOOL_CALL_CAP} tool calls.\n\n{affordance}"
    )
}

fn eval_user_prompt(task: &BenchTask, context: &ArmContext) -> String {
    format!(
        "{}\n\nInterface transcript ({} tool calls):\n{}\n\nReturn a concise final answer with citations.",
        task.prompt, context.tool_calls, context.transcript
    )
}

fn arm_context(arm: ArmId, task: &BenchTask, fixture: &FixtureVault) -> Result<ArmContext, String> {
    match arm {
        ArmId::Sdk => sdk_context(task, fixture),
        ArmId::Fs => fs_context(task, fixture, false),
        ArmId::Hybrid => fs_context(task, fixture, true),
    }
}

fn sdk_context(task: &BenchTask, fixture: &FixtureVault) -> Result<ArmContext, String> {
    let claims = context_claims(task, fixture)?;
    let mut transcript = String::new();
    transcript.push_str("search(query, k) -> ranked claim ids\n");
    for claim in &claims {
        transcript.push_str(&format!(
            "{} score=1.0 topic={} person={} source={}\n",
            claim.claim_id, claim.topic_id, claim.person, claim.source_ref
        ));
    }
    let get_claims = if task.class == TaskClass::RetrievalQa {
        Vec::new()
    } else {
        claims
    };
    if !get_claims.is_empty() {
        transcript.push_str("\nget(claim_id) samples:\n");
        for claim in &get_claims {
            transcript.push_str(&format!("{}: {}\n", claim.claim_id, claim.text));
            transcript.push_str(&format!(
                "  provenance: source_ref={} learned_at_epoch_s={} changed_after={} source_kind={}\n",
                claim.source_ref,
                claim.learned_at_epoch_s,
                claim.provenance.changed_after,
                claim.provenance.source_kind
            ));
        }
    }
    Ok(ArmContext {
        tool_calls: 1 + get_claims.len() as u32,
        transcript,
    })
}

fn fs_context(
    task: &BenchTask,
    fixture: &FixtureVault,
    hybrid: bool,
) -> Result<ArmContext, String> {
    let claims = context_claims(task, fixture)?;
    let mut transcript = String::new();
    if hybrid {
        transcript.push_str("$ cat '/q/");
        transcript.push_str(&task.prompt.replace('\'', ""));
        transcript.push_str("'\n");
    } else {
        transcript.push_str("$ grep -r '<task terms>' /claims/\n");
    }
    for claim in &claims {
        transcript.push_str(&format!("/claims/{}.txt\n", claim.claim_id));
    }
    transcript.push_str("\n$ cat <ranked claim files>\n");
    for claim in &claims {
        transcript.push_str(&format!(
            "== /claims/{}.txt ==\nid: {}\ntopic: {}\nsource: {}\nlearned_at_epoch_s: {}\nchanged_after: {}\nsource_kind: {}\nrelations: owner_of={}, employed_by={}\ntext: {}\n",
            claim.claim_id,
            claim.claim_id,
            claim.topic,
            claim.source_ref,
            claim.learned_at_epoch_s,
            claim.provenance.changed_after,
            claim.provenance.source_kind,
            claim.owned_object_id,
            claim.organization_id,
            claim.text
        ));
    }
    Ok(ArmContext {
        tool_calls: transcript_tool_calls(&transcript),
        transcript,
    })
}

fn transcript_tool_calls(transcript: &str) -> u32 {
    transcript
        .lines()
        .filter(|line| line.starts_with("$ "))
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
}

fn context_claims<'a>(
    task: &BenchTask,
    fixture: &'a FixtureVault,
) -> Result<Vec<&'a FixtureClaim>, String> {
    let ids = match &task.gold {
        GoldLabel::RetrievalQa { relevant_claim_ids } => {
            relevant_claim_ids.iter().collect::<Vec<_>>()
        }
        GoldLabel::MultiHop { supporting_ids, .. }
        | GoldLabel::Provenance { supporting_ids, .. } => {
            supporting_ids.iter().take(8).collect::<Vec<_>>()
        }
        GoldLabel::BrowseThenAnswer {
            required_claim_ids, ..
        } => required_claim_ids.iter().collect::<Vec<_>>(),
    };
    let by_id = fixture
        .claims
        .iter()
        .map(|claim| (claim.claim_id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();
    ids.into_iter()
        .map(|id| {
            by_id
                .get(id.as_str())
                .copied()
                .ok_or_else(|| format!("missing fixture claim `{id}`"))
        })
        .collect()
}

fn request_nonce(task: &BenchTask, arm: ArmId, rep_index: u32) -> String {
    format!(
        "{CAMPAIGN_ID}:{}:{}:rep-{rep_index}",
        task.task_id,
        arm.as_str()
    )
}

fn judge_request_nonce(task: &BenchTask, rep_index: u32) -> String {
    format!(
        "{CAMPAIGN_ID}:{}:browse-judge:rep-{rep_index}",
        task.task_id
    )
}

fn openrouter_request_body(
    messages: &[Value],
    max_tokens: u32,
    request_user: &str,
    settings: &RunSettings,
) -> Value {
    json!({
        "model": settings.model,
        "messages": messages,
        "temperature": REQUEST_TEMPERATURE,
        "max_tokens": max_tokens,
        "provider": settings.provider_lock(),
        "user": request_user
    })
}

fn eval_memo_key(
    task: &BenchTask,
    arm: ArmId,
    rep_index: u32,
    request_nonce: &str,
    request_hash: &str,
    judge_cache_key: Option<&str>,
) -> String {
    let mut input = json!({
        "campaign": CAMPAIGN_ID,
        "callPurpose": "Eval",
        "scorerVersion": SCORER_VERSION,
        "taskId": task.task_id,
        "class": task.class.as_str(),
        "arm": arm.as_str(),
        "repIndex": rep_index,
        "requestNonce": request_nonce,
        "requestHash": request_hash,
    });
    if let Some(judge_cache_key) = judge_cache_key {
        input["judgeCacheKey"] = json!(judge_cache_key);
    }
    blake3_hex(input.to_string().as_bytes())
}

fn judge_cache_key(task: &BenchTask) -> Option<String> {
    if task.class == TaskClass::BrowseThenAnswer {
        Some(BROWSE_JUDGE_PROMPT_VERSION.to_owned())
    } else {
        None
    }
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn call_openrouter(
    api_key: &str,
    messages: &[Value],
    max_tokens: u32,
    request_user: &str,
    settings: &RunSettings,
) -> Result<ChatResponse, String> {
    if api_key.contains(['\r', '\n']) {
        return Err("OPENROUTER_API_KEY contains unsupported newline characters".to_owned());
    }
    let request = openrouter_request_body(messages, max_tokens, request_user, settings);
    let mut request_file =
        tempfile::NamedTempFile::new().map_err(|error| format!("create request body: {error}"))?;
    request_file
        .write_all(request.to_string().as_bytes())
        .map_err(|error| format!("write OpenRouter request body: {error}"))?;
    request_file
        .flush()
        .map_err(|error| format!("flush OpenRouter request body: {error}"))?;

    let curl_config = format!(
        "silent\n\
         show-error\n\
         fail-with-body\n\
         max-time = \"{}\"\n\
         header = \"Authorization: Bearer {}\"\n\
         header = \"Content-Type: application/json\"\n",
        WALL_CLOCK_CAP_S,
        curl_config_escape(api_key)
    );
    let mut child = Command::new("curl")
        .arg("--config")
        .arg("-")
        .arg("--data-binary")
        .arg(format!("@{}", request_file.path().display()))
        .arg(OPENROUTER_CHAT_COMPLETIONS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn curl for OpenRouter: {error}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "curl stdin was not available".to_owned())?;
        stdin
            .write_all(curl_config.as_bytes())
            .map_err(|error| format!("write curl config: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait for OpenRouter response: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "OpenRouter provider-locked request failed: status={} stderr={} body={}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        ));
    }
    let body: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse OpenRouter response JSON: {error}"))?;
    let content = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("OpenRouter response missing assistant content: {body}"))?
        .to_owned();
    let tokens_total = body
        .get("usage")
        .and_then(|usage| usage.get("total_tokens"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let generation_id = body
        .get("id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Ok(ChatResponse {
        content,
        tokens_total,
        generation_id,
    })
}

fn curl_config_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn chat_message(role: &str, content: String) -> Value {
    json!({
        "role": role,
        "content": content
    })
}

fn score_task(task: &BenchTask, answer: &str) -> (f64, Value) {
    match &task.gold {
        GoldLabel::RetrievalQa { relevant_claim_ids } => {
            let cited = extract_claim_ids(answer);
            let gold = relevant_claim_ids.iter().cloned().collect::<BTreeSet<_>>();
            let f1 = set_f1(&cited, &gold);
            (
                f1,
                json!({"set_f1": f1, "cited": cited, "gold_count": gold.len()}),
            )
        }
        GoldLabel::MultiHop {
            exact_answer,
            supporting_ids,
        } => {
            let answer_hit = contains_case_insensitive(answer, exact_answer);
            let support_f1 = set_f1(
                &extract_claim_ids(answer),
                &supporting_ids.iter().cloned().collect::<BTreeSet<_>>(),
            );
            let score = if answer_hit { 0.7 } else { 0.0 } + support_f1 * 0.3;
            (
                score,
                json!({"exact_answer": answer_hit, "supporting_ids_f1": support_f1}),
            )
        }
        GoldLabel::Provenance {
            field,
            value,
            supporting_ids,
        } => {
            let value_hit = contains_case_insensitive(answer, value);
            let support_f1 = set_f1(
                &extract_claim_ids(answer),
                &supporting_ids.iter().cloned().collect::<BTreeSet<_>>(),
            );
            let score = if value_hit { 0.7 } else { 0.0 } + support_f1 * 0.3;
            (
                score,
                json!({"field": field, "field_match": value_hit, "supporting_ids_f1": support_f1}),
            )
        }
        GoldLabel::BrowseThenAnswer {
            required_claim_ids, ..
        } => {
            let citation_f1 = set_f1(
                &extract_claim_ids(answer),
                &required_claim_ids.iter().cloned().collect::<BTreeSet<_>>(),
            );
            (
                citation_f1,
                json!({"citation_f1": citation_f1, "blind_judge": "pending"}),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn judge_browse_answer(
    api_key: &str,
    task: &BenchTask,
    fixture: &FixtureVault,
    answer: &str,
    citation_score: f64,
    citation_detail: Value,
    rep_index: u32,
    settings: &RunSettings,
) -> Result<(f64, Value, u32, Option<String>), String> {
    let GoldLabel::BrowseThenAnswer {
        topic,
        rubric,
        required_claim_ids,
    } = &task.gold
    else {
        return Ok((citation_score, citation_detail, 0, None));
    };
    let evidence = claim_evidence_block(fixture, required_claim_ids)?;
    let judge_answer = blind_judge_answer(answer);
    let judge_prompt = format!(
        "Grade this answer on a blind 1-5 rubric. The arm identity is hidden.\n\
         Task topic: {topic}\n\
         Required claim evidence:\n{evidence}\n\
         Rubric coverage: {}\n\
         Rubric faithfulness: {}\n\
         Rubric citation validity: {}\n\
         Return JSON only: {{\"coverage\":1-5,\"faithfulness\":1-5,\"citation_validity\":1-5,\"notes\":\"short\"}}\n\n\
         Answer:\n{judge_answer}",
        rubric.coverage, rubric.faithfulness, rubric.citation_validity
    );
    let request_user = judge_request_nonce(task, rep_index);
    let response = call_openrouter(
        api_key,
        &[
            chat_message(
                "system",
                "You are a blind evaluator. Return valid JSON only.".to_owned(),
            ),
            chat_message("user", judge_prompt),
        ],
        1_200,
        &request_user,
        settings,
    )?;
    let parsed = serde_json::from_str::<Value>(&response.content).unwrap_or_else(|_| {
        json!({
            "coverage": 1,
            "faithfulness": 1,
            "citation_validity": 1,
            "notes": "judge returned non-JSON"
        })
    });
    let coverage = rubric_score(&parsed, "coverage");
    let faithfulness = rubric_score(&parsed, "faithfulness");
    let citation_validity = rubric_score(&parsed, "citation_validity");
    let mean = (coverage + faithfulness + citation_validity) / 15.0;
    let final_accuracy = final_browse_accuracy(mean, citation_score);
    let generation_id = response.generation_id.clone();
    Ok((
        final_accuracy,
        json!({
            "browse_rubric": parsed,
            "rubric_normalized_score": mean,
            "citation_score": citation_score,
            "normalized_score": final_accuracy,
            "combiner": "min(rubric_normalized_score,citation_score)",
            "judge_tokens_total": response.tokens_total,
            "judge_generation_id": generation_id.as_deref(),
            "judge_prompt_version": BROWSE_JUDGE_PROMPT_VERSION,
            "citation_precheck": citation_detail
        }),
        response.tokens_total,
        generation_id,
    ))
}

fn blind_judge_answer(answer: &str) -> String {
    let mut output = String::with_capacity(answer.len());
    let mut rest = answer;
    while let Some(start) = rest.find("/claims/") {
        output.push_str(&rest[..start]);
        let path_start = start + "/claims/".len();
        let after_prefix = &rest[path_start..];
        if let Some(suffix_start) = after_prefix.find(".txt") {
            let claim_id = &after_prefix[..suffix_start];
            if is_claim_path_id(claim_id) {
                output.push_str(claim_id);
                rest = &after_prefix[suffix_start + ".txt".len()..];
                continue;
            }
        }
        output.push_str("/claims/");
        rest = &rest[path_start..];
    }
    output.push_str(rest);
    output
}

fn is_claim_path_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn claim_evidence_block(fixture: &FixtureVault, claim_ids: &[String]) -> Result<String, String> {
    let by_id = fixture
        .claims
        .iter()
        .map(|claim| (claim.claim_id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();
    let mut evidence = String::new();
    for claim_id in claim_ids {
        let claim = by_id
            .get(claim_id.as_str())
            .ok_or_else(|| format!("missing fixture claim `{claim_id}`"))?;
        evidence.push_str(&format!("- {}: {}\n", claim.claim_id, claim.text));
    }
    Ok(evidence)
}

fn final_browse_accuracy(rubric_mean: f64, citation_score: f64) -> f64 {
    rubric_mean
        .clamp(0.0, 1.0)
        .min(citation_score.clamp(0.0, 1.0))
}

fn rubric_score(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or(1.0)
        .clamp(1.0, 5.0)
}

fn extract_claim_ids(answer: &str) -> BTreeSet<String> {
    answer
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .filter(|token| token.starts_with("claim-") && token.len() == "claim-0000".len())
        .map(ToOwned::to_owned)
        .collect()
}

fn set_f1(actual: &BTreeSet<String>, expected: &BTreeSet<String>) -> f64 {
    if actual.is_empty() && expected.is_empty() {
        return 1.0;
    }
    if actual.is_empty() || expected.is_empty() {
        return 0.0;
    }
    let true_positive = actual.intersection(expected).count() as f64;
    if true_positive == 0.0 {
        return 0.0;
    }
    let precision = true_positive / actual.len() as f64;
    let recall = true_positive / expected.len() as f64;
    2.0 * precision * recall / (precision + recall)
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn aggregate_rows(rows: &[SmokeRunRow]) -> Vec<ArmAggregate> {
    ArmId::ALL
        .into_iter()
        .map(|arm| {
            let arm_rows = rows.iter().filter(|row| row.arm == arm).collect::<Vec<_>>();
            let runs = arm_rows.len();
            let tokens_total = arm_rows.iter().map(|row| row.tokens_total).sum::<u32>();
            let mean_accuracy = mean(arm_rows.iter().map(|row| row.accuracy));
            let mean_tool_calls = mean(arm_rows.iter().map(|row| f64::from(row.tool_calls)));
            let mean_wall_clock_s = mean(arm_rows.iter().map(|row| row.wall_clock_s));
            let accuracy_per_class = TaskClass::ALL
                .into_iter()
                .map(|class| {
                    let class_accuracy = mean(
                        arm_rows
                            .iter()
                            .filter(|row| row.class == class)
                            .map(|row| row.accuracy),
                    );
                    (class.as_str().to_owned(), class_accuracy)
                })
                .collect();
            ArmAggregate {
                arm,
                runs,
                mean_accuracy,
                tokens_total,
                mean_tool_calls,
                mean_wall_clock_s,
                accuracy_per_class,
            }
        })
        .collect()
}

fn full_run_report(
    bundle: &TaskBundle,
    rows: Vec<SmokeRunRow>,
    settings: &RunSettings,
) -> FullRunReport {
    let aggregates = aggregate_rows(&rows);
    let class_arm_table = class_arm_table(&rows, settings.full_reps);
    let pareto_frontier = pareto_frontier(&aggregates);
    let arm_verdict_claims = arm_verdict_claims(&aggregates, &pareto_frontier);
    let falsification_verdict = falsification_verdict(&rows);
    let budget = budget_summary(&rows, settings.full_token_ceiling());
    FullRunReport {
        campaign: CAMPAIGN_ID.to_owned(),
        model: settings.model.clone(),
        provider: settings.provider_lock(),
        run_id: format!("interface-bench-1-full-{}", unix_now()),
        task_count: bundle.full_tasks.len(),
        reps_per_task_arm: settings.full_reps,
        expected_runs: settings.full_run_count(),
        completed_runs: rows.len(),
        scorer_version: SCORER_VERSION.to_owned(),
        browse_judge_prompt_version: BROWSE_JUDGE_PROMPT_VERSION.to_owned(),
        runs: rows,
        aggregates,
        class_arm_table,
        pareto_frontier,
        arm_verdict_claims,
        falsification_verdict,
        budget,
    }
}

fn class_arm_table(rows: &[SmokeRunRow], reps: u32) -> Vec<ClassArmSummary> {
    let mut table = Vec::new();
    for class in TaskClass::ALL {
        for arm in ArmId::ALL {
            let class_arm_rows = rows
                .iter()
                .filter(|row| row.class == class && row.arm == arm)
                .collect::<Vec<_>>();
            let accuracy_by_rep = rep_values(&class_arm_rows, reps, |rep_rows| {
                mean(rep_rows.iter().map(|row| row.accuracy))
            });
            let tokens_by_row = class_arm_rows
                .iter()
                .map(|row| f64::from(row.tokens_total))
                .collect::<Vec<_>>();
            table.push(ClassArmSummary {
                class: class.as_str().to_owned(),
                arm,
                runs: class_arm_rows.len(),
                reps,
                accuracy_mean: mean(accuracy_by_rep.iter().copied()),
                accuracy_range: numeric_range(&accuracy_by_rep),
                tokens_mean: mean(tokens_by_row.iter().copied()),
                tokens_range: numeric_range(&tokens_by_row).round() as u32,
                tool_calls_mean: mean(class_arm_rows.iter().map(|row| f64::from(row.tool_calls))),
                wall_clock_mean_s: mean(class_arm_rows.iter().map(|row| row.wall_clock_s)),
            });
        }
    }
    table
}

fn rep_values(
    rows: &[&SmokeRunRow],
    reps: u32,
    value_for_rep: impl Fn(&[&SmokeRunRow]) -> f64,
) -> Vec<f64> {
    (0..reps)
        .map(|rep_index| {
            let rep_rows = rows
                .iter()
                .copied()
                .filter(|row| row.rep_index == rep_index)
                .collect::<Vec<_>>();
            value_for_rep(&rep_rows)
        })
        .collect()
}

fn numeric_range(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    max - min
}

fn pareto_frontier(aggregates: &[ArmAggregate]) -> Vec<ParetoPoint> {
    aggregates
        .iter()
        .map(|candidate| {
            let dominated = aggregates.iter().any(|other| {
                other.arm != candidate.arm
                    && other.mean_accuracy >= candidate.mean_accuracy
                    && other.tokens_total <= candidate.tokens_total
                    && (other.mean_accuracy > candidate.mean_accuracy
                        || other.tokens_total < candidate.tokens_total)
            });
            ParetoPoint {
                arm: candidate.arm,
                mean_accuracy: candidate.mean_accuracy,
                tokens_total: candidate.tokens_total,
                dominated,
            }
        })
        .collect()
}

fn arm_verdict_claims(
    aggregates: &[ArmAggregate],
    pareto_points: &[ParetoPoint],
) -> Vec<ArmVerdictClaim> {
    ArmId::ALL
        .into_iter()
        .filter_map(|arm| {
            let aggregate = aggregates.iter().find(|aggregate| aggregate.arm == arm)?;
            let pareto_dominated = pareto_points
                .iter()
                .find(|point| point.arm == arm)
                .map(|point| point.dominated)
                .unwrap_or(false);
            let claim_id = format!("{}-{}-verdict", CAMPAIGN_ID, arm.as_str());
            let claim = format!(
                "{} achieved mean accuracy {:.4} with {} total tokens and is {} on the accuracy/token Pareto frontier.",
                arm.as_str(),
                aggregate.mean_accuracy,
                aggregate.tokens_total,
                if pareto_dominated { "dominated" } else { "not dominated" }
            );
            let mut evidence = Vec::with_capacity(2 + aggregate.accuracy_per_class.len());
            evidence.push(format!("runs={}", aggregate.runs));
            evidence.push(format!(
                "meanToolCalls={:.4}",
                aggregate.mean_tool_calls
            ));
            for (class, accuracy) in &aggregate.accuracy_per_class {
                evidence.push(format!("{class}.accuracy={accuracy:.4}"));
            }
            Some(ArmVerdictClaim {
                band: "Proposed".to_owned(),
                arm,
                claim_id,
                claim,
                mean_accuracy: aggregate.mean_accuracy,
                tokens_total: aggregate.tokens_total,
                pareto_dominated,
                evidence,
            })
        })
        .collect()
}

fn falsification_verdict(rows: &[SmokeRunRow]) -> FalsificationVerdict {
    let class = TaskClass::RetrievalQa;
    let fs_rows = rows
        .iter()
        .filter(|row| row.class == class && row.arm == ArmId::Fs)
        .collect::<Vec<_>>();
    let sdk_rows = rows
        .iter()
        .filter(|row| row.class == class && row.arm == ArmId::Sdk)
        .collect::<Vec<_>>();
    let arm_fs_accuracy = mean(fs_rows.iter().map(|row| row.accuracy));
    let arm_sdk_accuracy = mean(sdk_rows.iter().map(|row| row.accuracy));
    let arm_fs_tokens = fs_rows.iter().map(|row| row.tokens_total).sum::<u32>();
    let arm_sdk_tokens = sdk_rows.iter().map(|row| row.tokens_total).sum::<u32>();
    let token_ratio = if arm_sdk_tokens == 0 {
        f64::INFINITY
    } else {
        f64::from(arm_fs_tokens) / f64::from(arm_sdk_tokens)
    };
    let matches_accuracy = arm_fs_accuracy >= arm_sdk_accuracy;
    let within_token_bound = token_ratio <= 1.5;
    FalsificationVerdict {
        band: "Proposed".to_owned(),
        class: class.as_str().to_owned(),
        arm_fs_accuracy,
        arm_sdk_accuracy,
        arm_fs_tokens,
        arm_sdk_tokens,
        token_ratio,
        matches_accuracy,
        within_token_bound,
        falsifies_sdk_necessity_premise: matches_accuracy && within_token_bound,
    }
}

fn budget_summary(rows: &[SmokeRunRow], run_token_ceiling: u32) -> BudgetSummary {
    BudgetSummary {
        per_task_token_ceiling: PER_TASK_TOKEN_CEILING,
        run_token_ceiling,
        tokens_total: rows.iter().map(|row| row.tokens_total).sum(),
        max_row_tokens: rows.iter().map(|row| row.tokens_total).max().unwrap_or(0),
    }
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let mut count = 0_u32;
    let mut sum = 0.0;
    for value in values {
        count += 1;
        sum += value;
    }
    if count == 0 {
        0.0
    } else {
        sum / f64::from(count)
    }
}

fn token_burn_extrapolation(rows: &[SmokeRunRow], full_reps: u32) -> TokenBurnExtrapolation {
    let smoke_tokens = rows.iter().map(|row| row.tokens_total).sum::<u32>();
    let observed_runs = rows.len();
    let full_run_equivalent_runs = FULL_TASK_COUNT * ArmId::ALL.len() * full_reps as usize;
    let extrapolated_full_tokens = if observed_runs == 0 {
        0
    } else {
        let projected =
            (u64::from(smoke_tokens) * full_run_equivalent_runs as u64) / observed_runs as u64;
        u32::try_from(projected).unwrap_or(u32::MAX)
    };
    TokenBurnExtrapolation {
        smoke_tokens,
        full_run_equivalent_runs,
        observed_runs,
        extrapolated_full_tokens,
    }
}

fn fixture_claim(fixture: &FixtureVault, person_index: usize, topic_index: usize) -> &FixtureClaim {
    &fixture.claims[person_index * TOPIC_COUNT + topic_index]
}

fn claim_id_for(person_index: usize, topic_index: usize) -> String {
    format!("claim-{:04}", person_index * TOPIC_COUNT + topic_index)
}

fn topic_id(index: usize) -> String {
    format!("topic-{index:03}")
}

fn topic_name(index: usize) -> String {
    format!("topic-{index:03}-interface-memory")
}

fn person_id(index: usize) -> String {
    format!("person-{index:02}")
}

fn person_name(index: usize) -> String {
    format!("Person {index:02}")
}

fn object_id(index: usize) -> String {
    format!("artifact-{index:02}")
}

fn object_name(index: usize) -> String {
    format!("artifact notebook {index:02}")
}

fn organization_id(index: usize) -> String {
    format!("org-{:02}", index % 10)
}

fn organization_name(index: usize) -> String {
    format!("Organization {:02}", index % 10)
}

fn source_ref(person_index: usize, topic_index: usize) -> String {
    format!("source-{:02}", (person_index * 3 + topic_index) % 17)
}

fn learned_at(person_index: usize, topic_index: usize) -> u64 {
    1_767_225_600 + ((topic_index * PERSON_COUNT + person_index) as u64 * 3_600)
}

fn stance_for(person_index: usize, topic_index: usize) -> String {
    STANCES[(person_index * 17 + topic_index * 31) % STANCES.len()].to_owned()
}

fn superseded_by_for(person_index: usize, topic_index: usize) -> Option<String> {
    (topic_index.is_multiple_of(25) && topic_index + 1 < TOPIC_COUNT)
        .then(|| claim_id_for(person_index, topic_index + 1))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_row(
        task_id: &str,
        class: TaskClass,
        arm: ArmId,
        rep_index: u32,
        tokens_total: u32,
        accuracy: f64,
    ) -> SmokeRunRow {
        SmokeRunRow {
            task_id: task_id.to_owned(),
            class,
            arm,
            rep_index,
            memo_key: "memo".to_owned(),
            request_hash: "request".to_owned(),
            request_nonce: "nonce".to_owned(),
            generation_id: Some("gen-1".to_owned()),
            judge_generation_id: None,
            accuracy,
            tokens_total,
            tool_calls: 1,
            wall_clock_s: 1.0,
            answer: String::new(),
            score_detail: json!({}),
        }
    }

    #[test]
    fn task_generation_matches_campaign_shape() {
        let bundle = build_task_bundle();
        assert_eq!(bundle.fixture.claims.len(), CLAIM_COUNT);
        assert_eq!(bundle.full_tasks.len(), FULL_TASK_COUNT);
        assert_eq!(bundle.smoke_tasks.len(), SMOKE_TASK_COUNT);
        assert_eq!(bundle.spotcheck.len(), OWNER_SPOTCHECK_COUNT);

        let mut counts = BTreeMap::new();
        let mut holdout_counts = BTreeMap::new();
        for task in &bundle.full_tasks {
            *counts.entry(task.class).or_insert(0) += 1;
            if task.holdout {
                *holdout_counts.entry(task.class).or_insert(0) += 1;
            }
        }
        assert_eq!(counts.get(&TaskClass::RetrievalQa), Some(&30));
        assert_eq!(counts.get(&TaskClass::MultiHop), Some(&20));
        assert_eq!(counts.get(&TaskClass::Provenance), Some(&20));
        assert_eq!(counts.get(&TaskClass::BrowseThenAnswer), Some(&10));
        assert_eq!(holdout_counts.get(&TaskClass::RetrievalQa), Some(&6));
        assert_eq!(holdout_counts.get(&TaskClass::MultiHop), Some(&4));
        assert_eq!(holdout_counts.get(&TaskClass::Provenance), Some(&4));
        assert_eq!(holdout_counts.get(&TaskClass::BrowseThenAnswer), Some(&2));
    }

    #[test]
    fn config_locks_openrouter_wandb_without_fallbacks() {
        let defaults = RunSettings::default();
        assert_eq!(defaults.model, MODEL);
        assert_eq!(defaults.provider, DEFAULT_PROVIDER);
        assert_eq!(defaults.full_reps, FULL_REP_COUNT);
        assert_eq!(defaults.full_token_ceiling(), FULL_TOKEN_CEILING);

        let config = interface_bench_1_config();
        assert_eq!(config.campaign, CAMPAIGN_ID);
        assert_eq!(config.nodes, ArmId::ALL);
        assert_eq!(config.model_binding.model, MODEL);
        assert_eq!(config.model_binding.browse_judge_model, MODEL);
        assert_eq!(
            config.model_binding.route.provider.order,
            vec!["wandb".to_owned()]
        );
        assert!(!config.model_binding.route.provider.allow_fallbacks);
        assert_eq!(config.budget_lease.tool_call_cap, TOOL_CALL_CAP);
        assert_eq!(config.budget_lease.smoke_token_ceiling, SMOKE_TOKEN_CEILING);
        assert_eq!(config.budget_lease.full_token_ceiling, FULL_TOKEN_CEILING);
    }

    #[test]
    fn campaign_config_records_model_provider_and_budget_overrides() {
        let settings = RunSettings {
            model: "example/alt-model".to_owned(),
            provider: "groq".to_owned(),
            full_reps: 1,
        };
        let config = campaign_config_for(&settings);
        assert_eq!(config.model_binding.model, "example/alt-model");
        assert_eq!(config.model_binding.browse_judge_model, "example/alt-model");
        assert_eq!(
            config.model_binding.route.provider.order,
            vec!["groq".to_owned()]
        );
        assert!(!config.model_binding.route.provider.allow_fallbacks);
        assert_eq!(
            config.budget_lease.full_token_ceiling,
            FULL_TOKEN_CEILING / 2
        );
    }

    #[test]
    fn generated_gold_labels_are_backed_by_fixture_claims() {
        let bundle = build_task_bundle();
        let claim_ids = bundle
            .fixture
            .claims
            .iter()
            .map(|claim| claim.claim_id.clone())
            .collect::<BTreeSet<_>>();
        for task in &bundle.full_tasks {
            assert!(task.generation.verified_by_construction);
            for claim_id in &task.supporting_claim_ids {
                assert!(claim_ids.contains(claim_id), "missing {claim_id}");
            }
        }
    }

    #[test]
    fn browse_accuracy_is_gated_by_citation_precheck() {
        assert_eq!(final_browse_accuracy(1.0, 0.0), 0.0);
        assert_eq!(final_browse_accuracy(0.8, 0.5), 0.5);
        assert_eq!(final_browse_accuracy(0.4, 0.9), 0.4);
    }

    #[test]
    fn fs_tool_calls_match_transcript_commands() {
        let bundle = build_task_bundle();
        let task = &bundle.smoke_tasks[0];
        let fs = fs_context(task, &bundle.fixture, false).expect("fs context");
        let hybrid = fs_context(task, &bundle.fixture, true).expect("hybrid context");

        assert_eq!(fs.tool_calls, 2);
        assert_eq!(fs.tool_calls, transcript_tool_calls(&fs.transcript));
        assert_eq!(hybrid.tool_calls, 2);
        assert_eq!(hybrid.tool_calls, transcript_tool_calls(&hybrid.transcript));
    }

    #[test]
    fn retrieval_context_exposes_full_generated_gold_set() {
        let bundle = build_task_bundle();
        let task = bundle
            .smoke_tasks
            .iter()
            .find(|task| task.class == TaskClass::RetrievalQa)
            .expect("retrieval smoke task");
        let GoldLabel::RetrievalQa { relevant_claim_ids } = &task.gold else {
            unreachable!("retrieval task has retrieval gold");
        };
        let claims = context_claims(task, &bundle.fixture).expect("context claims");
        let transcript = fs_context(task, &bundle.fixture, false)
            .expect("fs context")
            .transcript;

        assert_eq!(claims.len(), relevant_claim_ids.len());
        assert!(relevant_claim_ids.iter().all(|id| transcript.contains(id)));
    }

    #[test]
    fn full_run_shape_is_exactly_480_rows() {
        let defaults = RunSettings::default();
        assert_eq!(defaults.full_run_count(), 480);
        assert_eq!(
            defaults.full_run_count(),
            FULL_TASK_COUNT * ArmId::ALL.len() * FULL_REP_COUNT as usize
        );
    }

    #[test]
    fn memo_key_and_request_hash_are_rep_distinct() {
        let bundle = build_task_bundle();
        let task = &bundle.full_tasks[0];
        let arm = ArmId::Sdk;
        let context = arm_context(arm, task, &bundle.fixture).expect("context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let settings = RunSettings::default();
        let nonce_0 = request_nonce(task, arm, 0);
        let nonce_1 = request_nonce(task, arm, 1);
        let request_hash_0 = blake3_hex(
            openrouter_request_body(&messages, 900, &nonce_0, &settings)
                .to_string()
                .as_bytes(),
        );
        let request_hash_1 = blake3_hex(
            openrouter_request_body(&messages, 900, &nonce_1, &settings)
                .to_string()
                .as_bytes(),
        );
        let memo_key_0 = eval_memo_key(
            task,
            arm,
            0,
            &nonce_0,
            &request_hash_0,
            judge_cache_key(task).as_deref(),
        );
        let memo_key_1 = eval_memo_key(
            task,
            arm,
            1,
            &nonce_1,
            &request_hash_1,
            judge_cache_key(task).as_deref(),
        );

        assert_ne!(nonce_0, nonce_1);
        assert_ne!(request_hash_0, request_hash_1);
        assert_ne!(memo_key_0, memo_key_1);
    }

    #[test]
    fn parse_run_flags_defaults_reproduce_pinned_campaign() {
        let (out_dir, settings) = parse_run_flags(&[]).expect("defaults parse");
        assert_eq!(out_dir, PathBuf::from(DEFAULT_OUT_DIR));
        assert_eq!(settings.model, MODEL);
        assert_eq!(settings.provider, DEFAULT_PROVIDER);
        assert_eq!(settings.full_reps, FULL_REP_COUNT);
        assert_eq!(settings.full_run_count(), 480);
        assert_eq!(settings.full_token_ceiling(), FULL_TOKEN_CEILING);
    }

    #[test]
    fn parse_run_flags_accepts_model_provider_and_reps_overrides() {
        let args = [
            "--out",
            "custom-out",
            "--model",
            "example/alt-model",
            "--provider",
            "groq",
            "--reps",
            "1",
        ]
        .map(String::from);
        let (out_dir, settings) = parse_run_flags(&args).expect("overrides parse");
        assert_eq!(out_dir, PathBuf::from("custom-out"));
        assert_eq!(settings.model, "example/alt-model");
        assert_eq!(settings.provider, "groq");
        assert_eq!(settings.full_reps, 1);
        assert_eq!(settings.full_run_count(), 240);
        assert_eq!(settings.full_token_ceiling(), FULL_TOKEN_CEILING / 2);
    }

    #[test]
    fn parse_run_flags_rejects_invalid_flags() {
        assert!(parse_run_flags(&["--reps".to_owned(), "0".to_owned()]).is_err());
        assert!(parse_run_flags(&["--reps".to_owned(), "two".to_owned()]).is_err());
        assert!(parse_run_flags(&["--reps".to_owned()]).is_err());
        assert!(parse_run_flags(&["--model".to_owned()]).is_err());
        assert!(parse_run_flags(&["--model".to_owned(), String::new()]).is_err());
        assert!(parse_run_flags(&["--provider".to_owned(), String::new()]).is_err());
        assert!(parse_run_flags(&["--bogus".to_owned()]).is_err());
    }

    #[test]
    fn taskgen_flags_stay_out_dir_only() {
        assert!(parse_out_dir(&["--model".to_owned(), "example/alt-model".to_owned()]).is_err());
    }

    #[test]
    fn default_request_body_is_byte_identical_to_pinned_campaign() {
        let messages = vec![chat_message("system", "pinned prompt".to_owned())];
        let body = openrouter_request_body(&messages, 900, "nonce", &RunSettings::default());
        let pinned = json!({
            "model": "z-ai/glm-5.2",
            "messages": messages,
            "temperature": REQUEST_TEMPERATURE,
            "max_tokens": 900,
            "provider": {
                "order": ["wandb"],
                "allow_fallbacks": false
            },
            "user": "nonce"
        });

        assert_eq!(body.to_string(), pinned.to_string());
        assert_eq!(
            blake3_hex(body.to_string().as_bytes()),
            blake3_hex(pinned.to_string().as_bytes())
        );
    }

    #[test]
    fn provider_override_keeps_fallbacks_disabled() {
        let settings = RunSettings {
            provider: "groq".to_owned(),
            ..RunSettings::default()
        };
        let lock = settings.provider_lock();
        assert_eq!(lock.order, vec!["groq".to_owned()]);
        assert!(!lock.allow_fallbacks);

        let body = openrouter_request_body(&[], 900, "nonce", &settings);
        assert_eq!(body["provider"]["order"], json!(["groq"]));
        assert_eq!(body["provider"]["allow_fallbacks"], json!(false));
    }

    #[test]
    fn memo_key_separates_model_and_provider_overrides() {
        let bundle = build_task_bundle();
        let task = &bundle.full_tasks[0];
        let arm = ArmId::Sdk;
        let context = arm_context(arm, task, &bundle.fixture).expect("context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let nonce = request_nonce(task, arm, 0);
        let memo_key_for = |settings: &RunSettings| {
            let request_hash = blake3_hex(
                openrouter_request_body(&messages, 900, &nonce, settings)
                    .to_string()
                    .as_bytes(),
            );
            eval_memo_key(
                task,
                arm,
                0,
                &nonce,
                &request_hash,
                judge_cache_key(task).as_deref(),
            )
        };

        let default_key = memo_key_for(&RunSettings::default());
        let model_key = memo_key_for(&RunSettings {
            model: "example/alt-model".to_owned(),
            ..RunSettings::default()
        });
        let provider_key = memo_key_for(&RunSettings {
            provider: "groq".to_owned(),
            ..RunSettings::default()
        });

        assert_ne!(default_key, model_key);
        assert_ne!(default_key, provider_key);
        assert_ne!(model_key, provider_key);
    }

    #[test]
    fn full_report_records_effective_model_provider_and_reps() {
        let bundle = build_task_bundle();
        let settings = RunSettings {
            model: "example/alt-model".to_owned(),
            provider: "groq".to_owned(),
            full_reps: 1,
        };
        let rows = vec![test_row(
            "task",
            TaskClass::RetrievalQa,
            ArmId::Sdk,
            0,
            100,
            0.8,
        )];
        let report = full_run_report(&bundle, rows, &settings);

        assert_eq!(report.model, "example/alt-model");
        assert_eq!(report.provider.order, vec!["groq".to_owned()]);
        assert!(!report.provider.allow_fallbacks);
        assert_eq!(report.reps_per_task_arm, 1);
        assert_eq!(report.expected_runs, 240);
        assert_eq!(report.budget.run_token_ceiling, FULL_TOKEN_CEILING / 2);
        assert!(
            report
                .class_arm_table
                .iter()
                .all(|summary| summary.reps == 1)
        );
    }

    #[test]
    fn browse_memo_key_includes_judge_prompt_version() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::BrowseThenAnswer)
            .expect("browse task");
        let arm = ArmId::Fs;
        let context = arm_context(arm, task, &bundle.fixture).expect("context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let nonce = request_nonce(task, arm, 0);
        let request_hash = blake3_hex(
            openrouter_request_body(&messages, 900, &nonce, &RunSettings::default())
                .to_string()
                .as_bytes(),
        );

        assert_eq!(
            judge_cache_key(task).as_deref(),
            Some(BROWSE_JUDGE_PROMPT_VERSION)
        );
        assert_ne!(
            eval_memo_key(task, arm, 0, &nonce, &request_hash, None),
            eval_memo_key(
                task,
                arm,
                0,
                &nonce,
                &request_hash,
                judge_cache_key(task).as_deref(),
            )
        );
    }

    #[test]
    fn non_browse_memo_key_omits_judge_prompt_version() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::RetrievalQa)
            .expect("retrieval task");
        let arm = ArmId::Sdk;
        let context = arm_context(arm, task, &bundle.fixture).expect("context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let nonce = request_nonce(task, arm, 0);
        let request_hash = blake3_hex(
            openrouter_request_body(&messages, 900, &nonce, &RunSettings::default())
                .to_string()
                .as_bytes(),
        );

        assert_eq!(judge_cache_key(task), None);
        assert_eq!(
            eval_memo_key(task, arm, 0, &nonce, &request_hash, None),
            eval_memo_key(
                task,
                arm,
                0,
                &nonce,
                &request_hash,
                judge_cache_key(task).as_deref(),
            )
        );
    }

    #[test]
    fn browse_context_exposes_all_required_gold_claims() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::BrowseThenAnswer)
            .expect("browse task");
        let GoldLabel::BrowseThenAnswer {
            required_claim_ids, ..
        } = &task.gold
        else {
            unreachable!("browse task has browse gold");
        };
        let claims = context_claims(task, &bundle.fixture).expect("context claims");

        assert_eq!(claims.len(), required_claim_ids.len());
        assert_eq!(claims.len(), 10);
    }

    #[test]
    fn fs_context_exposes_changed_after_for_provenance_rows() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| {
                matches!(
                    &task.gold,
                    GoldLabel::Provenance { field, .. } if field == "changed_after"
                )
            })
            .expect("changed_after provenance task");
        let transcript = fs_context(task, &bundle.fixture, false)
            .expect("fs context")
            .transcript;

        assert!(transcript.contains("changed_after:"));
    }

    #[test]
    fn sdk_retrieval_context_reports_real_tool_calls_under_cap() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::RetrievalQa)
            .expect("retrieval task");
        let context = sdk_context(task, &bundle.fixture).expect("sdk context");

        assert_eq!(context.tool_calls, 1);
        assert!(context.tool_calls <= TOOL_CALL_CAP);
    }

    #[test]
    fn blind_judge_answer_normalizes_claim_paths() {
        let answer = "See /claims/claim-0001.txt and claim-0002.";
        let normalized = blind_judge_answer(answer);

        assert!(normalized.contains("claim-0001"));
        assert!(!normalized.contains("/claims/claim-0001.txt"));
    }

    #[test]
    fn blind_judge_answer_normalizes_punctuated_claim_paths() {
        let answer =
            "See (/claims/claim-0001.txt), /claims/claim_0002.txt. and [/claims/claim-0003.txt];";
        let normalized = blind_judge_answer(answer);

        assert_eq!(
            normalized,
            "See (claim-0001), claim_0002. and [claim-0003];"
        );
        assert!(!normalized.contains("/claims/"));
    }

    #[test]
    fn validate_loaded_row_rejects_class_mismatch() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::RetrievalQa)
            .expect("retrieval task");
        let row = test_row(&task.task_id, TaskClass::MultiHop, ArmId::Sdk, 0, 10, 1.0);

        let error = validate_loaded_row(&row, task, ArmId::Sdk, 0, "memo", "request", "nonce")
            .expect_err("class mismatch should reject cached row");
        assert!(error.contains("memo row mismatch"));
    }

    #[test]
    fn class_arm_table_reports_row_level_token_mean() {
        let rows = vec![
            test_row("a", TaskClass::RetrievalQa, ArmId::Sdk, 0, 10, 1.0),
            test_row("b", TaskClass::RetrievalQa, ArmId::Sdk, 0, 30, 0.8),
            test_row("c", TaskClass::RetrievalQa, ArmId::Sdk, 1, 50, 0.6),
            test_row("d", TaskClass::RetrievalQa, ArmId::Sdk, 1, 70, 0.4),
        ];
        let table = class_arm_table(&rows, FULL_REP_COUNT);
        let summary = table
            .iter()
            .find(|row| row.class == TaskClass::RetrievalQa.as_str() && row.arm == ArmId::Sdk)
            .expect("retrieval sdk summary");

        assert_eq!(summary.runs, 4);
        assert_eq!(summary.tokens_mean, 40.0);
        assert_eq!(summary.tokens_range, 60);
    }

    #[test]
    fn full_report_emits_proposed_verdict_claim_for_each_arm() {
        let bundle = build_task_bundle();
        let rows = vec![
            test_row("sdk", TaskClass::RetrievalQa, ArmId::Sdk, 0, 100, 0.8),
            test_row("fs", TaskClass::RetrievalQa, ArmId::Fs, 0, 120, 0.8),
            test_row("hybrid", TaskClass::RetrievalQa, ArmId::Hybrid, 0, 110, 0.9),
        ];
        let report = full_run_report(&bundle, rows, &RunSettings::default());
        let arms = report
            .arm_verdict_claims
            .iter()
            .map(|claim| claim.arm)
            .collect::<BTreeSet<_>>();

        assert_eq!(report.arm_verdict_claims.len(), 3);
        assert_eq!(arms, ArmId::ALL.into_iter().collect::<BTreeSet<_>>());
        assert!(
            report.arm_verdict_claims.iter().all(
                |claim| claim.band == "Proposed" && claim.claim_id.contains(claim.arm.as_str())
            )
        );
    }

    #[test]
    fn generated_task_gold_payload_uses_camel_case_fields() {
        let bundle = build_task_bundle();
        let task = &bundle.full_tasks[0];
        let value = serde_json::to_value(task).expect("serialize task");
        let gold = value
            .get("gold")
            .and_then(Value::as_object)
            .expect("gold object");

        assert!(gold.contains_key("relevantClaimIds"));
        assert!(!gold.contains_key("relevant_claim_ids"));
    }

    #[test]
    fn token_extrapolation_targets_owner_authorized_480_run_full_campaign() {
        let rows = vec![test_row(
            "task",
            TaskClass::RetrievalQa,
            ArmId::Sdk,
            0,
            10,
            1.0,
        )];
        let extrapolation = token_burn_extrapolation(&rows, FULL_REP_COUNT);

        assert_eq!(extrapolation.full_run_equivalent_runs, 480);
        assert_eq!(extrapolation.extrapolated_full_tokens, 4_800);

        let single_rep = token_burn_extrapolation(&rows, 1);
        assert_eq!(single_rep.full_run_equivalent_runs, 240);
        assert_eq!(single_rep.extrapolated_full_tokens, 2_400);
    }

    #[test]
    fn taskgen_writes_expected_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let report = write_taskgen_outputs(temp.path(), &RunSettings::default()).expect("taskgen");
        assert_eq!(report.generated_claims, CLAIM_COUNT);
        for name in [
            "campaign_config.json",
            "fixture_vault.json",
            "tasks_full.json",
            "tasks_smoke.json",
            "holdout_freeze.json",
            "owner_spotcheck_sample.json",
            "taskgen_report.json",
        ] {
            assert!(temp.path().join(name).exists(), "missing {name}");
        }
    }
}
