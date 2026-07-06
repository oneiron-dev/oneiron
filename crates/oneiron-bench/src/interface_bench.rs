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
const TOOL_CALL_CAP: u32 = 25;
const WALL_CLOCK_CAP_S: u32 = 600;
const PER_TASK_TOKEN_CEILING: u32 = 10_000;
const SMOKE_TOKEN_CEILING: u32 = 250_000;
const FULL_TOKEN_CEILING: u32 = 5_000_000;
const MODEL: &str = "z-ai/glm-5.2";
const OPENROUTER_CHAT_COMPLETIONS: &str = "https://openrouter.ai/api/v1/chat/completions";

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
    RetrievalQa { relevant_claim_ids: Vec<String> },
    #[serde(rename = "multi-hop")]
    MultiHop {
        exact_answer: String,
        supporting_ids: Vec<String>,
    },
    #[serde(rename = "provenance")]
    Provenance {
        field: String,
        value: String,
        supporting_ids: Vec<String>,
    },
    #[serde(rename = "browse-then-answer")]
    BrowseThenAnswer {
        topic: String,
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
struct SmokeRunRow {
    task_id: String,
    class: TaskClass,
    arm: ArmId,
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
           smoke [--out DIR]      run the 8-task x 3-arm smoke through OpenRouter\n\
                                  using OPENROUTER_API_KEY and W&B-only routing\n\
         \n\
         default output dir: target/interface-bench/interface-bench-1"
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
    match parse_out_dir(args).and_then(|out| write_taskgen_outputs(&out)) {
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
    match parse_out_dir(args).and_then(|out| run_smoke(&out)) {
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

    Ok(out_dir.unwrap_or_else(|| PathBuf::from("target/interface-bench/interface-bench-1")))
}

fn interface_bench_1_config() -> CampaignConfig {
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
            full_token_ceiling: FULL_TOKEN_CEILING,
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
            model: MODEL.to_owned(),
            route: ProviderRoute {
                provider: locked_provider(),
            },
            browse_judge_model: MODEL.to_owned(),
        },
    }
}

fn locked_provider() -> ProviderLock {
    ProviderLock {
        order: vec!["wandb".to_owned()],
        allow_fallbacks: false,
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
                "When did we learn what {} thinks about {}?",
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

fn write_taskgen_outputs(out_dir: &Path) -> Result<TaskgenReport, String> {
    let bundle = build_task_bundle();
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

fn run_smoke(out_dir: &Path) -> Result<PathBuf, String> {
    let api_key = std::env::var("OPENROUTER_API_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "OPENROUTER_API_KEY is not present; smoke not run".to_owned())?;
    fs::create_dir_all(out_dir).map_err(|error| format!("create output dir: {error}"))?;

    let bundle = build_task_bundle();
    let mut rows = Vec::with_capacity(SMOKE_TASK_COUNT * ArmId::ALL.len());
    for task in &bundle.smoke_tasks {
        for arm in ArmId::ALL {
            let context = arm_context(arm, task, &bundle.fixture)?;
            let started = Instant::now();
            let response = call_openrouter(
                &api_key,
                &[
                    chat_message("system", shared_system_prompt(arm)),
                    chat_message("user", smoke_user_prompt(task, &context)),
                ],
                900,
            )?;
            let wall_clock_s = started.elapsed().as_secs_f64();
            let (accuracy, detail) = score_task(task, &response.content);
            let (accuracy, detail) = if task.class == TaskClass::BrowseThenAnswer {
                judge_browse_answer(&api_key, task, &response.content, accuracy, detail)?
            } else {
                (accuracy, detail)
            };
            rows.push(SmokeRunRow {
                task_id: task.task_id.clone(),
                class: task.class,
                arm,
                accuracy,
                tokens_total: response.tokens_total,
                tool_calls: context.tool_calls,
                wall_clock_s,
                answer: response.content,
                score_detail: detail,
            });
        }
    }

    let report = SmokeReport {
        campaign: CAMPAIGN_ID.to_owned(),
        model: MODEL.to_owned(),
        provider: locked_provider(),
        run_id: format!("interface-bench-1-smoke-{}", unix_now()),
        task_count: bundle.smoke_tasks.len(),
        aggregates: aggregate_rows(&rows),
        full_run_token_burn_extrapolation: token_burn_extrapolation(&rows),
        runs: rows,
    };
    let report_path = out_dir.join("smoke_report.json");
    write_json(&report_path, &report)?;
    Ok(report_path)
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

fn smoke_user_prompt(task: &BenchTask, context: &ArmContext) -> String {
    format!(
        "{}\n\nSmoke harness interface transcript ({} tool calls):\n{}\n\nReturn a concise final answer with citations.",
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
    transcript.push_str("\nget(claim_id) samples:\n");
    for claim in &claims {
        transcript.push_str(&format!("{}: {}\n", claim.claim_id, claim.text));
        transcript.push_str(&format!(
            "  provenance: source_ref={} learned_at_epoch_s={} changed_after={}\n",
            claim.source_ref, claim.learned_at_epoch_s, claim.provenance.changed_after
        ));
    }
    Ok(ArmContext {
        tool_calls: (1 + claims.len() as u32).min(TOOL_CALL_CAP),
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
            "== /claims/{}.txt ==\nid: {}\ntopic: {}\nsource: {}\nlearned_at_epoch_s: {}\nrelations: owner_of={}, employed_by={}\ntext: {}\n",
            claim.claim_id,
            claim.claim_id,
            claim.topic,
            claim.source_ref,
            claim.learned_at_epoch_s,
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
        GoldLabel::RetrievalQa { relevant_claim_ids } => relevant_claim_ids.iter().take(8),
        GoldLabel::MultiHop { supporting_ids, .. }
        | GoldLabel::Provenance { supporting_ids, .. } => supporting_ids.iter().take(8),
        GoldLabel::BrowseThenAnswer {
            required_claim_ids, ..
        } => required_claim_ids.iter().take(8),
    };
    let by_id = fixture
        .claims
        .iter()
        .map(|claim| (claim.claim_id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();
    ids.map(|id| {
        by_id
            .get(id.as_str())
            .copied()
            .ok_or_else(|| format!("missing fixture claim `{id}`"))
    })
    .collect()
}

fn call_openrouter(
    api_key: &str,
    messages: &[Value],
    max_tokens: u32,
) -> Result<ChatResponse, String> {
    if api_key.contains(['\r', '\n']) {
        return Err("OPENROUTER_API_KEY contains unsupported newline characters".to_owned());
    }
    let request = json!({
        "model": MODEL,
        "messages": messages,
        "temperature": 0,
        "max_tokens": max_tokens,
        "provider": {
            "order": ["wandb"],
            "allow_fallbacks": false
        }
    });
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
            "OpenRouter W&B-locked request failed: status={} stderr={} body={}",
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
    Ok(ChatResponse {
        content,
        tokens_total,
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

fn judge_browse_answer(
    api_key: &str,
    task: &BenchTask,
    answer: &str,
    citation_score: f64,
    citation_detail: Value,
) -> Result<(f64, Value), String> {
    let GoldLabel::BrowseThenAnswer { topic, rubric, .. } = &task.gold else {
        return Ok((citation_score, citation_detail));
    };
    let judge_prompt = format!(
        "Grade this answer on a blind 1-5 rubric. The arm identity is hidden.\n\
         Task topic: {topic}\n\
         Rubric coverage: {}\n\
         Rubric faithfulness: {}\n\
         Rubric citation validity: {}\n\
         Return JSON only: {{\"coverage\":1-5,\"faithfulness\":1-5,\"citation_validity\":1-5,\"notes\":\"short\"}}\n\n\
         Answer:\n{answer}",
        rubric.coverage, rubric.faithfulness, rubric.citation_validity
    );
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
    Ok((
        final_accuracy,
        json!({
            "browse_rubric": parsed,
            "rubric_normalized_score": mean,
            "citation_score": citation_score,
            "normalized_score": final_accuracy,
            "combiner": "min(rubric_normalized_score,citation_score)",
            "citation_precheck": citation_detail
        }),
    ))
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

fn token_burn_extrapolation(rows: &[SmokeRunRow]) -> TokenBurnExtrapolation {
    let smoke_tokens = rows.iter().map(|row| row.tokens_total).sum::<u32>();
    let observed_runs = rows.len();
    let full_run_equivalent_runs = 480;
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
        let config = interface_bench_1_config();
        assert_eq!(config.campaign, CAMPAIGN_ID);
        assert_eq!(config.nodes, ArmId::ALL);
        assert_eq!(config.model_binding.model, MODEL);
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
    fn taskgen_writes_expected_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let report = write_taskgen_outputs(temp.path()).expect("taskgen");
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
