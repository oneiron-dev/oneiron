//! Subcommand dispatch and pinned-model config parsing.

use super::config_types::{
    ArmId, BudgetLeaseConfig, CAMPAIGN_ID, CLAIM_COUNT, CampaignConfig, DEFAULT_OUT_DIR,
    DEFAULT_PROVIDER, DETERMINISTIC_SEED, DecideConfig, EvalCorpusConfig, FIXTURE_ID,
    FULL_REP_COUNT, FULL_TASK_COUNT, HoldoutPolicy, KIND, MAX_FULL_REPS, MODEL, MetricSet,
    ModelBinding, PER_TASK_TOKEN_CEILING, ProviderRoute, RunSettings, RunnerConfig,
    SMOKE_TASK_COUNT, SMOKE_TOKEN_CEILING, TOOL_CALL_CAP, WALL_CLOCK_CAP_S,
};
use super::eval_run::{run_full, run_memo_probe, run_smoke};
use super::taskgen::write_taskgen_outputs;
use super::wire_and_scoring::blake3_hex;
use oneiron::{ModelId, PinnedModelConfig, llm::ModelIdError};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
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
           --reps N               reps per task+arm for full runs, 1..={MAX_FULL_REPS}\n\
                                  (default {FULL_REP_COUNT}; probe always runs 2 reps)\n\
           --pinned-config PATH   pinned model config JSON; refuses the run before any\n\
                                  provider call unless exactly one pinned revision\n\
                                  covers the transmitted model. Rows written under a\n\
                                  pin record it and are never reused by another pin\n\
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

/// Wire shape of a pinned model config file: `{"allowed":[...],
/// "background_tier_enabled":bool}`. Entries are fully revisioned
/// `provider/name@revision` ids. The engine type carries no JSON concern, so
/// this DTO and its parse error stay in the bench crate.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PinnedModelConfigJson {
    pub(super) allowed: Vec<String>,
    pub(super) background_tier_enabled: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PinnedConfigParseError {
    #[error("pinned model config JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("allowed[{index}] is not a valid model id `{value}`: {source}")]
    InvalidModelId {
        index: usize,
        value: String,
        #[source]
        source: ModelIdError,
    },
    #[error("allowed[{index}] duplicates pinned model `{model}`")]
    Duplicate { index: usize, model: ModelId },
}

/// Parses a pinned model config file into the engine-owned
/// [`PinnedModelConfig`]. Every entry is validated through `ModelId::new`, and
/// a repeated entry is a typed `Duplicate` failure rather than a silent set
/// deduplication. An empty `allowed` array is valid and admits nothing.
pub(crate) fn parse_pinned_model_config(
    json: &str,
) -> Result<PinnedModelConfig, PinnedConfigParseError> {
    let parsed: PinnedModelConfigJson = serde_json::from_str(json)?;
    let mut allowed = BTreeSet::new();
    for (index, value) in parsed.allowed.into_iter().enumerate() {
        let model = ModelId::new(value.clone()).map_err(|source| {
            PinnedConfigParseError::InvalidModelId {
                index,
                value,
                source,
            }
        })?;
        if !allowed.insert(model.clone()) {
            return Err(PinnedConfigParseError::Duplicate { index, model });
        }
    }
    Ok(PinnedModelConfig {
        allowed,
        background_tier_enabled: parsed.background_tier_enabled,
    })
}

/// Why a transmitted wire id is not covered by the pin file. Both variants are
/// refusals: a pinned run NEVER falls back to transmitting unpinned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PinnedCoverageError {
    #[error("pinned config does not cover transmitted model `{wire_id}`; pinned ids: [{pinned}]")]
    NotCovered { wire_id: String, pinned: String },
    #[error(
        "pinned config covers transmitted model `{wire_id}` at more than one revision \
         ([{revisions}]); the revision actually served is not wire-attested"
    )]
    AmbiguousRevision { wire_id: String, revisions: String },
}

/// Resolves the wire id the bench actually transmits to THE ONE fully
/// revisioned pinned entry that covers it — the identity every pinned row is
/// attested and keyed by.
///
/// * a wire id that already carries `@revision` must equal a pinned entry
///   exactly, so a revision mismatch refuses rather than matching on the
///   unrevised `provider/name` pair;
/// * a bare `provider/name` wire id resolves only when EXACTLY ONE pinned
///   revision covers it. Two candidate revisions are ambiguous and refuse:
///   the revision the provider would serve is operator-asserted, not
///   wire-attested, so the bench must not guess which pin a row claims.
pub(super) fn pinned_model_for_wire_id(
    config: &PinnedModelConfig,
    wire_id: &str,
) -> Result<ModelId, PinnedCoverageError> {
    let pinned_ids = || {
        config
            .allowed
            .iter()
            .map(ModelId::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    if wire_id.contains('@') {
        return config
            .allowed
            .iter()
            .find(|model| model.as_str() == wire_id)
            .cloned()
            .ok_or_else(|| PinnedCoverageError::NotCovered {
                wire_id: wire_id.to_owned(),
                pinned: pinned_ids(),
            });
    }
    let candidates = config
        .allowed
        .iter()
        .filter(|model| format!("{}/{}", model.provider(), model.name()) == wire_id)
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [] => Err(PinnedCoverageError::NotCovered {
            wire_id: wire_id.to_owned(),
            pinned: pinned_ids(),
        }),
        [single] => Ok((*single).clone()),
        many => Err(PinnedCoverageError::AmbiguousRevision {
            wire_id: wire_id.to_owned(),
            revisions: many
                .iter()
                .map(|model| model.revision())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

/// A run launched under `--pinned-config`: the parsed policy plus the fully
/// revisioned pinned entry every wire id this run transmits resolves to.
/// Coverage is resolved ONCE, at flag-parse time, and every transmitted body
/// is re-checked against this map before it leaves the process.
#[derive(Debug, Clone)]
pub(super) struct PinnedRun {
    pub(super) config: PinnedModelConfig,
    pub(super) wire_models: BTreeMap<String, ModelId>,
}

impl PinnedRun {
    /// Deterministic digest of the admission policy this run was launched
    /// under: the sorted fully revisioned allow-list plus the background-tier
    /// switch. Recorded on every row so a reader can tell two runs under
    /// different pin files apart even when they pin the same revision.
    pub(super) fn config_digest(&self) -> String {
        let allowed = self
            .config
            .allowed
            .iter()
            .map(ModelId::as_str)
            .collect::<Vec<_>>();
        blake3_hex(
            json!({
                "allowed": allowed,
                "backgroundTierEnabled": self.config.background_tier_enabled,
            })
            .to_string()
            .as_bytes(),
        )
    }

    /// The pin a transmitted wire id resolves to, or None when this run's pin
    /// file does not cover it (always a refusal at the call site).
    pub(super) fn attestation_for(&self, wire_id: &str) -> Option<PinnedAttestation> {
        self.wire_models
            .get(wire_id)
            .map(|model| PinnedAttestation {
                model: model.as_str().to_owned(),
                config_digest: self.config_digest(),
            })
    }
}

/// The pin a single transmitted request rides under, recorded verbatim on the
/// row it produces: the fully revisioned pinned id covering the wire model the
/// body carries, plus the digest of the pin file that admitted it. A reader of
/// a row can therefore verify WHICH pinned revision that row claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PinnedAttestation {
    pub(super) model: String,
    pub(super) config_digest: String,
}

pub(super) fn parse_out_dir(args: &[String]) -> Result<PathBuf, String> {
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

pub(super) fn parse_run_flags(args: &[String]) -> Result<(PathBuf, RunSettings), String> {
    let mut out_dir = None;
    let mut settings = RunSettings::default();
    let mut pinned_config_path: Option<PathBuf> = None;
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
                if !(1..=MAX_FULL_REPS).contains(&reps) {
                    return Err(format!("--reps must be between 1 and {MAX_FULL_REPS}"));
                }
                settings.full_reps = reps;
                index += 2;
            }
            "--pinned-config" => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "--pinned-config requires a file path".to_owned())?;
                pinned_config_path = Some(PathBuf::from(value));
                index += 2;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }

    // Resolved AFTER the flag loop so a later `--model` is honored by the
    // coverage check. With the flag absent nothing below runs and behavior is
    // byte-identical to an unpinned run.
    if let Some(path) = pinned_config_path {
        let pinned = resolve_pinned_run(&path, &settings)?;
        settings.pinned = Some(pinned);
    }

    Ok((
        out_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_OUT_DIR)),
        settings,
    ))
}

/// Reads `--pinned-config`, parses it, and resolves the pinned revision for
/// every wire id this run would actually transmit. An uncovered or
/// ambiguously-revisioned model refuses the run before any provider call is
/// made; on success the run carries the exact revision each transmit is
/// attested under.
fn resolve_pinned_run(path: &Path, settings: &RunSettings) -> Result<PinnedRun, String> {
    let json = fs::read_to_string(path).map_err(|error| {
        format!(
            "--pinned-config {} could not be read: {error}",
            path.display()
        )
    })?;
    let config = parse_pinned_model_config(&json)
        .map_err(|error| format!("--pinned-config {}: {error}", path.display()))?;

    // The configured wire-id set is exactly what the bench transmits:
    // `settings.model` populates both `ModelBinding.model` and
    // `browse_judge_model`, and both enter the set should they ever diverge.
    let binding = campaign_config_for(settings).model_binding;
    let wire_ids = BTreeSet::from([binding.model, binding.browse_judge_model]);
    let mut wire_models = BTreeMap::new();
    for wire_id in wire_ids {
        let model = pinned_model_for_wire_id(&config, &wire_id)
            .map_err(|error| format!("--pinned-config {}: {error}", path.display()))?;
        wire_models.insert(wire_id, model);
    }
    Ok(PinnedRun {
        config,
        wire_models,
    })
}

pub(super) fn interface_bench_1_config() -> CampaignConfig {
    campaign_config_for(&RunSettings::default())
}

pub(super) fn campaign_config_for(settings: &RunSettings) -> CampaignConfig {
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
