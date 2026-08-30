//! ONE-218 eval-side driver for the telemetry-v0 retrieval-outcome loop.
//!
//! * `eval outcome-ingest` applies evaluator-supplied rewards read from JSONL
//!   to already-finalized retrieval runs via `Vault::record_retrieval_outcome`.
//! * `eval tune` runs one explicit bounded retrieval-blend tuning step via
//!   `Vault::tune_retrieval_blend_weights` and prints the weight table entry
//!   it persisted for live scoring to read.
//!
//! Both subcommands are explicit CLI invocations: no timer, no cadence and no
//! automatic trigger drives them. Rewards are never inferred — a row without
//! an evaluator-supplied finite reward and `evaluator`/`source` provenance is
//! refused before any vault call. Turn and session attribution rides the
//! outcome metadata verbatim and is never fabricated here.
//!
//! Both vault wrappers open their own write transaction and refuse to run
//! inside an active one, so this module opens the vault once and calls them at
//! transaction depth 0, never holding a transaction across a call.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oneiron::store::{RetrievalBlendTuningConfig, RetrievalOutcome};
use oneiron::{RetrievalRunId, Vault, VaultConfig};
use serde::{Deserialize, Serialize};

const EVAL_OUTCOME_INGEST_CONTRACT_VERSION: &str = "oneiron.eval_outcome_ingest.v1";
const EVAL_OUTCOME_INGEST_RECORD_TYPE: &str = "eval_outcome_ingest";
const METADATA_EVALUATOR_KEY: &str = "evaluator";
const METADATA_SOURCE_KEY: &str = "source";
const RUN_ID_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub(crate) enum EvalError {
    #[error("eval usage requested")]
    HelpRequested,
    #[error("missing required eval argument: {0}")]
    MissingArgument(&'static str),
    #[error("invalid eval argument `{0}`")]
    InvalidArgument(String),
    #[error("reward row {row} rejected after {applied} applied row(s): {reason}")]
    RewardRow {
        row: usize,
        applied: usize,
        reason: String,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("oneiron engine error: {0}")]
    Oneiron(#[from] oneiron::Error),
}

type EvalResult<T> = Result<T, EvalError>;

#[derive(Debug, PartialEq, Eq)]
struct OutcomeIngestArgs {
    vault_path: PathBuf,
    /// `None` reads the reward rows from stdin (`--rewards -`).
    rewards_path: Option<PathBuf>,
    key: Option<String>,
}

#[derive(Debug, PartialEq)]
struct TuneArgs {
    vault_path: PathBuf,
    config: RetrievalBlendTuningConfig,
}

/// One evaluator-supplied reward row. `reward` and `accepted` are explicit:
/// a row that omits either is refused rather than defaulted.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RewardRow {
    run_id: String,
    reward: f32,
    accepted: bool,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OutcomeIngestSummary {
    contract_version: String,
    record_type: String,
    ingested: usize,
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        [sub, rest @ ..] if sub == "outcome-ingest" => report(run_outcome_ingest(rest)),
        [sub, rest @ ..] if sub == "tune" => report(run_tune(rest)),
        [sub, ..] => {
            eprintln!("unknown eval subcommand: {sub}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn report(result: EvalResult<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(EvalError::HelpRequested) => {
            print_help();
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("eval command failed: {error}");
            if matches!(
                error,
                EvalError::MissingArgument(_) | EvalError::InvalidArgument(_)
            ) {
                print_help();
            }
            ExitCode::FAILURE
        }
    }
}

fn run_outcome_ingest(args: &[String]) -> EvalResult<()> {
    let args = parse_outcome_ingest_args(args)?;
    let vault = open_existing_vault(&args.vault_path)?;
    let ingested = match &args.rewards_path {
        Some(path) => ingest_outcomes(
            &vault,
            BufReader::new(File::open(path)?),
            args.key.as_deref(),
        )?,
        None => ingest_outcomes(&vault, std::io::stdin().lock(), args.key.as_deref())?,
    };

    let summary = OutcomeIngestSummary {
        contract_version: EVAL_OUTCOME_INGEST_CONTRACT_VERSION.to_owned(),
        record_type: EVAL_OUTCOME_INGEST_RECORD_TYPE.to_owned(),
        ingested,
    };
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    write_json_line(&summary, &mut lock)
}

fn run_tune(args: &[String]) -> EvalResult<()> {
    let args = parse_tune_args(args)?;
    let vault = open_existing_vault(&args.vault_path)?;
    let entry = vault.tune_retrieval_blend_weights(args.config)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    write_json_line(&entry, &mut lock)
}

/// Applies reward rows in file order, stopping at the first rejected row.
///
/// Rows already applied stay applied: they are honest, retryable state — the
/// outcome write is idempotent per run id and key — and the returned error
/// names the failing row plus how many rows preceded it.
fn ingest_outcomes(
    vault: &Vault,
    reader: impl BufRead,
    default_key: Option<&str>,
) -> EvalResult<usize> {
    let mut applied = 0_usize;
    for (index, line) in reader.lines().enumerate() {
        match apply_reward_line(vault, line, default_key) {
            Ok(true) => applied += 1,
            Ok(false) => {}
            Err(reason) => {
                return Err(EvalError::RewardRow {
                    row: index + 1,
                    applied,
                    reason,
                });
            }
        }
    }
    Ok(applied)
}

/// Applies one JSONL line, reporting `false` for a blank separator line.
fn apply_reward_line(
    vault: &Vault,
    line: std::io::Result<String>,
    default_key: Option<&str>,
) -> Result<bool, String> {
    let line = line.map_err(|error| error.to_string())?;
    if line.trim().is_empty() {
        return Ok(false);
    }
    let row: RewardRow = serde_json::from_str(&line).map_err(|error| error.to_string())?;
    let outcome = outcome_from_row(&row, default_key)?;
    vault
        .record_retrieval_outcome(outcome)
        .map_err(|error| error.to_string())?;
    Ok(true)
}

/// Vets one row's evaluator-supplied reward and provenance before it can
/// reach the vault.
fn outcome_from_row(
    row: &RewardRow,
    default_key: Option<&str>,
) -> Result<RetrievalOutcome, String> {
    if !row.reward.is_finite() {
        return Err("reward must be a finite evaluator scalar".to_owned());
    }
    require_provenance(&row.metadata, METADATA_EVALUATOR_KEY)?;
    require_provenance(&row.metadata, METADATA_SOURCE_KEY)?;
    let key = resolve_outcome_key(row.key.as_deref(), default_key)?;
    let run_id = parse_run_id(&row.run_id)?;
    Ok(RetrievalOutcome {
        run_id,
        key,
        reward: Some(row.reward),
        accepted: Some(row.accepted),
        metadata: row.metadata.clone(),
    })
}

fn require_provenance(metadata: &BTreeMap<String, String>, field: &str) -> Result<(), String> {
    match metadata.get(field) {
        Some(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(format!("metadata.{field} must be a non-empty string")),
    }
}

/// A per-row `key` overrides `--key`; exactly one key source must resolve.
fn resolve_outcome_key(row_key: Option<&str>, default_key: Option<&str>) -> Result<String, String> {
    match row_key.or(default_key) {
        Some(key) if !key.trim().is_empty() => Ok(key.to_owned()),
        Some(_) => Err("outcome key must not be empty".to_owned()),
        None => Err("no outcome key: supply a row `key` or --key".to_owned()),
    }
}

/// `RetrievalRunId` publishes no byte constructor, so its derived
/// `Deserialize` is the supported route from a hex run id back to the id.
fn parse_run_id(value: &str) -> Result<RetrievalRunId, String> {
    let bytes = parse_run_id_bytes(value)?;
    serde_json::from_value(serde_json::json!({ "bytes": bytes }))
        .map_err(|error| format!("run_id could not be decoded: {error}"))
}

fn parse_run_id_bytes(value: &str) -> Result<[u8; RUN_ID_LEN], String> {
    let raw = value.as_bytes();
    let expected = RUN_ID_LEN * 2;
    if raw.len() != expected {
        return Err(format!("run_id must be {expected} hex characters"));
    }

    let mut bytes = [0_u8; RUN_ID_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = decode_hex_nibble(raw[index * 2])?;
        let low = decode_hex_nibble(raw[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("run_id contains a non-hex character".to_owned()),
    }
}

fn open_existing_vault(path: &Path) -> EvalResult<Vault> {
    if !path.exists() {
        return Err(EvalError::InvalidArgument(format!(
            "--vault path does not exist: {}",
            path.display()
        )));
    }
    Ok(Vault::open(path, VaultConfig::device())?)
}

fn write_json_line<T: Serialize>(value: &T, writer: &mut impl Write) -> EvalResult<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn parse_outcome_ingest_args(args: &[String]) -> EvalResult<OutcomeIngestArgs> {
    if help_requested(args) {
        return Err(EvalError::HelpRequested);
    }

    let mut vault_path = None;
    let mut rewards = None;
    let mut key = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--vault" => {
                let value = required_value(args, index, "--vault")?;
                vault_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--rewards" => {
                let value = required_value(args, index, "--rewards")?;
                rewards = Some((value != "-").then(|| PathBuf::from(value)));
                index += 2;
            }
            "--key" => {
                let value = required_value(args, index, "--key")?;
                if value.trim().is_empty() {
                    return Err(EvalError::InvalidArgument(
                        "--key must not be empty".to_owned(),
                    ));
                }
                key = Some(value.to_owned());
                index += 2;
            }
            other => return Err(EvalError::InvalidArgument(other.to_owned())),
        }
    }

    Ok(OutcomeIngestArgs {
        vault_path: vault_path.ok_or(EvalError::MissingArgument("--vault"))?,
        rewards_path: rewards.ok_or(EvalError::MissingArgument("--rewards"))?,
        key,
    })
}

fn parse_tune_args(args: &[String]) -> EvalResult<TuneArgs> {
    if help_requested(args) {
        return Err(EvalError::HelpRequested);
    }

    let mut vault_path = None;
    let mut max_runs = None;
    let mut learning_rate = None;
    let mut min_reward_count = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--vault" => {
                let value = required_value(args, index, "--vault")?;
                vault_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--max-runs" => {
                let value = required_value(args, index, "--max-runs")?;
                max_runs = Some(parse_count(value, "--max-runs")?);
                index += 2;
            }
            "--learning-rate" => {
                let value = required_value(args, index, "--learning-rate")?;
                let rate = value.parse::<f32>().map_err(|_| {
                    EvalError::InvalidArgument(format!(
                        "--learning-rate expects a number, got `{value}`"
                    ))
                })?;
                learning_rate = Some(rate);
                index += 2;
            }
            "--min-reward-count" => {
                let value = required_value(args, index, "--min-reward-count")?;
                min_reward_count = Some(parse_count(value, "--min-reward-count")?);
                index += 2;
            }
            other => return Err(EvalError::InvalidArgument(other.to_owned())),
        }
    }

    // Flags map 1:1 onto the tuning config; unset ones keep the shipped
    // bounded defaults.
    let defaults = RetrievalBlendTuningConfig::default();
    Ok(TuneArgs {
        vault_path: vault_path.ok_or(EvalError::MissingArgument("--vault"))?,
        config: RetrievalBlendTuningConfig {
            max_runs: max_runs.unwrap_or(defaults.max_runs),
            learning_rate: learning_rate.unwrap_or(defaults.learning_rate),
            min_reward_count: min_reward_count.unwrap_or(defaults.min_reward_count),
        },
    })
}

fn parse_count(value: &str, flag: &'static str) -> EvalResult<usize> {
    value.parse::<usize>().map_err(|_| {
        EvalError::InvalidArgument(format!("{flag} expects an integer, got `{value}`"))
    })
}

fn help_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &'static str) -> EvalResult<&'a str> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .ok_or(EvalError::MissingArgument(flag))
}

fn print_help() {
    println!(
        "usage: oneiron-bench eval <subcommand> [flags]\n\
         \n\
         Drives the telemetry-v0 retrieval-outcome loop from the eval side.\n\
         Both subcommands are explicit invocations: nothing here runs on a\n\
         timer, a cadence, or a wake hook.\n\
         \n\
         subcommands:\n\
           outcome-ingest --vault <PATH> --rewards <PATH>|- [--key <KEY>]\n\
             Applies evaluator-supplied rewards to already-finalized retrieval\n\
             runs, one JSON object per line, in file order. A row carries\n\
             run_id (hex), reward (a finite number), accepted (a bool), an\n\
             optional key that overrides --key, and a metadata object whose\n\
             evaluator and source entries are required; optional turn_id and\n\
             session_id metadata is stored verbatim. Rewards are never\n\
             inferred. Ingest stops at the first rejected row, naming that row\n\
             and the rows already applied, and exits nonzero; success prints\n\
             one JSON summary carrying the ingested count.\n\
           tune --vault <PATH> [--max-runs N] [--learning-rate F] [--min-reward-count N]\n\
             Runs one bounded retrieval-blend tuning step over the persisted\n\
             rewards and prints the weight table entry it persisted."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::store::{RetrievalBlendWeightTableEntry, RetrievalOutcomeRecord};
    use oneiron::{EntityId, TimeRange};
    use std::io::Cursor;

    /// RET-010c recency half-life for `ENTITY_TYPE_SUMMARY`. The second
    /// fixture entity is aged by exactly one half-life so the recency blend
    /// column is non-degenerate and the tuner sees blend-signal components.
    const HALF_LIFE_DAYS: f32 = 90.0;
    const HALF_LIFE_SECS: u64 = 90 * 86_400;
    const PROVENANCE: &[(&str, &str)] = &[("evaluator", "judge.v1"), ("source", "beam.eval")];

    fn unix_now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_secs()
    }

    fn open_vault(path: &Path) -> Vault {
        Vault::open(path, VaultConfig::device()).expect("vault opens")
    }

    fn put_text(vault: &Vault, text: &str, learned_at: u64) {
        let id = EntityId::now();
        vault
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_SUMMARY,
                TimeRange { start: 1, end: 1 },
                learned_at,
                b"payload",
            )
            .text(&id, &[("body", text)])
            .commit()
            .expect("fixture text");
    }

    /// Mints `count` finalized pipeline retrieval runs that carry blend-signal
    /// score components, and returns their run ids.
    fn seed_retrieval_runs(vault: &Vault, count: usize) -> Vec<RetrievalRunId> {
        let now = unix_now_secs();
        put_text(vault, "eval fixture alpha", now);
        put_text(vault, "eval fixture beta", now - HALF_LIFE_SECS);

        let mut run_ids = Vec::with_capacity(count);
        for _ in 0..count {
            let results = vault
                .query()
                .search_text("eval fixture", 10)
                .boost_recency(HALF_LIFE_DAYS)
                .with_temporal_now(now)
                .run_with_telemetry()
                .expect("fixture retrieval");
            assert_eq!(results.value.len(), 2);
            run_ids.push(results.run_id.expect("telemetry run id"));
        }
        run_ids
    }

    fn reward_row(run_id: RetrievalRunId, metadata: &[(&str, &str)]) -> RewardRow {
        let mut fields = BTreeMap::new();
        for (key, value) in metadata {
            fields.insert((*key).to_owned(), (*value).to_owned());
        }
        RewardRow {
            run_id: run_id.to_hex(),
            reward: 0.75,
            accepted: true,
            key: None,
            metadata: fields,
        }
    }

    fn jsonl(rows: &[RewardRow]) -> String {
        let mut lines = Vec::with_capacity(rows.len());
        for row in rows {
            lines.push(serde_json::to_string(row).expect("row json"));
        }
        lines.join("\n")
    }

    fn ingest(vault: &Vault, rows: &str, default_key: Option<&str>) -> EvalResult<usize> {
        ingest_outcomes(vault, Cursor::new(rows.as_bytes()), default_key)
    }

    fn rejected_row(error: EvalError) -> (usize, usize, String) {
        match error {
            EvalError::RewardRow {
                row,
                applied,
                reason,
            } => (row, applied, reason),
            other => panic!("expected a rejected reward row, got {other}"),
        }
    }

    fn metadata_of<'a>(record: &'a RetrievalOutcomeRecord, field: &str) -> Option<&'a str> {
        record.metadata.get(field).map(String::as_str)
    }

    #[test]
    fn eval_outcome_ingest_applies_evaluator_reward_with_provenance_metadata() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = open_vault(tempdir.path());
        let run_id = seed_retrieval_runs(&vault, 1)[0];
        let mut metadata = PROVENANCE.to_vec();
        metadata.push(("turn_id", "turn-7"));
        metadata.push(("session_id", "session-3"));
        let rows = jsonl(&[reward_row(run_id, &metadata)]);

        let ingested = ingest(&vault, &rows, Some("beam.reward")).expect("ingest");

        assert_eq!(ingested, 1);
        let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
        assert_eq!(outcomes.len(), 1);
        let outcome = &outcomes[0];
        assert_eq!(outcome.key, "beam.reward");
        assert_eq!(outcome.reward, Some(0.75));
        assert_eq!(outcome.accepted, Some(true));
        assert_eq!(metadata_of(outcome, "evaluator"), Some("judge.v1"));
        assert_eq!(metadata_of(outcome, "source"), Some("beam.eval"));
        assert_eq!(metadata_of(outcome, "turn_id"), Some("turn-7"));
        assert_eq!(metadata_of(outcome, "session_id"), Some("session-3"));
    }

    #[test]
    fn eval_outcome_ingest_refuses_rows_without_provenance_before_any_vault_write() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = open_vault(tempdir.path());
        let run_id = seed_retrieval_runs(&vault, 1)[0];

        for metadata in [
            vec![("source", "beam.eval")],
            vec![("evaluator", "judge.v1")],
            vec![("evaluator", " "), ("source", "beam.eval")],
        ] {
            let rows = jsonl(&[reward_row(run_id, &metadata)]);
            let result = ingest(&vault, &rows, Some("beam.reward"));
            let (row, applied, reason) = rejected_row(result.expect_err("refused"));
            assert_eq!(row, 1);
            assert_eq!(applied, 0);
            assert!(reason.contains("must be a non-empty"), "{reason}");
        }

        let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
        assert!(outcomes.is_empty());
    }

    #[test]
    fn eval_outcome_ingest_refuses_a_non_finite_reward_before_any_vault_write() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = open_vault(tempdir.path());
        let run_id = seed_retrieval_runs(&vault, 1)[0];
        let hex = run_id.to_hex();
        let metadata = r#""metadata":{"evaluator":"judge.v1","source":"beam.eval"}"#;
        let rows = format!(r#"{{"run_id":"{hex}","reward":1e40,"accepted":true,{metadata}}}"#);

        let result = ingest(&vault, &rows, Some("beam.reward"));

        let (row, applied, reason) = rejected_row(result.expect_err("refused"));
        assert_eq!(row, 1);
        assert_eq!(applied, 0);
        assert!(reason.contains("finite"), "{reason}");
        let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
        assert!(outcomes.is_empty());
    }

    #[test]
    fn eval_outcome_ingest_needs_a_key_source_and_lets_the_row_override_it() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = open_vault(tempdir.path());
        let run_id = seed_retrieval_runs(&vault, 1)[0];
        let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);

        let result = ingest(&vault, &rows, None);

        let (row, applied, reason) = rejected_row(result.expect_err("refused"));
        assert_eq!(row, 1);
        assert_eq!(applied, 0);
        assert!(reason.contains("no outcome key"), "{reason}");

        let mut overriding = reward_row(run_id, PROVENANCE);
        overriding.key = Some("row.reward".to_owned());
        let rows = jsonl(&[overriding]);
        let ingested = ingest(&vault, &rows, Some("flag.reward")).expect("ingest");
        assert_eq!(ingested, 1);
        let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].key, "row.reward");
    }

    #[test]
    fn eval_outcome_ingest_stops_at_the_first_rejected_row_and_keeps_earlier_rows() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = open_vault(tempdir.path());
        let run_id = seed_retrieval_runs(&vault, 1)[0];
        let rows = jsonl(&[
            reward_row(run_id, PROVENANCE),
            reward_row(RetrievalRunId::now(), PROVENANCE),
            reward_row(run_id, PROVENANCE),
        ]);

        let result = ingest(&vault, &rows, Some("beam.reward"));

        let (row, applied, reason) = rejected_row(result.expect_err("refused"));
        assert_eq!(row, 2);
        assert_eq!(applied, 1);
        assert!(reason.contains("unknown run id"), "{reason}");
        let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
        assert_eq!(outcomes.len(), 1);
    }

    #[test]
    fn eval_outcome_ingest_applies_a_jsonl_file_against_the_named_vault() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = open_vault(tempdir.path());
        let run_id = seed_retrieval_runs(&vault, 1)[0];
        drop(vault);
        let rewards_path = tempdir.path().join("rewards.jsonl");
        let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
        std::fs::write(&rewards_path, rows).expect("rewards file");

        let exit = run(&[
            "outcome-ingest".to_owned(),
            "--vault".to_owned(),
            tempdir.path().display().to_string(),
            "--rewards".to_owned(),
            rewards_path.display().to_string(),
            "--key".to_owned(),
            "beam.reward".to_owned(),
        ]);

        assert!(matches!(exit, ExitCode::SUCCESS));
        let vault = open_vault(tempdir.path());
        let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].reward, Some(0.75));
    }

    #[test]
    fn eval_outcome_ingest_summary_is_one_json_line_with_the_ingested_count() {
        let summary = OutcomeIngestSummary {
            contract_version: EVAL_OUTCOME_INGEST_CONTRACT_VERSION.to_owned(),
            record_type: EVAL_OUTCOME_INGEST_RECORD_TYPE.to_owned(),
            ingested: 3,
        };
        let mut written = Vec::new();

        write_json_line(&summary, &mut written).expect("summary writes");

        let text = std::str::from_utf8(&written).expect("summary utf8");
        let mut lines = text.lines();
        let line = lines.next().expect("one summary line");
        let decoded: OutcomeIngestSummary = serde_json::from_str(line).expect("summary json");
        assert!(lines.next().is_none());
        assert_eq!(decoded, summary);
    }

    #[test]
    fn eval_outcome_ingest_parses_the_stdin_and_key_flags() {
        let args = parse_outcome_ingest_args(&[
            "--vault".to_owned(),
            "/tmp/oneiron-vault".to_owned(),
            "--rewards".to_owned(),
            "-".to_owned(),
            "--key".to_owned(),
            "beam.reward".to_owned(),
        ])
        .expect("args parse");

        assert_eq!(
            args,
            OutcomeIngestArgs {
                vault_path: PathBuf::from("/tmp/oneiron-vault"),
                rewards_path: None,
                key: Some("beam.reward".to_owned()),
            }
        );
        let only_vault = ["--vault".to_owned(), "/tmp/oneiron-vault".to_owned()];
        let error = parse_outcome_ingest_args(&only_vault).expect_err("rewards required");
        assert!(matches!(error, EvalError::MissingArgument("--rewards")));
    }

    #[test]
    fn eval_tune_persists_and_prints_the_bounded_weight_table_entry() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = open_vault(tempdir.path());
        let run_id = seed_retrieval_runs(&vault, 1)[0];
        let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
        let ingested = ingest(&vault, &rows, Some("beam.reward")).expect("ingest");
        assert_eq!(ingested, 1);
        let before = vault.retrieval_blend_weight_table().expect("table");
        drop(vault);

        let exit = run(&[
            "tune".to_owned(),
            "--vault".to_owned(),
            tempdir.path().display().to_string(),
            "--max-runs".to_owned(),
            "8".to_owned(),
            "--learning-rate".to_owned(),
            "0.10".to_owned(),
            "--min-reward-count".to_owned(),
            "1".to_owned(),
        ]);

        assert!(matches!(exit, ExitCode::SUCCESS));
        let vault = open_vault(tempdir.path());
        let tuned = vault.retrieval_blend_weight_table().expect("table");
        assert_ne!(tuned.weights, before.weights);
        assert_eq!(tuned.data_window.run_count, 1);
        assert_eq!(tuned.data_window.outcome_count, 1);
        let max_runs = tuned.provenance.get("max_runs").map(String::as_str);
        assert_eq!(max_runs, Some("8"));
    }

    #[test]
    fn eval_tune_honors_the_max_runs_bound() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = open_vault(tempdir.path());
        let run_ids = seed_retrieval_runs(&vault, 2);
        let mut rows = Vec::with_capacity(run_ids.len());
        for run_id in &run_ids {
            rows.push(reward_row(*run_id, PROVENANCE));
        }
        let ingested = ingest(&vault, &jsonl(&rows), Some("beam.reward")).expect("ingest");
        assert_eq!(ingested, 2);
        drop(vault);

        let exit = run(&[
            "tune".to_owned(),
            "--vault".to_owned(),
            tempdir.path().display().to_string(),
            "--max-runs".to_owned(),
            "1".to_owned(),
        ]);

        assert!(matches!(exit, ExitCode::SUCCESS));
        let vault = open_vault(tempdir.path());
        let tuned = vault.retrieval_blend_weight_table().expect("table");
        assert_eq!(tuned.data_window.run_count, 1);
        assert_eq!(tuned.data_window.outcome_count, 1);
    }

    #[test]
    fn eval_tune_maps_the_bounded_flags_onto_the_tuning_config() {
        let args = parse_tune_args(&[
            "--vault".to_owned(),
            "/tmp/oneiron-vault".to_owned(),
            "--max-runs".to_owned(),
            "32".to_owned(),
            "--learning-rate".to_owned(),
            "0.25".to_owned(),
            "--min-reward-count".to_owned(),
            "4".to_owned(),
        ])
        .expect("args parse");

        assert_eq!(
            args,
            TuneArgs {
                vault_path: PathBuf::from("/tmp/oneiron-vault"),
                config: RetrievalBlendTuningConfig {
                    max_runs: 32,
                    learning_rate: 0.25,
                    min_reward_count: 4,
                },
            }
        );
        let only_vault = ["--vault".to_owned(), "/tmp/oneiron-vault".to_owned()];
        let defaults = parse_tune_args(&only_vault).expect("args parse");
        assert_eq!(defaults.config, RetrievalBlendTuningConfig::default());
    }

    #[test]
    fn eval_tune_prints_the_returned_weight_table_entry() {
        let entry = RetrievalBlendWeightTableEntry::bootstrap();
        let mut written = Vec::new();

        write_json_line(&entry, &mut written).expect("entry writes");

        let text = std::str::from_utf8(&written).expect("entry utf8");
        let mut lines = text.lines();
        let line = lines.next().expect("one entry line");
        let decoded: RetrievalBlendWeightTableEntry =
            serde_json::from_str(line).expect("entry json");
        assert!(lines.next().is_none());
        assert_eq!(decoded, entry);
    }
}
