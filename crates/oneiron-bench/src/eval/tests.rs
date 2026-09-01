use super::*;
use oneiron::store::{RetrievalBlendWeightTableEntry, RetrievalOutcomeRecord};
use oneiron::{EntityId, TimeRange};
use std::io::Cursor;
use std::path::Path;

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

fn open_vault_with(path: &Path, config: VaultConfig) -> Vault {
    Vault::open(path, config).expect("vault opens")
}

fn open_vault(path: &Path) -> Vault {
    open_vault_with(path, VaultConfig::device())
}

/// A valid vault whose persisted identity differs from the device preset
/// in both of the fields the open gate compares by value: the HNSW
/// dimension and the embedding model id. Opening it under the device
/// preset fails `HnswConfigChanged`, which is exactly what made both eval
/// subcommands unusable against non-device vaults.
fn non_device_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 384;
    config.embedding_model = Some("oneiron/eval-fixture@v1".to_owned());
    config
}

/// Renders the required vault-open flags for `config`, so a test names
/// exactly the configuration its fixture vault was created with instead of
/// restating preset constants.
fn vault_open_flags(path: &Path, config: &VaultConfig) -> Vec<String> {
    let fast_dims = match config.fast_dims {
        Some(prefix) => prefix.to_string(),
        None => VAULT_CONFIG_NONE.to_owned(),
    };
    let embedding_model = match &config.embedding_model {
        Some(model) => model.clone(),
        None => VAULT_CONFIG_NONE.to_owned(),
    };
    let mut flags = vec![
        "--vault".to_owned(),
        path.display().to_string(),
        "--dimensions".to_owned(),
        config.dimensions.to_string(),
        "--fast-dims".to_owned(),
        fast_dims,
        "--embedding-model".to_owned(),
        embedding_model,
        "--hnsw-m-max-0".to_owned(),
        config.hnsw.m_max_0.to_string(),
        "--hnsw-ef-construction".to_owned(),
        config.hnsw.ef_construction.to_string(),
        "--map-size".to_owned(),
        config.map_size.to_string(),
    ];
    if config.dict_search_paths.is_empty() {
        flags.push("--dict-path".to_owned());
        flags.push(VAULT_CONFIG_NONE.to_owned());
    }
    for root in &config.dict_search_paths {
        flags.push("--dict-path".to_owned());
        flags.push(root.display().to_string());
    }
    flags
}

/// Builds one full `eval` argument vector: subcommand, the shared
/// vault-open flags for `config`, then the subcommand's own flags.
fn eval_argv(subcommand: &str, path: &Path, config: &VaultConfig, rest: &[String]) -> Vec<String> {
    let mut argv = vec![subcommand.to_owned()];
    argv.extend(vault_open_flags(path, config));
    argv.extend_from_slice(rest);
    argv
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().copied().map(String::from).collect()
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

    let exit = run(&eval_argv(
        "outcome-ingest",
        tempdir.path(),
        &VaultConfig::device(),
        &[
            "--rewards".to_owned(),
            rewards_path.display().to_string(),
            "--key".to_owned(),
            "beam.reward".to_owned(),
        ],
    ));

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
    let path = Path::new("/tmp/oneiron-vault");
    let vault_flags = vault_open_flags(path, &VaultConfig::device());
    let mut argv = vault_flags.clone();
    argv.extend(owned(&["--rewards", "-", "--key", "beam.reward"]));

    let args = parse_outcome_ingest_args(&argv).expect("args parse");

    assert_eq!(
        args,
        OutcomeIngestArgs {
            vault: VaultOpenArgs {
                path: PathBuf::from("/tmp/oneiron-vault"),
                dimensions: 1024,
                fast_dims: None,
                embedding_model: None,
                m_max_0: 64,
                ef_construction: 200,
                map_size: 1 << 30,
                dict_search_paths: Vec::new(),
            },
            rewards_path: None,
            key: Some("beam.reward".to_owned()),
        }
    );
    let error = parse_outcome_ingest_args(&vault_flags).expect_err("rewards required");
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

    let exit = run(&eval_argv(
        "tune",
        tempdir.path(),
        &VaultConfig::device(),
        &owned(&[
            "--max-runs",
            "8",
            "--learning-rate",
            "0.10",
            "--min-reward-count",
            "1",
        ]),
    ));

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

    let exit = run(&eval_argv(
        "tune",
        tempdir.path(),
        &VaultConfig::device(),
        &owned(&["--max-runs", "1"]),
    ));

    assert!(matches!(exit, ExitCode::SUCCESS));
    let vault = open_vault(tempdir.path());
    let tuned = vault.retrieval_blend_weight_table().expect("table");
    assert_eq!(tuned.data_window.run_count, 1);
    assert_eq!(tuned.data_window.outcome_count, 1);
}

#[test]
fn eval_tune_maps_the_bounded_flags_onto_the_tuning_config() {
    let path = Path::new("/tmp/oneiron-vault");
    let vault_flags = vault_open_flags(path, &non_device_vault_config());
    let mut argv = vault_flags.clone();
    argv.extend(owned(&[
        "--max-runs",
        "32",
        "--learning-rate",
        "0.25",
        "--min-reward-count",
        "4",
    ]));

    let args = parse_tune_args(&argv).expect("args parse");

    assert_eq!(
        args,
        TuneArgs {
            vault: VaultOpenArgs {
                path: PathBuf::from("/tmp/oneiron-vault"),
                dimensions: 384,
                fast_dims: None,
                embedding_model: Some("oneiron/eval-fixture@v1".to_owned()),
                m_max_0: 64,
                ef_construction: 200,
                map_size: 1 << 30,
                dict_search_paths: Vec::new(),
            },
            config: RetrievalBlendTuningConfig {
                max_runs: 32,
                learning_rate: 0.25,
                min_reward_count: 4,
            },
        }
    );
    // The tuning flags keep their shipped bounded defaults; the vault-open
    // flags do not default at all.
    let defaults = parse_tune_args(&vault_flags).expect("args parse");
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
    let decoded: RetrievalBlendWeightTableEntry = serde_json::from_str(line).expect("entry json");
    assert!(lines.next().is_none());
    assert_eq!(decoded, entry);
}

/// Drops one flag and its value from a rendered vault-open flag list.
fn without_flag(flags: &[String], flag: &str) -> Vec<String> {
    flags
        .chunks(2)
        .filter(|pair| pair[0] != flag)
        .flat_map(|pair| pair.iter().cloned())
        .collect()
}

/// Replaces one flag's value in a rendered vault-open flag list.
fn with_flag(flags: &[String], flag: &str, value: &str) -> Vec<String> {
    let mut replaced = without_flag(flags, flag);
    replaced.push(flag.to_owned());
    replaced.push(value.to_owned());
    replaced
}

/// Every vault-open flag set that must be refused against the non-device
/// fixture at `path`: four omit a required field, one is the full device
/// preset (exactly what the commands used to force), one is internally
/// inconsistent, and three disagree with the persisted vault — including the
/// `none` model sentinel the storage gate itself tolerates on a vectorless
/// vault. None may be silently completed or retried under
/// `VaultConfig::device`.
fn refused_vault_flag_sets(path: &Path) -> Vec<(&'static str, Vec<String>)> {
    let correct = vault_open_flags(path, &non_device_vault_config());
    vec![
        ("omitted dimensions", without_flag(&correct, "--dimensions")),
        ("omitted model", without_flag(&correct, "--embedding-model")),
        ("omitted map size", without_flag(&correct, "--map-size")),
        ("omitted dict path", without_flag(&correct, "--dict-path")),
        (
            "device preset",
            vault_open_flags(path, &VaultConfig::device()),
        ),
        (
            "inconsistent fast dims",
            with_flag(&correct, "--fast-dims", "512"),
        ),
        (
            "wrong model",
            with_flag(&correct, "--embedding-model", "oneiron/other@v1"),
        ),
        (
            "model none against a stamped vault",
            with_flag(&correct, "--embedding-model", VAULT_CONFIG_NONE),
        ),
        ("wrong m_max_0", with_flag(&correct, "--hnsw-m-max-0", "32")),
    ]
}

/// Creates and persists the non-device fixture vault, seeds `runs`
/// finalized retrieval runs, and returns their ids with the vault closed.
fn seed_non_device_vault(path: &Path, runs: usize) -> Vec<RetrievalRunId> {
    let vault = open_vault_with(path, non_device_vault_config());
    let run_ids = seed_retrieval_runs(&vault, runs);
    drop(vault);
    run_ids
}

#[test]
fn eval_outcome_ingest_opens_a_non_device_vault_through_the_explicit_config() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let run_id = seed_non_device_vault(tempdir.path(), 1)[0];
    // The device preset genuinely cannot reopen this vault, so the config
    // below is doing the work rather than coinciding with a default.
    assert!(Vault::open(tempdir.path(), VaultConfig::device()).is_err());
    let rewards_path = tempdir.path().join("rewards.jsonl");
    let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
    std::fs::write(&rewards_path, rows).expect("rewards file");

    let exit = run(&eval_argv(
        "outcome-ingest",
        tempdir.path(),
        &non_device_vault_config(),
        &[
            "--rewards".to_owned(),
            rewards_path.display().to_string(),
            "--key".to_owned(),
            "beam.reward".to_owned(),
        ],
    ));

    assert!(matches!(exit, ExitCode::SUCCESS));
    let vault = open_vault_with(tempdir.path(), non_device_vault_config());
    let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].key, "beam.reward");
    assert_eq!(outcomes[0].reward, Some(0.75));
    assert_eq!(metadata_of(&outcomes[0], "evaluator"), Some("judge.v1"));
}

#[test]
fn eval_tune_opens_a_non_device_vault_through_the_explicit_config() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let run_id = seed_non_device_vault(tempdir.path(), 1)[0];
    assert!(Vault::open(tempdir.path(), VaultConfig::device()).is_err());
    let vault = open_vault_with(tempdir.path(), non_device_vault_config());
    let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
    assert_eq!(
        ingest(&vault, &rows, Some("beam.reward")).expect("ingest"),
        1
    );
    let before = vault.retrieval_blend_weight_table().expect("table");
    drop(vault);

    let exit = run(&eval_argv(
        "tune",
        tempdir.path(),
        &non_device_vault_config(),
        &owned(&[
            "--max-runs",
            "8",
            "--learning-rate",
            "0.10",
            "--min-reward-count",
            "1",
        ]),
    ));

    assert!(matches!(exit, ExitCode::SUCCESS));
    let vault = open_vault_with(tempdir.path(), non_device_vault_config());
    let tuned = vault.retrieval_blend_weight_table().expect("table");
    assert_ne!(tuned.weights, before.weights);
    assert_eq!(tuned.data_window.run_count, 1);
    assert_eq!(tuned.data_window.outcome_count, 1);
    let max_runs = tuned.provenance.get("max_runs").map(String::as_str);
    assert_eq!(max_runs, Some("8"));
}

#[test]
fn eval_outcome_ingest_refuses_an_incomplete_or_disagreeing_vault_config() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let run_id = seed_non_device_vault(tempdir.path(), 1)[0];
    let rewards_path = tempdir.path().join("rewards.jsonl");
    let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
    std::fs::write(&rewards_path, rows).expect("rewards file");
    let reward_flags = vec![
        "--rewards".to_owned(),
        rewards_path.display().to_string(),
        "--key".to_owned(),
        "beam.reward".to_owned(),
    ];

    for (case, vault_flags) in refused_vault_flag_sets(tempdir.path()) {
        let mut argv = vec!["outcome-ingest".to_owned()];
        argv.extend(vault_flags);
        argv.extend_from_slice(&reward_flags);

        let exit = run(&argv);

        assert!(matches!(exit, ExitCode::FAILURE), "{case}");
        let vault = open_vault_with(tempdir.path(), non_device_vault_config());
        let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
        assert!(outcomes.is_empty(), "{case}");
    }
}

#[test]
fn eval_tune_refuses_an_incomplete_or_disagreeing_vault_config() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let run_id = seed_non_device_vault(tempdir.path(), 1)[0];
    let vault = open_vault_with(tempdir.path(), non_device_vault_config());
    let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
    assert_eq!(
        ingest(&vault, &rows, Some("beam.reward")).expect("ingest"),
        1
    );
    let before = vault.retrieval_blend_weight_table().expect("table");
    drop(vault);

    for (case, vault_flags) in refused_vault_flag_sets(tempdir.path()) {
        let mut argv = vec!["tune".to_owned()];
        argv.extend(vault_flags);
        argv.extend(owned(&["--max-runs", "8", "--min-reward-count", "1"]));

        let exit = run(&argv);

        assert!(matches!(exit, ExitCode::FAILURE), "{case}");
        let vault = open_vault_with(tempdir.path(), non_device_vault_config());
        let after = vault.retrieval_blend_weight_table().expect("table");
        assert_eq!(after, before, "{case}");
    }
}

/// Both subcommands' full argv against `path` under the device contract, so a
/// vault-root boundary case is proved for outcome-ingest and tune alike.
fn device_argv_for_both(path: &Path, rewards_path: &Path) -> Vec<Vec<String>> {
    let device = VaultConfig::device();
    vec![
        eval_argv(
            "outcome-ingest",
            path,
            &device,
            &[
                "--rewards".to_owned(),
                rewards_path.display().to_string(),
                "--key".to_owned(),
                "beam.reward".to_owned(),
            ],
        ),
        eval_argv(
            "tune",
            path,
            &device,
            &owned(&["--max-runs", "8", "--min-reward-count", "1"]),
        ),
    ]
}

/// Counts the directory entries under `path`, so "nothing was created here"
/// is asserted against the filesystem rather than against an error string.
fn entry_count(path: &Path) -> usize {
    std::fs::read_dir(path).expect("readable").count()
}

/// A mistyped or pre-created empty directory named as `--vault`. The old
/// `Path::exists` door admitted it and the create-capable open initialized a
/// vault there, so an empty rewards file reported success over storage that
/// never held a vault. Both subcommands must refuse and leave the directory
/// with zero entries — no `data.mdb`, no `lock.mdb`, nothing.
#[test]
fn eval_refuses_an_empty_vault_directory_and_creates_nothing() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("empty-root");
    std::fs::create_dir(&root).expect("empty directory");
    let rewards_path = tempdir.path().join("rewards.jsonl");
    std::fs::write(&rewards_path, "").expect("rewards file");

    for argv in device_argv_for_both(&root, &rewards_path) {
        let exit = run(&argv);

        assert!(matches!(exit, ExitCode::FAILURE), "{argv:?}");
        assert_eq!(entry_count(&root), 0, "{argv:?}");
    }
}

/// An absent path is refused without being brought into existence, and an
/// ordinary directory of unrelated files is never mistaken for a vault root.
#[test]
fn eval_refuses_an_absent_or_unrelated_vault_path_and_creates_nothing() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let rewards_path = tempdir.path().join("rewards.jsonl");
    std::fs::write(&rewards_path, "").expect("rewards file");
    let absent = tempdir.path().join("absent-root");
    let unrelated = tempdir.path().join("unrelated");
    std::fs::create_dir(&unrelated).expect("unrelated directory");
    let note = unrelated.join("notes.txt");
    std::fs::write(note, b"not a vault").expect("note file");

    for argv in device_argv_for_both(&absent, &rewards_path) {
        assert!(matches!(run(&argv), ExitCode::FAILURE), "{argv:?}");
        assert!(!absent.exists(), "{argv:?}");
    }
    for argv in device_argv_for_both(&unrelated, &rewards_path) {
        assert!(matches!(run(&argv), ExitCode::FAILURE), "{argv:?}");
        assert_eq!(entry_count(&unrelated), 1, "{argv:?}");
    }
}

/// The pre-open pin is what makes the create-capable open safe, so it must
/// reject a root whose LMDB files were swapped underneath it — the state a
/// removal or replacement inside the open window leaves behind. Both vaults
/// exist at once here, so the swapped-in files are genuinely other files and
/// the refusal cannot ride on a recycled identity.
#[test]
fn eval_vault_root_pin_refuses_a_replaced_root() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let replacement_dir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path();
    let replacement = replacement_dir.path();
    drop(open_vault(root));
    let pinned = ExistingVaultRoot::pin(root).expect("root pins");
    pinned.verify_unchanged().expect("untouched root verifies");
    drop(open_vault(replacement));

    for entry in [VaultRootEntry::Data, VaultRootEntry::Lock] {
        let name = entry.to_string();
        let target = root.join(&name);
        let source = replacement.join(&name);
        std::fs::remove_file(&target).expect("remove pinned");
        std::fs::rename(source, &target).expect("swap in");
    }

    let error = pinned.verify_unchanged().expect_err("replaced root");
    assert!(matches!(error, EvalError::InvalidArgument(_)), "{error}");
}

/// The fixture stamps `Some(oneiron/eval-fixture@v1)` but seeds only text
/// telemetry, so the storage gate's vectorless branch accepts a requested
/// `None` model and `Vault::open` itself succeeds. Exact nullable identity is
/// what has to refuse `--embedding-model none`, before any outcome is written.
#[test]
fn eval_outcome_ingest_refuses_model_none_against_a_stamped_vault() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let run_id = seed_non_device_vault(tempdir.path(), 1)[0];
    let mut vectorless = non_device_vault_config();
    vectorless.embedding_model = None;
    let tolerated = Vault::open(tempdir.path(), vectorless.clone());
    assert!(tolerated.is_ok(), "the storage gate tolerates this open");
    drop(tolerated);
    let rewards_path = tempdir.path().join("rewards.jsonl");
    let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
    std::fs::write(&rewards_path, rows).expect("rewards file");

    let exit = run(&eval_argv(
        "outcome-ingest",
        tempdir.path(),
        &vectorless,
        &[
            "--rewards".to_owned(),
            rewards_path.display().to_string(),
            "--key".to_owned(),
            "beam.reward".to_owned(),
        ],
    ));

    assert!(matches!(exit, ExitCode::FAILURE));
    let vault = open_vault_with(tempdir.path(), non_device_vault_config());
    let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
    assert!(outcomes.is_empty());
}

/// A dictionary root the operator trusts. The Chinese analyzer probes
/// `<root>/zh/jieba.dict.utf8`, so these bytes are hashed into the vault's
/// persisted analyzer manifest: naming the root is the only way to reopen a
/// vault built over it, and the bench never learns it from the vault.
fn trusted_dict_root(dir: &Path) -> PathBuf {
    let root = dir.join("trusted-dicts");
    std::fs::create_dir_all(root.join("zh")).expect("dict dir");
    let dict = root.join("zh").join("jieba.dict.utf8");
    let bytes = "研究 100 n\n東京 90 n\n";
    std::fs::write(dict, bytes).expect("dict bytes");
    root
}

/// The non-device fixture plus the two dimensions the contract used to
/// inherit from `VaultConfig::device`: trusted dictionary roots and runtime
/// map sizing.
fn custom_dict_vault_config(dict_root: &Path) -> VaultConfig {
    let mut config = non_device_vault_config();
    config.dict_search_paths = vec![dict_root.to_path_buf()];
    config.map_size = 96 * 1024 * 1024;
    config
}

/// The class the original ONE-218 defect belonged to, at its widest: a valid
/// vault whose analyzer identity comes from custom dictionaries and whose
/// runtime sizing is not the device preset. Reopened through the repaired
/// contract, both subcommands reach their intended mutation; a dictionary root
/// that exists but is not this vault's own still fails closed.
#[test]
fn eval_reopens_a_custom_dictionary_vault_for_outcome_ingest_and_tune() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let dict_root = trusted_dict_root(tempdir.path());
    let config = custom_dict_vault_config(&dict_root);
    let vault_path = tempdir.path().join("vault");
    let vault = open_vault_with(&vault_path, config.clone());
    let run_id = seed_retrieval_runs(&vault, 1)[0];
    let before = vault.retrieval_blend_weight_table().expect("table");
    drop(vault);
    // The analyzer identity is load-bearing: every other flag is correct and
    // the vault still cannot be reopened without its dictionary root.
    let without_dicts = Vault::open(&vault_path, non_device_vault_config());
    assert!(without_dicts.is_err());
    let rewards_path = tempdir.path().join("rewards.jsonl");
    let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
    std::fs::write(&rewards_path, rows).expect("rewards file");
    let reward_flags = vec![
        "--rewards".to_owned(),
        rewards_path.display().to_string(),
        "--key".to_owned(),
        "beam.reward".to_owned(),
    ];

    let wrong_root = tempdir.path().join("other-dicts");
    std::fs::create_dir(&wrong_root).expect("other dict dir");
    let wrong_root_arg = wrong_root.display().to_string();
    let correct = vault_open_flags(&vault_path, &config);
    let mut wrong_argv = vec!["outcome-ingest".to_owned()];
    wrong_argv.extend(with_flag(&correct, "--dict-path", &wrong_root_arg));
    wrong_argv.extend_from_slice(&reward_flags);
    let refused = run(&wrong_argv);

    let ingest = run(&eval_argv(
        "outcome-ingest",
        &vault_path,
        &config,
        &reward_flags,
    ));
    let tune = run(&eval_argv(
        "tune",
        &vault_path,
        &config,
        &owned(&[
            "--max-runs",
            "8",
            "--learning-rate",
            "0.10",
            "--min-reward-count",
            "1",
        ]),
    ));

    assert!(matches!(refused, ExitCode::FAILURE));
    assert!(matches!(ingest, ExitCode::SUCCESS));
    assert!(matches!(tune, ExitCode::SUCCESS));
    let vault = open_vault_with(&vault_path, config);
    let outcomes = vault.retrieval_outcomes(run_id).expect("outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].reward, Some(0.75));
    let tuned = vault.retrieval_blend_weight_table().expect("table");
    assert_ne!(tuned.weights, before.weights);
    assert_eq!(tuned.data_window.outcome_count, 1);
}

/// The top-level help names `eval --help` as the place to read the vault-open
/// contract, so both usage spellings print it and succeed instead of landing
/// in the unknown-subcommand arm.
#[test]
fn eval_help_flags_print_usage_and_succeed() {
    for flag in ["--help", "-h"] {
        let exit = run(&owned(&[flag]));
        assert!(matches!(exit, ExitCode::SUCCESS), "{flag}");
    }
    assert!(matches!(run(&owned(&["nope"])), ExitCode::FAILURE));
}

/// The stored analyzer identity, read back through the engine's own doctor
/// seam on the existing-only door — the one door that never rewrites it. The
/// bench still decodes no vault byte of its own.
fn stored_analyzer_manifest_hash(path: &Path, config: &VaultConfig) -> Option<String> {
    let vault = Vault::open_existing(path, config.clone()).expect("existing vault reopens");
    vault.doctor().expect("doctor").analyzer_manifest_hash
}

/// The M1 class at bench level: a real vault root is renamed away and an empty
/// directory takes its place. The create-capable open hands LMDB the pathname,
/// so it would initialize a whole new vault in the replacement and only then
/// let the pin notice; the engine's existing-only door refuses and the
/// replacement stays at zero entries.
///
/// The engine door is exercised directly as well as through both subcommands,
/// so the refusal is proved at the trust boundary rather than only at the
/// bench's defense-in-depth pin.
#[test]
fn eval_refuses_an_empty_directory_replacement_of_a_real_vault() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("vault");
    let moved = tempdir.path().join("moved");
    drop(open_vault(&root));
    std::fs::rename(&root, &moved).expect("move the real vault away");
    std::fs::create_dir(&root).expect("empty replacement");
    let rewards_path = tempdir.path().join("rewards.jsonl");
    std::fs::write(&rewards_path, "").expect("rewards file");

    let refused = Vault::open_existing(&root, VaultConfig::device());

    assert!(refused.is_err(), "the engine door itself must refuse");
    assert_eq!(entry_count(&root), 0, "the engine wrote nothing");
    for argv in device_argv_for_both(&root, &rewards_path) {
        assert!(matches!(run(&argv), ExitCode::FAILURE), "{argv:?}");
        assert_eq!(entry_count(&root), 0, "{argv:?}");
    }
    assert!(moved.join("data.mdb").exists(), "the real vault survives");
}

/// M2 at bench level: the vault holds NO model id and the operator names one.
/// `Vault::open` answers that by stamping the supplied id mid-open, after which
/// the post-open doctor comparison trivially agrees and the command succeeds
/// against a vault it just mutated. The existing-only door compares the
/// pre-open bytes, so the command fails and the id stays unstamped.
#[test]
fn eval_outcome_ingest_refuses_a_supplied_model_against_an_unstamped_vault() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let vault_path = tempdir.path().join("vault");
    let mut vectorless = non_device_vault_config();
    vectorless.embedding_model = None;
    let vault = open_vault_with(&vault_path, vectorless.clone());
    let run_id = seed_retrieval_runs(&vault, 1)[0];
    drop(vault);
    let rewards_path = tempdir.path().join("rewards.jsonl");
    let rows = jsonl(&[reward_row(run_id, PROVENANCE)]);
    std::fs::write(&rewards_path, rows).expect("rewards file");
    let mut supplied = vectorless.clone();
    supplied.embedding_model = Some("oneiron/eval-fixture@v1".to_owned());

    let exit = run(&eval_argv(
        "outcome-ingest",
        &vault_path,
        &supplied,
        &[
            "--rewards".to_owned(),
            rewards_path.display().to_string(),
            "--key".to_owned(),
            "beam.reward".to_owned(),
        ],
    ));

    assert!(matches!(exit, ExitCode::FAILURE));
    let vault = open_vault_with(&vault_path, vectorless);
    assert_eq!(vault.doctor().expect("doctor").embedding_model_id, None);
    assert!(
        vault
            .retrieval_outcomes(run_id)
            .expect("outcomes")
            .is_empty()
    );
}

/// M3 at bench level: a custom-dictionary vault whose text index is EMPTY, plus
/// a dictionary root that exists but is not this vault's. The create-capable
/// open rewrites the stored analyzer manifest to the wrong identity on an empty
/// index and then succeeds, so an empty reward file used to report success
/// against a vault whose analyzer identity it had just replaced. The
/// existing-only door compares the manifest in every state and refuses, leaving
/// the stored identity exactly as it was.
#[test]
fn eval_outcome_ingest_refuses_a_wrong_dict_root_on_an_empty_text_index() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let dict_root = trusted_dict_root(tempdir.path());
    let config = custom_dict_vault_config(&dict_root);
    let vault_path = tempdir.path().join("vault");
    // No text is seeded, so the empty-index rewrite branch is the reachable one.
    drop(open_vault_with(&vault_path, config.clone()));
    let before = stored_analyzer_manifest_hash(&vault_path, &config);
    assert!(before.is_some(), "the fixture stamps an analyzer manifest");
    let wrong_root = tempdir.path().join("other-dicts");
    std::fs::create_dir(&wrong_root).expect("other dict dir");
    let wrong_root_arg = wrong_root.display().to_string();
    let rewards_path = tempdir.path().join("rewards.jsonl");
    std::fs::write(&rewards_path, "").expect("rewards file");
    let correct = vault_open_flags(&vault_path, &config);
    let mut argv = vec!["outcome-ingest".to_owned()];
    argv.extend(with_flag(&correct, "--dict-path", &wrong_root_arg));
    argv.push("--rewards".to_owned());
    argv.push(rewards_path.display().to_string());
    argv.extend(owned(&["--key", "beam.reward"]));

    let exit = run(&argv);

    assert!(matches!(exit, ExitCode::FAILURE));
    assert_eq!(stored_analyzer_manifest_hash(&vault_path, &config), before);
}
