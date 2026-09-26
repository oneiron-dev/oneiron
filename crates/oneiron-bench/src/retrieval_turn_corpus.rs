//! Offline replay of finalized, turn-indexed retrieval runs. This replays the
//! recorded pack and trace, not a fresh search against a potentially changed vault.
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use oneiron::store::{RetrievalRunRecord, RetrievalState, RetrievalTurn};
use oneiron::{RetrievalRunId, RetrievalScoreBreakdown, RetrievalTrace, Vault, VaultConfig};
use serde::{Deserialize, Serialize};

const CONTRACT: &str = "oneiron.retrieval_turn_corpus.v1";
const DEFAULT_DIMENSIONS: usize = 1024;

#[derive(Debug, thiserror::Error)]
enum CorpusError {
    #[error("usage requested")]
    Help,
    #[error("invalid corpus argument: {0}")]
    Argument(String),
    #[error("invalid corpus row: {0}")]
    Row(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("engine error: {0}")]
    Engine(#[from] oneiron::Error),
}

type Result<T> = std::result::Result<T, CorpusError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TurnRow {
    contract_version: String,
    record_type: String,
    turn: RetrievalTurn,
    runs: Vec<RetrievalRunRecord>,
}

/// Reconstructed from recorded data alone; no vault, query, graph, or clock is read.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayRun {
    run_id: RetrievalRunId,
    state: RetrievalState,
    result_ids: Vec<[u8; 16]>,
    pack: Vec<RetrievalScoreBreakdown>,
    trace: Option<RetrievalTrace>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayTurn {
    turn: RetrievalTurn,
    runs: Vec<ReplayRun>,
}

fn validate(row: &TurnRow) -> Result<()> {
    if row.contract_version != CONTRACT || row.record_type != "retrieval_turn" {
        return Err(CorpusError::Row(
            "unknown contract version or record type".into(),
        ));
    }
    if row.runs.is_empty() {
        return Err(CorpusError::Row("turn has no finalized runs".into()));
    }
    let mut ids = HashSet::new();
    for run in &row.runs {
        if run.turn != Some(row.turn) || !ids.insert(run.run_id) {
            return Err(CorpusError::Row("turn mismatch or duplicate run id".into()));
        }
        // The run's result ids are the observed surfaced pack; score_breakdown
        // retains stage scores, which may include more than the surfaced pack.
        if run.result_ids.iter().any(|id| {
            !run.score_breakdown
                .iter()
                .any(|score| &score.result_id == id)
        }) {
            return Err(CorpusError::Row(
                "surfaced result missing from score breakdown".into(),
            ));
        }
    }
    Ok(())
}

fn export(vault: &Vault, turn_ids: &[[u8; 16]], writer: &mut impl Write) -> Result<usize> {
    let mut seen = HashSet::new();
    for turn_id in turn_ids {
        if !seen.insert(*turn_id) {
            return Err(CorpusError::Argument("duplicate turn id".into()));
        }
        let ids = vault.retrieval_runs_by_turn(turn_id)?;
        let runs = ids
            .into_iter()
            .map(|id| {
                vault
                    .retrieval_run(id)?
                    .ok_or_else(|| CorpusError::Row("indexed run is not finalized".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        let turn = runs
            .first()
            .and_then(|run| run.turn)
            .ok_or_else(|| CorpusError::Row("turn has no finalized runs".into()))?;
        let row = TurnRow {
            contract_version: CONTRACT.into(),
            record_type: "retrieval_turn".into(),
            turn,
            runs,
        };
        validate(&row)?;
        serde_json::to_writer(&mut *writer, &row)?;
        writer.write_all(b"\n")?;
    }
    Ok(turn_ids.len())
}

/// Stage beside the destination so invalid turns or write failures never
/// truncate an existing corpus. Stdout intentionally remains streaming.
fn export_to_file(vault: &Vault, turn_ids: &[[u8; 16]], path: &std::path::Path) -> Result<usize> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut pending = tempfile::NamedTempFile::new_in(directory)?;
    let count = export(vault, turn_ids, &mut pending)?;
    pending.flush()?;
    pending
        .persist(path)
        .map_err(|err| CorpusError::Io(err.error))?;
    Ok(count)
}

fn load(reader: impl BufRead) -> Result<Vec<TurnRow>> {
    let mut turns = Vec::new();
    let mut seen_turns = HashSet::new();
    let mut seen_runs = HashSet::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.is_empty() {
            return Err(CorpusError::Row(format!("empty line {}", index + 1)));
        }
        let row: TurnRow = serde_json::from_str(&line)?;
        validate(&row)?;
        if !seen_turns.insert(row.turn.turn_id)
            || row.runs.iter().any(|run| !seen_runs.insert(run.run_id))
        {
            return Err(CorpusError::Row(format!(
                "duplicate turn or run on line {}",
                index + 1
            )));
        }
        turns.push(row);
    }
    if turns.is_empty() {
        return Err(CorpusError::Row("empty corpus".into()));
    }
    Ok(turns)
}

fn replay(rows: &[TurnRow]) -> Vec<ReplayTurn> {
    rows.iter()
        .map(|row| ReplayTurn {
            turn: row.turn,
            runs: row
                .runs
                .iter()
                .map(|run| ReplayRun {
                    run_id: run.run_id,
                    state: run.replay_state().clone(),
                    result_ids: run.result_ids.clone(),
                    pack: run
                        .result_ids
                        .iter()
                        .map(|id| {
                            run.score_breakdown
                                .iter()
                                .find(|score| &score.result_id == id)
                                .expect("load validated the pack")
                                .clone()
                        })
                        .collect(),
                    trace: run.trace.clone(),
                })
                .collect(),
        })
        .collect()
}

fn parse_hex(value: &str) -> Result<[u8; 16]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CorpusError::Argument(format!(
            "expected a 32-digit turn id, got `{value}`"
        )));
    }
    let mut out = [0; 16];
    for (n, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[n * 2..n * 2 + 2], 16)
            .map_err(|_| CorpusError::Argument("invalid turn id".into()))?;
    }
    Ok(out)
}

fn argument<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|v| !v.starts_with("--"))
        .ok_or_else(|| CorpusError::Argument(format!("missing value for {flag}")))
}

fn execute(args: &[String]) -> Result<usize> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Err(CorpusError::Help);
    }
    let (mode, flags) = args.split_first().ok_or(CorpusError::Help)?;
    let mut vault_path = None;
    let mut input = None;
    let mut output = None;
    let mut turn_ids = Vec::new();
    let mut dimensions = DEFAULT_DIMENSIONS;
    let mut embedding_model = None;
    let mut index = 0;
    while index < flags.len() {
        let flag = flags[index].as_str();
        let value = argument(flags, index, flag)?;
        match flag {
            "--vault" => vault_path = Some(PathBuf::from(value)),
            "--in" => input = Some(PathBuf::from(value)),
            "--out" => output = Some(PathBuf::from(value)),
            "--turn-id" => turn_ids.push(parse_hex(value)?),
            "--dimensions" => {
                dimensions = value
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| CorpusError::Argument("dimensions must be positive".into()))?;
            }
            "--embedding-model" => embedding_model = Some(value.to_owned()),
            _ => return Err(CorpusError::Argument(format!("unknown flag {flag}"))),
        }
        index += 2;
    }
    match mode.as_str() {
        "corpus-export" if input.is_none() && vault_path.is_some() && !turn_ids.is_empty() => {
            let path = vault_path.expect("checked");
            if !path.exists() { return Err(CorpusError::Argument("vault path does not exist".into())); }
            let mut cfg = VaultConfig::device();
            cfg.dimensions = dimensions;
            cfg.embedding_model = embedding_model;
            let vault = Vault::open(path, cfg)?;
            match output {
                Some(path) => export_to_file(&vault, &turn_ids, &path),
                None => export(&vault, &turn_ids, &mut std::io::stdout().lock()),
            }
        }
        "corpus-replay" if input.is_some() && vault_path.is_none() && turn_ids.is_empty() && dimensions == DEFAULT_DIMENSIONS && embedding_model.is_none() => {
            let rows = load(BufReader::new(File::open(input.expect("checked"))?))?;
            let replayed = replay(&rows);
            match output {
                Some(path) => write_replay(&replayed, &mut File::create(path)?),
                None => write_replay(&replayed, &mut std::io::stdout().lock()),
            }
        }
        _ => Err(CorpusError::Argument("expected corpus-export --vault PATH --turn-id HEX32 [--out PATH] or corpus-replay --in PATH [--out PATH]".into())),
    }
}

fn write_replay(turns: &[ReplayTurn], writer: &mut impl Write) -> Result<usize> {
    for turn in turns {
        serde_json::to_writer(&mut *writer, turn)?;
        writer.write_all(b"\n")?;
    }
    Ok(turns.len())
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    match execute(args) {
        Ok(count) => {
            let _ = writeln!(std::io::stderr().lock(), "processed {count} turn(s)");
            ExitCode::SUCCESS
        }
        Err(CorpusError::Help) => {
            let _ = writeln!(
                std::io::stdout().lock(),
                "usage: oneiron-bench beam corpus-export --vault PATH --turn-id HEX32 [--turn-id HEX32 ...] [--out PATH] [--dimensions N] [--embedding-model MODEL]\n       oneiron-bench beam corpus-replay --in PATH [--out PATH]\nReplay emits recorded packs, states and traces; it does not rerun retrieval."
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr().lock(), "BEAM turn corpus failed: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::{EntityId, TimeRange};

    #[test]
    fn logged_turns_export_reload_and_replay_identical_packs_and_traces() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = VaultConfig::device();
        cfg.dimensions = 4;
        cfg.map_size = 32 * 1024 * 1024;
        let vault = Vault::open(dir.path(), cfg).unwrap();
        for text in ["corpus alpha", "corpus beta"] {
            let id = EntityId::now();
            vault
                .batch()
                .put(
                    &id,
                    oneiron::registry::ENTITY_TYPE_SUMMARY,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"payload",
                )
                .text(&id, &[("body", text)])
                .commit()
                .unwrap();
        }
        let mut original = Vec::new();
        let mut turns = Vec::new();
        for n in 0..3_u8 {
            let turn = RetrievalTurn {
                turn_id: [n + 1; 16],
                episode_id: [9; 16],
                turn_idx: u64::from(n),
            };
            turns.push(turn.turn_id);
            let mut expected_runs = Vec::new();
            for _ in 0..2 {
                let result = vault
                    .query()
                    .search_text("corpus", 10)
                    .retrieval_turn(turn)
                    .capture_retrieval_trace(true)
                    .run_with_telemetry()
                    .unwrap();
                let ids: Vec<_> = result.value.iter().map(|hit| *hit.id.as_bytes()).collect();
                let run = vault
                    .retrieval_run(result.run_id.unwrap())
                    .unwrap()
                    .unwrap();
                assert_eq!(run.result_ids, ids);
                assert!(run.trace.is_some());
                expected_runs.push(run);
            }
            original.push(expected_runs);
        }
        let mut jsonl = Vec::new();
        assert_eq!(export(&vault, &turns, &mut jsonl).unwrap(), 3);
        let rows = load(BufReader::new(jsonl.as_slice())).unwrap();
        assert_eq!(rows.len(), 3);
        for (row, expected) in rows.iter().zip(&original) {
            assert_eq!(&row.runs, expected);
        }
        let replayed = replay(&rows);
        for (turn, expected) in replayed.iter().zip(&original) {
            for (run, source) in turn.runs.iter().zip(expected) {
                assert_eq!(run.state, *source.replay_state());
                assert_eq!(run.result_ids, source.result_ids);
                assert_eq!(
                    run.pack,
                    source
                        .result_ids
                        .iter()
                        .map(|id| source
                            .score_breakdown
                            .iter()
                            .find(|score| &score.result_id == id)
                            .unwrap()
                            .clone())
                        .collect::<Vec<_>>()
                );
                assert_eq!(run.trace, source.trace);
            }
        }
    }

    #[test]
    fn file_export_failure_keeps_previous_corpus() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault");
        let output = dir.path().join("corpus.jsonl");
        let turn = RetrievalTurn {
            turn_id: [1; 16],
            episode_id: [2; 16],
            turn_idx: 0,
        };
        let vault = Vault::open(&vault_path, VaultConfig::device()).unwrap();
        let result = vault
            .query()
            .search_text("missing", 2)
            .retrieval_turn(turn)
            .run_with_telemetry()
            .unwrap();
        assert!(
            vault
                .retrieval_run(result.run_id.unwrap())
                .unwrap()
                .is_some()
        );
        drop(vault);

        let prior = b"previous complete corpus\n";
        std::fs::write(&output, prior).unwrap();
        for ids in [
            vec!["03".repeat(16)],
            vec!["01".repeat(16), "03".repeat(16)],
            vec!["01".repeat(16), "01".repeat(16)],
        ] {
            let mut args = vec![
                "corpus-export".to_owned(),
                "--vault".to_owned(),
                vault_path.display().to_string(),
                "--out".to_owned(),
                output.display().to_string(),
                "--dimensions".to_owned(),
                "1024".to_owned(),
            ];
            for id in ids {
                args.extend(["--turn-id".to_owned(), id]);
            }
            assert!(execute(&args).is_err());
            assert_eq!(std::fs::read(&output).unwrap(), prior);
        }
        let args = [
            "corpus-export".to_owned(),
            "--vault".to_owned(),
            vault_path.display().to_string(),
            "--out".to_owned(),
            output.display().to_string(),
            "--turn-id".to_owned(),
            "01".repeat(16),
        ];
        assert_eq!(execute(&args).unwrap(), 1);
        let rows = load(BufReader::new(File::open(&output).unwrap())).unwrap();
        assert_eq!(rows[0].turn, turn);
    }

    #[test]
    fn rejects_bad_version_mismatched_turn_and_duplicate_rows() {
        let turn = RetrievalTurn {
            turn_id: [1; 16],
            episode_id: [2; 16],
            turn_idx: 0,
        };
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        let result = vault
            .query()
            .search_text("nothing", 2)
            .retrieval_turn(turn)
            .capture_retrieval_trace(true)
            .run_with_telemetry()
            .unwrap();
        let run = vault
            .retrieval_run(result.run_id.unwrap())
            .unwrap()
            .unwrap();
        let mut row = TurnRow {
            contract_version: CONTRACT.into(),
            record_type: "retrieval_turn".into(),
            turn,
            runs: vec![run],
        };
        assert!(validate(&row).is_ok());
        row.contract_version = "unknown".into();
        assert!(validate(&row).is_err());
        row.contract_version = CONTRACT.into();
        row.turn.turn_idx += 1;
        assert!(validate(&row).is_err());
        row.turn = turn;
        let line = serde_json::to_string(&row).unwrap();
        let duplicate = format!("{line}\n{line}\n");
        assert!(load(BufReader::new(duplicate.as_bytes())).is_err());
    }
}
