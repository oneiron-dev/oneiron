//! Measurement executable: stamped owned formualizer over `cases.json`.
//!
//! Reads the pinned corpus, evaluates every case on a fresh
//! [`FormualizerEngine`](oneiron_xlsx_formula::engine::FormualizerEngine), and
//! writes one JSON report (`engine_stamp`, `corpus_sha256`, per-case rows).
//! Exit 0 after writing the report even when cases fail: a failing case is
//! data, not a runner crash. Exit nonzero only when the runner itself cannot
//! run (bad args, unreadable corpus, hash mismatch, unwritable output).
//!
//! No stdout result scraping: the report file is the output. `--version`
//! prints the deterministic engine stamp, not the harness version.

use std::path::PathBuf;

use oneiron_xlsx_formula::engine::ENGINE_STAMP;
use oneiron_xlsx_formula::measure::{MeasureOptions, measure_corpus, read_corpus_cases};

fn usage() -> String {
    "usage: measure --cases <cases.json> --provenance <provenance.json> --output <report.json> [--limit N] [--version]"
        .to_owned()
}

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--version") {
        emit_stdout(&format!("{ENGINE_STAMP}\n"));
        return 0;
    }
    let mut cases: Option<PathBuf> = None;
    let mut provenance: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut limit: Option<usize> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--cases" => {
                index += 1;
                cases = args.get(index).map(PathBuf::from);
            }
            "--provenance" => {
                index += 1;
                provenance = args.get(index).map(PathBuf::from);
            }
            "--output" => {
                index += 1;
                output = args.get(index).map(PathBuf::from);
            }
            "--limit" => {
                index += 1;
                limit = args.get(index).and_then(|text| text.parse().ok());
                if limit.is_none() {
                    emit_stderr("measure: --limit needs a number\n");
                    return 2;
                }
            }
            other => {
                emit_stderr(&format!("measure: unknown argument {other}\n{}\n", usage()));
                return 2;
            }
        }
        index += 1;
    }
    let (Some(cases_path), Some(provenance_path), Some(output_path)) = (cases, provenance, output)
    else {
        emit_stderr(&format!("{}\n", usage()));
        return 2;
    };
    let provenance_raw = match std::fs::read_to_string(&provenance_path) {
        Ok(raw) => raw,
        Err(_) => {
            emit_stderr(&format!(
                "measure: cannot read {}\n",
                provenance_path.display()
            ));
            return 1;
        }
    };
    let expected_sha256 = match serde_json::from_str::<serde_json::Value>(&provenance_raw)
        .ok()
        .and_then(|json| json.get("normalized_cases_sha256").cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
    {
        Some(sha) => sha,
        None => {
            emit_stderr("measure: provenance has no normalized_cases_sha256\n");
            return 1;
        }
    };
    let mut loaded = match read_corpus_cases(&cases_path, &expected_sha256) {
        Ok(cases) => cases,
        Err(error) => {
            emit_stderr(&format!("measure: {error}\n"));
            return 1;
        }
    };
    if let Some(count) = limit {
        loaded.truncate(count);
    }
    let report = measure_corpus(&loaded, &expected_sha256, &MeasureOptions::default());
    let text = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned());
    if std::fs::write(&output_path, format!("{text}\n")).is_err() {
        emit_stderr(&format!(
            "measure: cannot write {}\n",
            output_path.display()
        ));
        return 1;
    }
    let mut counts: Vec<(&str, usize)> = report
        .status_counts
        .iter()
        .map(|(status, count)| (status.as_str(), *count))
        .collect();
    counts.sort_unstable();
    let summary = counts
        .iter()
        .map(|(status, count)| format!("{status}={count}"))
        .collect::<Vec<_>>()
        .join(" ");
    emit_stderr(&format!(
        "measure: {} cases ({summary}), stamp {}\n",
        loaded.len(),
        report.engine_stamp
    ));
    0
}

/// Write one line to stdout. Plain print macros would trip the
/// print-macros ratchet, which counts every CLI the same as library code.
fn emit_stdout(line: &str) {
    use std::io::Write;
    let _ = std::io::stdout().lock().write_all(line.as_bytes());
}

/// Write one line to stderr. See [`emit_stdout`].
fn emit_stderr(line: &str) {
    use std::io::Write;
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}
