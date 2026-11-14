//! `scorecard grade-run`: grade a TREC run file into a scorecard.
//!
//! A reference run (a Pyserini/Lucene baseline over the same slice) is graded
//! by the same ruler code as a keyword run; the params digest is the run file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use oneiron_ruler::pack::load_slice;
use oneiron_ruler::scorecard::{
    Hit, QueryRun, RepeatRun, RunHeader, ScorecardError, build_keyword_scorecard, write_scorecard,
};

use super::ScorecardFailure;
use super::run::{check_commit, flag_u32};
use super::{parse_flags, parse_slice, required_flag};

/// The flags `scorecard grade-run` takes.
const KNOWN_FLAGS: &[&str] = &[
    "pack-dir",
    "slice",
    "run",
    "retriever",
    "engine-commit",
    "out",
    "budget-rows",
];

/// The budget rows when `--budget-rows` is omitted.
const DEFAULT_BUDGET_ROWS: u32 = 100;

/// One parsed run line: its query, record, rank and score bits, in file order.
struct RunLine<'a> {
    /// The query id.
    query_id: &'a str,
    /// The record id.
    record_id: &'a str,
    /// The rank, ascending.
    rank: u64,
    /// `f32::to_bits` of the score.
    score_bits: u32,
}

/// Grade one TREC run file into a scorecard file, and report the summary.
pub(crate) fn run(args: &[String]) -> Result<serde_json::Value, ScorecardFailure> {
    let flags = parse_flags(args, KNOWN_FLAGS)?;
    let slice_name = required_flag(&flags, "slice")?;
    if slice_name == "sealed" {
        return Err(ScorecardFailure::Input(
            "the sealed slice is opened only by its once-only run; a reference run file is graded on search or held_out"
                .to_owned(),
        ));
    }
    let slice = parse_slice(slice_name)?;
    let engine_commit = required_flag(&flags, "engine-commit")?;
    check_commit(engine_commit)?;
    let pack_dir = required_flag(&flags, "pack-dir")?;
    let run_path = required_flag(&flags, "run")?;
    let retriever = required_flag(&flags, "retriever")?;
    let out = required_flag(&flags, "out")?;
    let budget_rows = flag_u32(
        flags.get("budget-rows").map(String::as_str),
        "budget-rows",
        DEFAULT_BUDGET_ROWS,
        1,
        u32::MAX,
    )?;
    let loaded = load_slice(Path::new(pack_dir), slice)
        .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
    let run_bytes = std::fs::read(run_path)
        .map_err(|error| ScorecardFailure::Input(format!("run read failed: {error}")))?;
    let mut queries: BTreeSet<&str> = BTreeSet::new();
    for query in &loaded.slice.queries {
        queries.insert(query.query_id.as_str());
    }
    let lines = parse_run(&run_bytes, &queries)?;
    let mut by_query: BTreeMap<&str, Vec<RunLine>> = BTreeMap::new();
    for line in lines {
        by_query.entry(line.query_id).or_default().push(line);
    }
    let mut runs = Vec::with_capacity(loaded.slice.queries.len());
    for query in &loaded.slice.queries {
        let mut hits = Vec::new();
        if let Some(lines) = by_query.get_mut(query.query_id.as_str()) {
            lines.sort_by_key(|line| line.rank);
            for line in lines {
                hits.push(Hit {
                    record_id: line.record_id.to_owned(),
                    score_bits: line.score_bits,
                });
            }
        }
        runs.push(QueryRun {
            query_id: query.query_id.clone(),
            repeats: vec![RepeatRun { hits, search_us: 0 }],
        });
    }
    let header = RunHeader {
        engine_commit: engine_commit.to_owned(),
        params_digest: oneiron_ruler::pack::sha256_hex(&run_bytes),
        budget_rows,
    };
    let scorecard = build_keyword_scorecard(
        &loaded.slice,
        &loaded.pack_digest,
        &header,
        &runs,
        retriever,
    )
    .map_err(map_grade_error)?;
    write_scorecard(Path::new(out), &scorecard)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    let metrics = serde_json::to_value(&scorecard.metrics)
        .map_err(|error| ScorecardFailure::Run(error.to_string()))?;
    Ok(serde_json::json!({
        "scorecard": out,
        "slice": slice.as_str(),
        "pack_digest": loaded.pack_digest,
        "params_digest": scorecard.params_digest,
        "retriever": retriever,
        "query_count": scorecard.query_count,
        "metrics": metrics,
    }))
}

/// Parse a TREC run: six fields, a positive rank, a finite score; blank lines skipped.
fn parse_run<'a>(
    bytes: &'a [u8],
    queries: &BTreeSet<&str>,
) -> Result<Vec<RunLine<'a>>, ScorecardFailure> {
    let mut lines = Vec::new();
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (index, raw) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let number = index + 1;
        let Ok(text) = str::from_utf8(raw) else {
            return Err(ScorecardFailure::Input(format!("bad run line {number}")));
        };
        let text = text.strip_suffix('\r').unwrap_or(text);
        if text.trim().is_empty() {
            continue;
        }
        let mut parts = text.split_whitespace();
        let fields = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        );
        let (
            Some(query_id),
            Some(_iteration),
            Some(record_id),
            Some(rank_text),
            Some(score_text),
            Some(_tag),
            None,
        ) = fields
        else {
            return Err(ScorecardFailure::Input(format!("bad run line {number}")));
        };
        let rank = rank_text
            .parse::<u64>()
            .map_err(|_| ScorecardFailure::Input(format!("bad run line {number}")))?;
        if rank == 0 {
            return Err(ScorecardFailure::Input(format!("bad run line {number}")));
        }
        let score = score_text
            .parse::<f32>()
            .map_err(|_| ScorecardFailure::Input(format!("bad run line {number}")))?;
        if !score.is_finite() {
            return Err(ScorecardFailure::Input(format!("bad run line {number}")));
        }
        if !queries.contains(query_id) {
            return Err(ScorecardFailure::Input(format!(
                "run line {number} names a query outside the slice: {query_id}"
            )));
        }
        if !seen.insert((query_id, record_id)) {
            return Err(ScorecardFailure::Input(format!(
                "run line {number} repeats {query_id} {record_id}"
            )));
        }
        lines.push(RunLine {
            query_id,
            record_id,
            rank,
            score_bits: score.to_bits(),
        });
    }
    Ok(lines)
}

/// Map a grading failure: a bad retriever flag is bad input, the rest ran.
fn map_grade_error(error: ScorecardError) -> ScorecardFailure {
    match &error {
        ScorecardError::BadRetriever { .. } => ScorecardFailure::Input(error.to_string()),
        _ => ScorecardFailure::Run(error.to_string()),
    }
}
