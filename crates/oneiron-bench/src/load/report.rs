//! The result file, and `load compare`, which reads two of them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::corpus::Query;
use super::server::Memory;
use super::stats::Summary;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Report {
    pub(super) bench: String,
    pub(super) label: Option<String>,
    pub(super) started_unix: u64,
    pub(super) host: Host,
    pub(super) server_bin: String,
    pub(super) server_bytes: u64,
    pub(super) plan: serde_json::Value,
    pub(super) runs: Vec<Run>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Host {
    pub(super) hostname: String,
    pub(super) cpu: String,
    pub(super) logical_cpus: usize,
    /// The job's cgroup CPU quota (`cpu.max`), when one applies.
    pub(super) cgroup_cpu_max: Option<String>,
    pub(super) load_start: String,
    pub(super) load_end: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Rows {
    pub(super) turns: usize,
    pub(super) messages: usize,
    pub(super) claims: usize,
    pub(super) owner_claims: usize,
    pub(super) conversations: usize,
    /// Witness writes four edges per message plus one per turn; a claim one.
    pub(super) edges_written: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Startup {
    pub(super) ready_ms: f64,
    pub(super) at_ready: Memory,
    pub(super) peak: Memory,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Cell {
    pub(super) name: String,
    pub(super) grade: String,
    pub(super) secret_scan: String,
    pub(super) agents: usize,
    pub(super) summary: Summary,
    /// Per verb, for ingest cells.
    pub(super) by_verb: BTreeMap<String, Summary>,
    pub(super) server_cpu_seconds: Option<f64>,
    pub(super) load_before: String,
    pub(super) load_after: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct GoldenQuery {
    pub(super) query: Query,
    /// Per grade: the tag index of each returned item, in rank order.
    pub(super) rankings: BTreeMap<String, Vec<Option<usize>>>,
    pub(super) errors: BTreeMap<String, String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct AgentMemory {
    pub(super) agents: usize,
    pub(super) anon_before_mib: f64,
    pub(super) anon_after_mib: f64,
    pub(super) kib_per_agent: f64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Fairness {
    pub(super) callers: usize,
    pub(super) heavy_threads: usize,
    pub(super) alone: Cell,
    pub(super) beside_heavy: Cell,
    pub(super) heavy: Cell,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Run {
    pub(super) records: usize,
    pub(super) documents: usize,
    pub(super) secret_scan: String,
    pub(super) vectors: bool,
    pub(super) rows: Rows,
    pub(super) mint_seconds: f64,
    /// Seconds added to the wall clock so holder proofs land in the vault's
    /// replay window: the vault's authority clock lags while it is closed.
    #[serde(default)]
    pub(super) clock_skew_secs: i64,
    pub(super) startup_empty: Startup,
    pub(super) ingest: Vec<Cell>,
    pub(super) drain_seconds: Option<f64>,
    pub(super) steady: Memory,
    pub(super) disk_mib: f64,
    pub(super) golden: Vec<GoldenQuery>,
    /// Per grade: the share of targeted golden queries whose record is in the
    /// top 10; a failed query is a miss.
    pub(super) hit_at_10: BTreeMap<String, f64>,
    pub(super) memory_per_agent: Option<AgentMemory>,
    pub(super) recall: Vec<Cell>,
    pub(super) mixed: Vec<Cell>,
    pub(super) fairness: Option<Fairness>,
    pub(super) startup_full: Startup,
    pub(super) notes: Vec<String>,
}

fn ms(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |v| format!("{v:.1}"))
}

fn line(out: &mut String, name: &str, a: &str, b: &str) {
    let _ = writeln!(out, "| {name} | {a} | {b} |");
}

fn cells(run: &Run) -> BTreeMap<String, &Cell> {
    run.ingest
        .iter()
        .chain(&run.recall)
        .chain(&run.mixed)
        .chain(
            run.fairness
                .iter()
                .flat_map(|f| [&f.alone, &f.beside_heavy, &f.heavy]),
        )
        .map(|cell| (cell.name.clone(), cell))
        .collect()
}

/// One grade's golden queries across two runs.
#[derive(Default)]
struct Equality {
    equal: usize,
    differ: usize,
    failed_in_a: usize,
    failed_in_b: usize,
    failed_in_both: usize,
    /// Queries of this grade only one run asked.
    asked_by_one: usize,
}

/// Golden rankings per grade between two runs over the same queries; every
/// query of every grade either run asked counts, failures included.
fn ranking_equality(a: &Run, b: &Run) -> Result<BTreeMap<String, Equality>, String> {
    let same = a.golden.len() == b.golden.len()
        && a.golden
            .iter()
            .zip(&b.golden)
            .all(|(qa, qb)| qa.query.text == qb.query.text);
    if !same {
        return Err("the golden queries differ: another seed, scale or --queries".into());
    }
    let mut out = BTreeMap::<String, Equality>::new();
    for (qa, qb) in a.golden.iter().zip(&b.golden) {
        let grades = [qa, qb]
            .iter()
            .flat_map(|q| q.rankings.keys().chain(q.errors.keys()))
            .collect::<BTreeSet<_>>();
        for grade in grades {
            let entry = out.entry(grade.clone()).or_default();
            let asked =
                |q: &GoldenQuery| q.rankings.contains_key(grade) || q.errors.contains_key(grade);
            if !(asked(qa) && asked(qb)) {
                entry.asked_by_one += 1;
                continue;
            }
            match (qa.rankings.get(grade), qb.rankings.get(grade)) {
                (Some(x), Some(y)) if x == y => entry.equal += 1,
                (Some(_), Some(_)) => entry.differ += 1,
                (Some(_), None) => entry.failed_in_b += 1,
                (None, Some(_)) => entry.failed_in_a += 1,
                (None, None) => entry.failed_in_both += 1,
            }
        }
    }
    Ok(out)
}

fn compare_run(out: &mut String, a: &Run, b: &Run) {
    let _ = writeln!(
        out,
        "\n### {} records, vectors {}\n\n| metric | A | B |\n|---|---|---|",
        a.records, a.vectors
    );
    line(
        out,
        "startup empty ready ms",
        &format!("{:.0}", a.startup_empty.ready_ms),
        &format!("{:.0}", b.startup_empty.ready_ms),
    );
    line(
        out,
        "startup full ready ms",
        &format!("{:.0}", a.startup_full.ready_ms),
        &format!("{:.0}", b.startup_full.ready_ms),
    );
    line(
        out,
        "startup full peak HWM MiB",
        &format!("{:.0}", a.startup_full.peak.hwm_mib),
        &format!("{:.0}", b.startup_full.peak.hwm_mib),
    );
    line(
        out,
        "steady RSS MiB",
        &format!("{:.0}", a.steady.rss_mib),
        &format!("{:.0}", b.steady.rss_mib),
    );
    line(out, "secrets setting", &a.secret_scan, &b.secret_scan);
    let (ca, cb) = (cells(a), cells(b));
    for (name, cell) in &ca {
        let Some(other) = cb.get(name) else { continue };
        let fmt = |c: &Cell| {
            if c.summary.latency_status == "not_measured" {
                return format!(
                    "latency not_measured ({}), fail {}; {}",
                    c.summary.latency_reason.as_deref().unwrap_or("no timing"),
                    c.summary.failed,
                    c.secret_scan
                );
            }
            format!(
                "p50 {} p95 {} ms, {:.1}/s, fail {}{}",
                ms(c.summary.p50_ms),
                ms(c.summary.p95_ms),
                c.summary.per_second,
                c.summary.failed,
                if c.summary.partial > 0 {
                    format!(", partial {}", c.summary.partial)
                } else {
                    String::new()
                }
            )
        };
        line(out, name, &fmt(cell), &fmt(other));
    }
    match ranking_equality(a, b) {
        Ok(grades) => {
            for (grade, e) in grades {
                let total = e.equal + e.differ + e.failed_in_a + e.failed_in_b + e.failed_in_both;
                line(
                    out,
                    &format!("golden {grade}: rankings"),
                    &format!("equal {}/{total}, differ {}", e.equal, e.differ),
                    &format!(
                        "failed only in A {}, only in B {}, in both {}; asked by one run {}",
                        e.failed_in_a, e.failed_in_b, e.failed_in_both, e.asked_by_one
                    ),
                );
            }
        }
        Err(error) => line(out, "golden rankings", &error, ""),
    }
    for (grade, hit) in &a.hit_at_10 {
        let other = b
            .hit_at_10
            .get(grade)
            .map_or_else(|| "-".to_owned(), |h| format!("{h:.3}"));
        line(
            out,
            &format!("golden {grade}: hit@10"),
            &format!("{hit:.3}"),
            &other,
        );
    }
}

/// `load compare A.json B.json`: a markdown table of every shared metric.
pub(super) fn compare(a: &Path, b: &Path) -> Result<String, String> {
    let read = |path: &Path| -> Result<Report, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    };
    let (ra, rb) = (read(a)?, read(b)?);
    let mut out = format!(
        "A: {} ({}, {} cpus, load {} → {})\nB: {} ({}, {} cpus, load {} → {})\n",
        ra.label.as_deref().unwrap_or("-"),
        ra.host.hostname,
        ra.host.logical_cpus,
        ra.host.load_start,
        ra.host.load_end,
        rb.label.as_deref().unwrap_or("-"),
        rb.host.hostname,
        rb.host.logical_cpus,
        rb.host.load_start,
        rb.host.load_end,
    );
    for run in &ra.runs {
        if let Some(other) = rb
            .runs
            .iter()
            .find(|o| o.records == run.records && o.vectors == run.vectors)
        {
            compare_run(&mut out, run, other);
        }
    }
    Ok(out)
}
