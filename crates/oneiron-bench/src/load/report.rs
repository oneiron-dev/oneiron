//! The result file, and `load compare`, which reads two of them.

use std::collections::BTreeMap;
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
    pub(super) vectors: bool,
    pub(super) rows: Rows,
    pub(super) mint_seconds: f64,
    pub(super) startup_empty: Startup,
    pub(super) ingest: Vec<Cell>,
    pub(super) drain_seconds: Option<f64>,
    pub(super) steady: Memory,
    pub(super) disk_mib: f64,
    pub(super) golden: Vec<GoldenQuery>,
    /// Per grade: the share of targeted golden queries whose record is in the top 10.
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

/// Golden rankings equal between two runs, per grade: (equal, compared).
fn ranking_equality(a: &Run, b: &Run) -> BTreeMap<String, (usize, usize)> {
    let mut out = BTreeMap::<String, (usize, usize)>::new();
    for (qa, qb) in a.golden.iter().zip(&b.golden) {
        for (grade, ranking) in &qa.rankings {
            if let Some(other) = qb.rankings.get(grade) {
                let entry = out.entry(grade.clone()).or_default();
                entry.1 += 1;
                entry.0 += usize::from(ranking == other);
            }
        }
    }
    out
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
    let (ca, cb) = (cells(a), cells(b));
    for (name, cell) in &ca {
        let Some(other) = cb.get(name) else { continue };
        let fmt = |c: &Cell| {
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
    for (grade, (equal, total)) in ranking_equality(a, b) {
        line(
            out,
            &format!("golden {grade}: equal rankings"),
            &format!("{equal}/{total}"),
            "",
        );
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
