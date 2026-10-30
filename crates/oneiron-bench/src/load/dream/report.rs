//! The `load dream` result: the JSON report and the 15-line summary on
//! stdout. The report holds ids, counts, ms and the recall query strings,
//! never the model key.

use serde_json::{Value, json};

use super::super::stats::{Sample, Summary};
use super::cycle::{self, DreamerStatus, Tick};
use super::proof::Tried;
use super::server_log::{Fields, Scan, Seen, number};
use super::{AFTER, Cycle, Run, Seeded, turns};

/// Everything the report is written from.
pub(super) struct Measured<'a> {
    pub(super) run: &'a Run<'a>,
    pub(super) seeded: &'a Seeded,
    pub(super) baseline: Summary,
    pub(super) cycle: &'a Cycle,
    pub(super) scan: &'a Scan,
    pub(super) landed: &'a [String],
    pub(super) source: &'static str,
    pub(super) tried: &'a [Tried],
    pub(super) status_after: Option<DreamerStatus>,
}

/// Fields that stay text though they may read as numbers.
const TEXT_FIELDS: [&str; 6] = [
    "attempt",
    "landed_ids",
    "outcome",
    "scope",
    "stop",
    "trigger",
];

/// A line's fields as JSON: numbers as numbers, the rest as text.
fn fields_json(fields: &Fields) -> Value {
    fields
        .iter()
        .map(|(key, value)| {
            let text = || Value::from(value.clone());
            let parsed = if TEXT_FIELDS.contains(&key.as_str()) {
                text()
            } else {
                value
                    .parse::<u64>()
                    .map(Value::from)
                    .or_else(|_| value.parse::<f64>().map(Value::from))
                    .unwrap_or_else(|_| text())
            };
            (key.clone(), parsed)
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// The lines read from `from_ms` on, each with when it was read after t0.
fn lines_json(lines: &[Seen], from_ms: f64, t0_ms: f64) -> Vec<Value> {
    lines
        .iter()
        .filter(|seen| seen.at_ms >= from_ms)
        .map(|seen| {
            let mut line = fields_json(&seen.fields);
            line["read_ms_after_t0"] = json!(seen.at_ms - t0_ms);
            line
        })
        .collect()
}

/// The sum of a numeric field over the lines read at or after `from_ms`, and
/// how many of them carried it.
fn field_sum(lines: &[Seen], from_ms: f64, key: &str) -> (f64, usize) {
    lines
        .iter()
        .filter(|seen| seen.at_ms >= from_ms)
        .filter_map(|seen| number(&seen.fields, key))
        .fold((0.0, 0), |(sum, n), x| (sum + x, n + 1))
}

/// The loop's recalls that started in `[from_ms, to_ms)`.
fn window(ticks: &[Tick], from_ms: f64, to_ms: f64) -> Summary {
    let samples = ticks
        .iter()
        .filter(|tick| (from_ms..to_ms).contains(&tick.at_ms))
        .map(|tick| Sample {
            ms: tick.ms,
            error: tick.error.clone(),
            partial: false,
            items: tick.items,
        })
        .collect::<Vec<_>>();
    Summary::of(&samples, (to_ms - from_ms).max(0.0) / 1000.0)
}

/// The report's `cycle` part: how the round ended, its stage lines and
/// pass lines, their sums, and the Dreamer's status around it.
fn cycle_json(m: &Measured<'_>) -> Value {
    let (t0, end) = (m.cycle.t0_ms, m.cycle.waited.end_ms);
    let stages = &m.scan.stages;
    let stage_ms = [
        "prep_ms",
        "branch_ms",
        "extract_ms",
        "corrections_ms",
        "resolve_ms",
        "gap_ms",
        "commit_ms",
        "total_ms",
    ]
    .iter()
    .map(|key| ((*key).to_owned(), json!(field_sum(stages, t0, key).0)))
    .collect::<serde_json::Map<_, _>>();
    let per_pass = m
        .scan
        .passes
        .iter()
        .filter(|seen| seen.at_ms >= t0)
        .map(|seen| json!(number(&seen.fields, "snapshot_at_exports")))
        .collect::<Vec<_>>();
    let exports = json!({
        "per_pass": per_pass,
        "passes_sum": field_sum(&m.scan.passes, t0, "snapshot_at_exports").0,
        "pass_lines_counting": field_sum(&m.scan.passes, t0, "snapshot_at_exports").1,
        "partitions_sum": field_sum(stages, t0, "snapshot_at_exports").0,
        "partition_lines_counting": field_sum(stages, t0, "snapshot_at_exports").1,
    });
    let before = json!({
        "stages": stages.iter().filter(|s| s.at_ms < t0).count(),
        "passes": m.scan.passes.iter().filter(|s| s.at_ms < t0).count(),
    });
    let waited = &m.cycle.waited;
    let first_line = stages
        .iter()
        .filter(|s| s.at_ms >= t0)
        .map(|s| s.at_ms - t0)
        .reduce(f64::min);
    json!({
        "end_reason": waited.reason,
        "wall_ms": end - t0,
        "first_stage_line_ms_after_t0": first_line,
        "bound_s": m.run.plan.cycle_timeout.as_secs(),
        "partition_attempts": cycle::outcomes(m.scan, t0).0.len(),
        "outcomes": cycle::outcomes(m.scan, t0).0,
        "turns_planned": field_sum(stages, t0, "turns").0,
        "stage_ms_sum": stage_ms,
        "landed": field_sum(stages, t0, "landed").0,
        "rejected": field_sum(stages, t0, "rejected").0,
        "snapshot_at_exports": exports,
        "stage_lines": lines_json(stages, t0, t0),
        "pass_lines": lines_json(&m.scan.passes, t0, t0),
        "lines_before_t0": before,
        "stage_lines_logged": m.scan.observed(),
        "status_before": waited.status_before,
        "status_end": waited.status_end,
        "status_after": m.status_after,
        "status_reads": waited.status_reads,
        "status_errors": waited.status_errors,
    })
}

/// The report's `recalls` part: the baseline, and the loop's recalls before
/// t0, during the cycle and in the `AFTER` that followed it.
fn recalls_json(m: &Measured<'_>) -> Value {
    let (t0, end) = (m.cycle.t0_ms, m.cycle.waited.end_ms);
    let ticks = &m.cycle.ticks;
    let first = ticks.first().map_or(t0, |tick| tick.at_ms);
    let after_ms = AFTER.as_secs_f64() * 1000.0;
    let ticks_json = ticks
        .iter()
        .map(|tick| {
            json!({
                "start_ms_after_t0": tick.at_ms - t0,
                "ms": tick.ms,
                "ok": tick.error.is_none(),
                "error": tick.error,
                "items": tick.items,
                "query": tick.query,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "effort": "light",
        "limit": cycle::RECALL_LIMIT,
        "every_ms": m.run.plan.recall_every.as_secs_f64() * 1000.0,
        "queries": m.run.queries,
        "baseline": m.baseline,
        "loop_before_t0": window(ticks, first, t0),
        "during": window(ticks, t0, end),
        // The loop stops `AFTER` past the end, give or take one step.
        "after": window(ticks, end, end + after_ms + 1000.0),
        "loop": ticks_json,
    })
}

pub(super) fn report(m: &Measured<'_>) -> Value {
    let (t0, end) = (m.cycle.t0_ms, m.cycle.waited.end_ms);
    let in_cycle = |at_ms: f64| (t0..=end).contains(&at_ms);
    let mut first = Vec::<&str>::new();
    for alarm in m.scan.alarms.iter().filter(|a| in_cycle(a.at_ms)) {
        if first.len() < 5 && !first.contains(&alarm.message.as_str()) {
            first.push(&alarm.message);
        }
    }
    let count = |level: &str, all: bool| {
        m.scan
            .alarms
            .iter()
            .filter(|a| a.level == level && (all || in_cycle(a.at_ms)))
            .count()
    };
    let server_log = json!({
        "warn_during_cycle": count("warn", false),
        "error_during_cycle": count("error", false),
        "first_messages_during_cycle": first,
        "warn_total": count("warn", true),
        "error_total": count("error", true),
    });
    let found = m.tried.iter().filter(|t| t.found).count();
    let reason = m.cycle.waited.reason.as_str();
    let ended = reason != "timeout"
        && !reason.starts_with("dreamer_idle")
        && !reason.starts_with("end_refused");
    let during = window(&m.cycle.ticks, t0, end);
    let counted = field_sum(&m.scan.passes, t0, "snapshot_at_exports").1
        + field_sum(&m.scan.stages, t0, "snapshot_at_exports").1;
    let landed = field_sum(&m.scan.stages, t0, "landed").0;
    let verdicts = json!({
        "1_consolidation_row_landed":
            landed > 0.0 || (m.source != "stage_lines" && !m.landed.is_empty()),
        "2_recall_finds_landed_row": found > 0,
        "3_no_hang": ended && during.completed > 0 && during.failed == 0,
        "4_snapshot_at_exports_counted": counted > 0,
        "5_timed": m.scan.stages.iter().any(|s| s.at_ms >= t0) && !m.cycle.ticks.is_empty(),
    });
    let seed = json!({
        "ms": m.seeded.seconds * 1000.0,
        "writes": m.seeded.witness.len() + m.seeded.claims.len(),
        "witness": Summary::of(&m.seeded.witness, m.seeded.seconds),
        "claims_upsert": Summary::of(&m.seeded.claims, m.seeded.seconds),
        "activity_hints": m.seeded.activity_hints,
        "hint_errors": m.seeded.hint_errors,
        // No facade read names a sitting's turns: the turns the round
        // planned show in the stage lines' `turns`.
        "sitting_membership": "not readable on the facade; see cycle.turns_planned",
    });
    let corpus = json!({
        "path": m.run.plan.corpus.display().to_string(),
        "selection": turns::Counts::of(m.run.turns),
        "notes_seeded": m.run.plan.notes,
    });
    let proof = json!({
        "landed_ids": m.landed,
        "landed_ids_source": m.source,
        "tried": m.tried,
        "found": found,
    });
    json!({
        "bench": "oneiron-bench load dream v1",
        "corpus": corpus,
        "seed": seed,
        "t0_ms_since_start": t0,
        "cycle": cycle_json(m),
        "proof": proof,
        "recalls": recalls_json(m),
        "server_log": server_log,
        "pass": verdicts,
    })
}

/// A JSON number as text, or `-`.
fn ms_text(value: &Value) -> String {
    value
        .as_f64()
        .map_or_else(|| "-".to_owned(), |x| format!("{x:.0}"))
}

/// Yes or no.
fn yes(value: &Value) -> &'static str {
    if value.as_bool() == Some(true) {
        "yes"
    } else {
        "no"
    }
}

/// p50 / p95 / max of a summary, in ms.
fn spread(summary: &Value) -> String {
    format!(
        "n {} failed {} p50 {} p95 {} max {} ms",
        summary["completed"],
        summary["failed"],
        ms_text(&summary["p50_ms"]),
        ms_text(&summary["p95_ms"]),
        ms_text(&summary["max_ms"])
    )
}

/// The 15-line summary on stdout.
pub(super) fn summary(r: &Value) -> String {
    let c = &r["cycle"];
    let s = &c["stage_ms_sum"];
    let x = &c["snapshot_at_exports"];
    let p = &r["pass"];
    let best = r["proof"]["tried"]
        .as_array()
        .and_then(|tried| tried.iter().filter_map(|t| t["rank"].as_u64()).min());
    [
        format!(
            "load dream {}: {} after {} ms (bound {} s)",
            r["label"].as_str().unwrap_or("-"),
            c["end_reason"].as_str().unwrap_or("-"),
            ms_text(&c["wall_ms"]),
            c["bound_s"]
        ),
        format!(
            "model {} preflight {} ms; server {}",
            r["model"]["reply_model"].as_str().unwrap_or("-"),
            ms_text(&r["model"]["preflight_ms"]),
            r["server"]["version"].as_str().unwrap_or("-")
        ),
        format!(
            "seed: {} turns, {} messages, {} writes in {} ms",
            r["corpus"]["selection"]["turns"],
            r["corpus"]["selection"]["messages"],
            r["seed"]["writes"],
            ms_text(&r["seed"]["ms"])
        ),
        format!(
            "partitions: {} attempts, {} turns planned, {} stage lines, {} pass lines",
            c["partition_attempts"],
            ms_text(&c["turns_planned"]),
            c["stage_lines"].as_array().map_or(0, Vec::len),
            c["pass_lines"].as_array().map_or(0, Vec::len)
        ),
        format!(
            "stage ms (sum): prep {} branch {} extract {} corrections {} resolve {} gap {} commit {} total {}",
            ms_text(&s["prep_ms"]),
            ms_text(&s["branch_ms"]),
            ms_text(&s["extract_ms"]),
            ms_text(&s["corrections_ms"]),
            ms_text(&s["resolve_ms"]),
            ms_text(&s["gap_ms"]),
            ms_text(&s["commit_ms"]),
            ms_text(&s["total_ms"])
        ),
        format!(
            "landed {} rejected {}; SnapshotAt exports: passes {} (per pass {}), partitions {}",
            ms_text(&c["landed"]),
            ms_text(&c["rejected"]),
            ms_text(&x["passes_sum"]),
            x["per_pass"],
            ms_text(&x["partitions_sum"])
        ),
        format!(
            "1 consolidation row landed: {}",
            yes(&p["1_consolidation_row_landed"])
        ),
        format!(
            "2 recall finds a landed row: {} ({} of {} tried, best rank {}; ids from {})",
            yes(&p["2_recall_finds_landed_row"]),
            r["proof"]["found"],
            r["proof"]["tried"].as_array().map_or(0, Vec::len),
            best.map_or_else(|| "-".to_owned(), |rank| rank.to_string()),
            r["proof"]["landed_ids_source"].as_str().unwrap_or("-")
        ),
        format!("3 no hang: {}", yes(&p["3_no_hang"])),
        format!(
            "4 SnapshotAt exports counted: {}",
            yes(&p["4_snapshot_at_exports_counted"])
        ),
        format!("5 timed: {}", yes(&p["5_timed"])),
        format!("recall baseline: {}", spread(&r["recalls"]["baseline"])),
        format!("recall during:   {}", spread(&r["recalls"]["during"])),
        format!("recall after:    {}", spread(&r["recalls"]["after"])),
        format!(
            "server log during the cycle: {} warn, {} error",
            r["server_log"]["warn_during_cycle"], r["server_log"]["error_during_cycle"]
        ),
    ]
    .join("\n")
}
