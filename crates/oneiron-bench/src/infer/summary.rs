//! One summary line per arm: the clean rows grouped by (arm_id,
//! config_digest), as a markdown table and as `<out>.summary.json`; and the
//! identity tables, which set each case's reply digest beside the same case's
//! under every other arm run at the same draft depth.
//!
//! A rate column says where it came from: `native` is the engine's own
//! `timings`, `e2e` the client-side estimate a row always carries. VRAM is
//! the sampled whole-card reading, never an allocator peak and never one
//! request's own.
//!
//! Rows come in cohorts (`cohort_id`, `cohort_size`): a cohort is complete
//! when every call of it has a row, and clean when every one of those rows is
//! `ok`. A row from before cohorts is a cohort of one. Medians and identity
//! read clean cohorts only, so a partly failed concurrent cohort, whose
//! survivors ran beside a different load, is left out. Client throughput
//! reads complete cohorts, failed calls' time included.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;
use serde_json::{Value as JsonValue, json};

/// A row's cohort: (arm_id, config_digest, cohort_id).
type CohortKey<'a> = (&'a str, &'a str, &'a str);

/// One arm: (arm_id, config_digest).
type ArmKey = (String, String);

/// One case of an identity table: (case_id, case_digest, rep).
type CaseKey = (String, String, u64);

/// One arm's reply digests, by case.
type Digests = BTreeMap<CaseKey, BTreeSet<String>>;

#[derive(Debug, Serialize)]
pub(super) struct ArmSummary {
    pub(super) arm_id: String,
    pub(super) config_digest: String,
    pub(super) transport: Option<String>,
    pub(super) served_model: Option<String>,
    pub(super) n: usize,
    pub(super) ttft_any_ms_median: Option<f64>,
    pub(super) ttft_text_ms_median: Option<f64>,
    pub(super) prefill_tps_median: Option<f64>,
    /// `native` (engine `prompt_per_second`), `e2e` (`prefill_tps_e2e`) or
    /// `none`.
    pub(super) prefill_source: &'static str,
    pub(super) decode_tps_median: Option<f64>,
    /// `native` (engine `predicted_per_second`), `e2e` (`decode_tps_e2e`) or
    /// `none`.
    pub(super) decode_source: &'static str,
    pub(super) draft_n: Option<f64>,
    pub(super) draft_n_accepted: Option<f64>,
    /// Accepted over drafted, summed over the rows that report both.
    pub(super) draft_acceptance: Option<f64>,
    pub(super) vram_loaded_mib_median: Option<f64>,
    /// The highest sampled whole-card reading on any of the arm's rows.
    pub(super) vram_run_peak_mib: Option<u64>,
    pub(super) quality_mean: Option<f64>,
    pub(super) schema_ok: usize,
    /// Client wall-clock output rate over the arm's complete cohorts: the
    /// `ok` rows' output tokens over the cohorts' summed makespans (first
    /// call's start to last call's end), failed calls' time included.
    pub(super) client_tps: Option<f64>,
    /// The complete cohorts that rate covers, and the failed calls in them.
    pub(super) client_cohorts: usize,
    pub(super) client_failed_calls: usize,
}

/// One draft depth's identity table: the arms that ran at it, and each
/// case's reply digest under each of them.
#[derive(Debug, Serialize)]
pub(super) struct Identity {
    /// The engine's reported depth, else the declared one, else `unknown`.
    pub(super) draft_depth: String,
    pub(super) arms: Vec<IdentityArm>,
    pub(super) cases: Vec<IdentityCase>,
    pub(super) equal: usize,
    pub(super) different: usize,
    pub(super) missing: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct IdentityArm {
    pub(super) arm_id: String,
    pub(super) config_digest: String,
}

#[derive(Debug, Serialize)]
pub(super) struct IdentityCase {
    pub(super) case_id: String,
    pub(super) case_digest: String,
    pub(super) rep: u64,
    /// Each arm's `output_digest`s for the case, in `arms` order: none where
    /// it has no clean row, more than one where its own rows disagree.
    pub(super) digests: Vec<Vec<String>>,
    /// `different` when any two digests differ, else `missing` when an arm
    /// has none, else `equal`.
    pub(super) status: &'static str,
}

/// The client throughput of one arm's complete cohorts.
#[derive(Default)]
struct Client {
    tokens: f64,
    makespan_ms: f64,
    cohorts: usize,
    failed: usize,
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    values.retain(|value| value.is_finite());
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    Some(if values.len() % 2 == 0 {
        f64::midpoint(values[mid - 1], values[mid])
    } else {
        values[mid]
    })
}

/// Each row's number at `path`, skipping the rows without one.
fn numbers(rows: &[&JsonValue], path: &[&str]) -> Vec<f64> {
    rows.iter()
        .filter_map(|row| path.iter().fold(*row, |value, key| &value[*key]).as_f64())
        .collect()
}

/// The median of the native rate where any row has one, else of the e2e
/// estimate.
fn rate(rows: &[&JsonValue], native: &str, e2e: &str) -> (Option<f64>, &'static str) {
    let engine = median(numbers(rows, &["native", native]));
    if engine.is_some() {
        return (engine, "native");
    }
    match median(numbers(rows, &[e2e])) {
        Some(estimate) => (Some(estimate), "e2e"),
        None => (None, "none"),
    }
}

/// A row's cohort, or `None` for a row written before cohorts.
fn cohort_key(row: &JsonValue) -> Option<CohortKey<'_>> {
    Some((
        row["arm_id"].as_str()?,
        row["config_digest"].as_str()?,
        row["cohort_id"].as_str()?,
    ))
}

/// Every row that has a cohort, by cohort.
fn cohorts(rows: &[JsonValue]) -> BTreeMap<CohortKey<'_>, Vec<&JsonValue>> {
    let mut groups: BTreeMap<CohortKey<'_>, Vec<&JsonValue>> = BTreeMap::new();
    for row in rows {
        if let Some(key) = cohort_key(row) {
            groups.entry(key).or_default().push(row);
        }
    }
    groups
}

/// Whether every call of a cohort has its row.
fn complete(members: &[&JsonValue]) -> bool {
    members
        .first()
        .and_then(|row| row["cohort_size"].as_u64())
        .and_then(|size| usize::try_from(size).ok())
        .is_some_and(|size| members.len() == size)
}

/// The `ok` rows of clean cohorts, in file order.
fn clean_rows(rows: &[JsonValue]) -> Vec<&JsonValue> {
    let clean: BTreeSet<CohortKey<'_>> = cohorts(rows)
        .into_iter()
        .filter(|(_, members)| complete(members) && members.iter().all(|row| row["status"] == "ok"))
        .map(|(key, _)| key)
        .collect();
    rows.iter()
        .filter(|row| {
            row["status"] == "ok" && cohort_key(row).is_none_or(|key| clean.contains(&key))
        })
        .collect()
}

/// Each arm's client throughput over its complete cohorts. A cohort whose
/// rows lack offsets, or span no time, is left out.
fn client(rows: &[JsonValue]) -> BTreeMap<ArmKey, Client> {
    let mut arms: BTreeMap<ArmKey, Client> = BTreeMap::new();
    for ((arm_id, digest, _), members) in cohorts(rows) {
        if !complete(&members) {
            continue;
        }
        let starts = numbers(&members, &["start_offset_ms"]);
        let ends = numbers(&members, &["end_offset_ms"]);
        if starts.len() != members.len() || ends.len() != members.len() {
            continue;
        }
        let first = starts.iter().copied().fold(f64::INFINITY, f64::min);
        let last = ends.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let span = last - first;
        if span.is_nan() || span <= 0.0 {
            continue;
        }
        let ok: Vec<&JsonValue> = members
            .iter()
            .copied()
            .filter(|row| row["status"] == "ok")
            .collect();
        let arm = arms
            .entry((arm_id.to_owned(), digest.to_owned()))
            .or_default();
        arm.tokens += numbers(&ok, &["output_tokens"]).iter().sum::<f64>();
        arm.makespan_ms += span;
        arm.cohorts += 1;
        arm.failed += members.len() - ok.len();
    }
    arms
}

fn arm(
    arm_id: String,
    config_digest: String,
    rows: &[&JsonValue],
    client: Option<&Client>,
) -> ArmSummary {
    let text = |key: &str| {
        rows.first()
            .and_then(|row| row[key].as_str())
            .map(str::to_owned)
    };
    let (prefill_tps_median, prefill_source) = rate(rows, "prompt_per_second", "prefill_tps_e2e");
    let (decode_tps_median, decode_source) = rate(rows, "predicted_per_second", "decode_tps_e2e");
    let (mut drafted, mut accepted, mut drafting) = (0.0, 0.0, false);
    for row in rows {
        if let (Some(n), Some(ok)) = (
            row["native"]["draft_n"].as_f64(),
            row["native"]["draft_n_accepted"].as_f64(),
        ) {
            drafted += n;
            accepted += ok;
            drafting = true;
        }
    }
    let scores = numbers(rows, &["quality", "score"]);
    ArmSummary {
        arm_id,
        config_digest,
        transport: text("transport"),
        served_model: text("served_model"),
        n: rows.len(),
        ttft_any_ms_median: median(numbers(rows, &["ttft_any_ms"])),
        ttft_text_ms_median: median(numbers(rows, &["ttft_text_ms"])),
        prefill_tps_median,
        prefill_source,
        decode_tps_median,
        decode_source,
        draft_n: drafting.then_some(drafted),
        draft_n_accepted: drafting.then_some(accepted),
        draft_acceptance: (drafting && drafted > 0.0).then_some(accepted / drafted),
        vram_loaded_mib_median: median(numbers(rows, &["vram_loaded_mib"])),
        vram_run_peak_mib: rows
            .iter()
            .flat_map(|row| [&row["vram_case_peak_mib"], &row["vram_loaded_mib"]])
            .filter_map(JsonValue::as_u64)
            .max(),
        quality_mean: (!scores.is_empty())
            .then(|| scores.iter().sum::<f64>() / scores.len() as f64),
        schema_ok: rows
            .iter()
            .filter(|row| row["quality"]["schema_ok"] == true)
            .count(),
        client_tps: client
            .filter(|client| client.cohorts > 0 && client.makespan_ms > 0.0)
            .map(|client| client.tokens / (client.makespan_ms / 1000.0)),
        client_cohorts: client.map_or(0, |client| client.cohorts),
        client_failed_calls: client.map_or(0, |client| client.failed),
    }
}

/// Every arm the clean rows hold, in (arm_id, config_digest) order.
pub(super) fn summarize(rows: &[JsonValue]) -> Vec<ArmSummary> {
    let mut groups: BTreeMap<ArmKey, Vec<&JsonValue>> = BTreeMap::new();
    for row in clean_rows(rows) {
        let (Some(arm_id), Some(digest)) = (row["arm_id"].as_str(), row["config_digest"].as_str())
        else {
            continue;
        };
        groups
            .entry((arm_id.to_owned(), digest.to_owned()))
            .or_default()
            .push(row);
    }
    let clients = client(rows);
    groups
        .into_iter()
        .map(|(key, rows)| {
            let client = clients.get(&key);
            arm(key.0, key.1, &rows, client)
        })
        .collect()
}

/// A row's draft depth: what the engine reported in its timings, else what
/// the run declared, else `unknown`.
fn depth(row: &JsonValue) -> String {
    if let Some(depth) = row["native"]["draft_depth"].as_f64() {
        return format!("{depth:.0}");
    }
    row["draft_depth"]
        .as_u64()
        .map_or_else(|| "unknown".to_owned(), |depth| depth.to_string())
}

fn identity_table(draft_depth: String, arms: BTreeMap<ArmKey, Digests>) -> Identity {
    // One arm alone has nothing to compare: its table lists no case.
    let keys: BTreeSet<&CaseKey> = if arms.len() >= 2 {
        arms.values().flat_map(BTreeMap::keys).collect()
    } else {
        BTreeSet::new()
    };
    let (mut equal, mut different, mut missing) = (0, 0, 0);
    let mut cases = Vec::new();
    for key in keys {
        let digests: Vec<Vec<String>> = arms
            .values()
            .map(|by_case| {
                by_case
                    .get(key)
                    .map_or_else(Vec::new, |set| set.iter().cloned().collect())
            })
            .collect();
        let seen: BTreeSet<&String> = digests.iter().flatten().collect();
        let status = if seen.len() > 1 {
            different += 1;
            "different"
        } else if digests.iter().any(Vec::is_empty) {
            missing += 1;
            "missing"
        } else {
            equal += 1;
            "equal"
        };
        cases.push(IdentityCase {
            case_id: key.0.clone(),
            case_digest: key.1.clone(),
            rep: key.2,
            digests,
            status,
        });
    }
    Identity {
        draft_depth,
        arms: arms
            .into_keys()
            .map(|(arm_id, config_digest)| IdentityArm {
                arm_id,
                config_digest,
            })
            .collect(),
        cases,
        equal,
        different,
        missing,
    }
}

/// The identity tables of the clean rows, one per draft depth: a verify width
/// alone can move a greedy reply, so arms are compared only at one depth.
/// Keyed by (case_id, case_digest, rep); a column per (arm_id,
/// config_digest). An equal `output_digest` is equal reply text, not equal
/// tokens, reasoning or tool calls.
pub(super) fn identity(rows: &[JsonValue]) -> Vec<Identity> {
    let mut depths: BTreeMap<String, BTreeMap<ArmKey, Digests>> = BTreeMap::new();
    for row in clean_rows(rows) {
        let (Some(arm_id), Some(config), Some(case_id), Some(case_digest), Some(rep), Some(digest)) = (
            row["arm_id"].as_str(),
            row["config_digest"].as_str(),
            row["case_id"].as_str(),
            row["case_digest"].as_str(),
            row["rep"].as_u64(),
            row["output_digest"].as_str(),
        ) else {
            continue;
        };
        depths
            .entry(depth(row))
            .or_default()
            .entry((arm_id.to_owned(), config.to_owned()))
            .or_default()
            .entry((case_id.to_owned(), case_digest.to_owned(), rep))
            .or_default()
            .insert(digest.to_owned());
    }
    depths
        .into_iter()
        .map(|(draft_depth, arms)| identity_table(draft_depth, arms))
        .collect()
}

fn cell(value: Option<f64>, digits: usize) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.digits$}"))
}

fn short(digest: &str, len: usize) -> &str {
    digest.get(..len).unwrap_or(digest)
}

pub(super) fn markdown(arms: &[ArmSummary]) -> String {
    let mut table = String::from(
        "| arm | config | n | ttft_any ms | ttft_text ms | prefill tok/s | decode tok/s | draft accept | VRAM loaded MiB | VRAM peak MiB (whole card, sampled) | quality | schema_ok | client tok/s (cohorts, failed) |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for arm in arms {
        let digest = short(&arm.config_digest, 12);
        table.push_str(&format!(
            "| {} | {digest} | {} | {} | {} | {} {} | {} {} | {} | {} | {} | {} | {}/{} | {} ({}, {}) |\n",
            arm.arm_id,
            arm.n,
            cell(arm.ttft_any_ms_median, 1),
            cell(arm.ttft_text_ms_median, 1),
            cell(arm.prefill_tps_median, 1),
            arm.prefill_source,
            cell(arm.decode_tps_median, 1),
            arm.decode_source,
            cell(arm.draft_acceptance, 3),
            cell(arm.vram_loaded_mib_median, 0),
            arm.vram_run_peak_mib
                .map_or_else(|| "-".to_owned(), |peak| peak.to_string()),
            cell(arm.quality_mean, 3),
            arm.schema_ok,
            arm.n,
            cell(arm.client_tps, 1),
            arm.client_cohorts,
            arm.client_failed_calls,
        ));
    }
    table
}

/// The identity tables as markdown: per depth, a row per case and a column
/// per arm, each cell a digest's head, `-` for none, or how many disagree.
pub(super) fn identity_markdown(tables: &[Identity]) -> String {
    let mut out = String::from(
        "Identity: each case's output_digest (reply text only) across arms, at one draft depth\n",
    );
    if tables.is_empty() {
        out.push_str("no clean ok rows to compare\n");
    }
    for table in tables {
        out.push_str(&format!(
            "\ndraft depth {}: {} equal, {} different, {} missing\n",
            table.draft_depth, table.equal, table.different, table.missing
        ));
        if table.arms.len() < 2 {
            let names: Vec<&str> = table.arms.iter().map(|arm| arm.arm_id.as_str()).collect();
            out.push_str(&format!(
                "one arm only ({}): nothing to compare\n",
                names.join(", ")
            ));
            continue;
        }
        out.push_str("| case | rep |");
        for arm in &table.arms {
            out.push_str(&format!(
                " {} {} |",
                arm.arm_id,
                short(&arm.config_digest, 12)
            ));
        }
        out.push_str(" status |\n|---|---|");
        out.push_str(&"---|".repeat(table.arms.len()));
        out.push_str("---|\n");
        for case in &table.cases {
            out.push_str(&format!(
                "| {} {} | {} |",
                case.case_id,
                short(&case.case_digest, 8),
                case.rep
            ));
            for digests in &case.digests {
                let shown = match digests.as_slice() {
                    [] => "-".to_owned(),
                    [one] => short(one, 12).to_owned(),
                    many => format!("{} differ", many.len()),
                };
                out.push_str(&format!(" {shown} |"));
            }
            out.push_str(&format!(" {} |\n", case.status));
        }
    }
    out
}

/// Writes `arms` and the identity `tables` beside the rows they came from,
/// as `<rows>.summary.json`.
pub(super) fn write_json(
    rows_path: &Path,
    arms: &[ArmSummary],
    tables: &[Identity],
) -> Result<(), String> {
    let path = super::sibling(rows_path, ".summary.json");
    let body = json!({
        "schema": "oneiron.infer-bench.summary.v1",
        "rows": rows_path.display().to_string(),
        "arms": arms,
        "identity": tables,
    });
    let text = serde_json::to_string_pretty(&body).map_err(|e| format!("encode summary: {e}"))?;
    std::fs::write(&path, text + "\n").map_err(|e| format!("write {}: {e}", path.display()))
}
