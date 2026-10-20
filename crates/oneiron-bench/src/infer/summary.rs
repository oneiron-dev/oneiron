//! One summary line per arm: the `ok` rows grouped by (arm_id,
//! config_digest), as a markdown table and as `<out>.summary.json`.
//!
//! A rate column says where it came from: `native` is the engine's own
//! `timings`, `e2e` the client-side estimate a row always carries. VRAM is
//! the sampled reading, never an allocator peak.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde_json::{Value as JsonValue, json};

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
    /// The highest sampled reading on any of the arm's rows.
    pub(super) vram_run_peak_mib: Option<u64>,
    pub(super) quality_mean: Option<f64>,
    pub(super) schema_ok: usize,
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

fn arm(arm_id: String, config_digest: String, rows: &[&JsonValue]) -> ArmSummary {
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
    }
}

/// Every arm the `ok` rows hold, in (arm_id, config_digest) order.
pub(super) fn summarize(rows: &[JsonValue]) -> Vec<ArmSummary> {
    let mut groups: BTreeMap<(String, String), Vec<&JsonValue>> = BTreeMap::new();
    for row in rows.iter().filter(|row| row["status"] == "ok") {
        let (Some(arm_id), Some(digest)) = (row["arm_id"].as_str(), row["config_digest"].as_str())
        else {
            continue;
        };
        groups
            .entry((arm_id.to_owned(), digest.to_owned()))
            .or_default()
            .push(row);
    }
    groups
        .into_iter()
        .map(|((arm_id, digest), rows)| arm(arm_id, digest, &rows))
        .collect()
}

fn cell(value: Option<f64>, digits: usize) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.digits$}"))
}

pub(super) fn markdown(arms: &[ArmSummary]) -> String {
    let mut table = String::from(
        "| arm | config | n | ttft_any ms | ttft_text ms | prefill tok/s | decode tok/s | draft accept | VRAM loaded MiB | VRAM peak MiB (sampled) | quality | schema_ok |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for arm in arms {
        let digest = arm.config_digest.get(..12).unwrap_or(&arm.config_digest);
        table.push_str(&format!(
            "| {} | {digest} | {} | {} | {} | {} {} | {} {} | {} | {} | {} | {} | {}/{} |\n",
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
        ));
    }
    table
}

/// Writes `arms` beside the rows they came from, as `<rows>.summary.json`.
pub(super) fn write_json(rows_path: &Path, arms: &[ArmSummary]) -> Result<(), String> {
    let path = super::sibling(rows_path, ".summary.json");
    let body = json!({
        "schema": "oneiron.infer-bench.summary.v1",
        "rows": rows_path.display().to_string(),
        "arms": arms,
    });
    let text = serde_json::to_string_pretty(&body).map_err(|e| format!("encode summary: {e}"))?;
    std::fs::write(&path, text + "\n").map_err(|e| format!("write {}: {e}", path.display()))
}
