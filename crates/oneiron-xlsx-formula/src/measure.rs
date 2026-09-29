//! Step-19 corpus runner: honest per-case results over the pinned 834 cases.
//!
//! The runner stages each case from `cases.json` on a fresh workbook (no
//! cross-case state), evaluates the anchor cell, and emits one [`CaseResult`]
//! per case. It never invents a golden: `expected` in the fixture is upstream
//! belief, so the report carries the engine value plus a comparison against
//! that belief, and probe cases (expected `null`) are reported, never scored.
//!
//! Statuses are stable machine keys. `unsupported` means the case shape cannot
//! be staged (nested setup values, unreadable range); `error` means the engine
//! refused the case. Both are reported per case; neither is silently dropped
//! or counted as a pass.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::engine::{CellValue, FormualizerEngine, RecalcEngine, StagedValue};
use crate::error::{FormulaError, Result};

/// Default anchor for scalar cases (no `check_range`): `F1`.
pub const DEFAULT_ANCHOR: &str = "F1";

/// One normalized corpus case from `cases.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct CorpusCase {
    /// Stable case id (`ABS_positive_number`).
    pub id: String,
    /// Source function file (`ABS`).
    pub function: String,
    /// UI formula text including the leading `=`.
    pub formula: String,
    /// Setup cells by A1 address. Values starting with `=` are formulas.
    #[serde(default)]
    pub setup_cells: BTreeMap<String, serde_json::Value>,
    /// Upstream expectation (belief, not an Excel golden). `null` = probe.
    pub expected: serde_json::Value,
    /// Spill read range (`A30:B30`); absent for scalar cases.
    pub check_range: Option<String>,
}

/// Runner options. All caps are checked before staging, never mid-case.
#[derive(Debug, Clone)]
pub struct MeasureOptions {
    /// Maximum setup cells per case. Above this the case is `unsupported`.
    pub max_setup_cells: usize,
    /// Maximum formula bytes per case. Above this the case is `unsupported`.
    pub max_formula_bytes: usize,
    /// Maximum grid cells read per case. Above this the case is `unsupported`.
    pub max_grid_cells: usize,
}

impl Default for MeasureOptions {
    fn default() -> Self {
        Self {
            max_setup_cells: 1024,
            max_formula_bytes: 16 * 1024,
            max_grid_cells: 4096,
        }
    }
}

/// One honest per-case outcome. `status` is the stable machine key; `value` is
/// present exactly when the engine evaluated the anchor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseResult {
    /// Case id.
    pub id: String,
    /// Source function.
    pub function: String,
    /// `ok`, `engine-error`, `unsupported`, or `probe`.
    pub status: String,
    /// Engine value at the anchor (scalar or flattened/2-D spill grid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    /// Whether the engine value matches upstream `expected` under the
    /// corpus 1e-9 comparison. `None` for probes and non-`ok` cases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches_upstream: Option<bool>,
    /// Machine detail for non-`ok` cases (error code or upstream message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Whole-corpus outcome: engine stamp plus one row per case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorpusReport {
    /// Engine stamp (`formualizer-workbook 0.9.3 upstream <rev>`).
    pub engine_stamp: String,
    /// Corpus cases pinned hash (sha256 over the raw `cases.json` bytes).
    pub corpus_sha256: String,
    /// Per-case results in corpus order.
    pub cases: BTreeMap<String, CaseResult>,
    /// Counts by status key.
    pub status_counts: BTreeMap<String, usize>,
}

/// Read and hash-pin `cases.json`. The caller passes the expected sha256 (the
/// fixture `provenance.json` value); a mismatch is [`FormulaError::InvalidCorpus`].
pub fn read_corpus_cases(path: &Path, expected_sha256: &str) -> Result<Vec<CorpusCase>> {
    let raw =
        std::fs::read(path).map_err(|_| FormulaError::InvalidCorpus("cases.json unreadable"))?;
    let digest = sha256_hex(&raw);
    if digest != expected_sha256 {
        return Err(FormulaError::InvalidCorpus("cases.json hash mismatch"));
    }
    serde_json::from_slice(&raw).map_err(|_| FormulaError::InvalidCorpus("cases.json malformed"))
}

/// Evaluate one case on a fresh engine. Pure over the case plus options.
pub fn evaluate_case(
    case: &CorpusCase,
    options: &MeasureOptions,
    engine: &mut FormualizerEngine,
) -> CaseResult {
    let probe = case.expected.is_null();
    if case.setup_cells.len() > options.max_setup_cells {
        return unsupported(case, "too-many-setup-cells");
    }
    if case.formula.len() > options.max_formula_bytes {
        return unsupported(case, "formula-too-large");
    }
    let anchor = anchor_for(case);
    let read_range = read_range_for(case, options);
    if case.check_range.is_some() && read_range.is_none() {
        return unsupported(case, "unreadable-check-range");
    }
    let mut setup = BTreeMap::new();
    for (address, value) in &case.setup_cells {
        match staged_value(value) {
            Ok(staged) => {
                setup.insert(address.clone(), staged);
            }
            Err(reason) => return unsupported(case, reason),
        }
    }
    match engine.evaluate(&setup, &case.formula, &anchor, read_range.as_deref()) {
        Ok(report) => {
            let value = report_value(&report.value, report.grid.as_ref(), &case.expected);
            let matches_upstream = if probe {
                None
            } else {
                Some(same_value(&value, &case.expected))
            };
            CaseResult {
                id: case.id.clone(),
                function: case.function.clone(),
                status: if probe {
                    "probe".to_owned()
                } else {
                    "ok".to_owned()
                },
                value: Some(value),
                matches_upstream,
                detail: None,
            }
        }
        Err(error) => CaseResult {
            id: case.id.clone(),
            function: case.function.clone(),
            status: "engine-error".to_owned(),
            value: None,
            matches_upstream: None,
            detail: Some(error_detail(&error)),
        },
    }
}

/// Run every case in order on fresh engine state and summarize by status.
pub fn measure_corpus(
    cases: &[CorpusCase],
    corpus_sha256: &str,
    options: &MeasureOptions,
) -> CorpusReport {
    let mut engine = FormualizerEngine::new();
    let stamp = crate::engine::ENGINE_STAMP.to_owned();
    let mut results = BTreeMap::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for case in cases {
        let result = evaluate_case(case, options, &mut engine);
        *counts.entry(result.status.clone()).or_insert(0) += 1;
        results.insert(case.id.clone(), result);
    }
    CorpusReport {
        engine_stamp: stamp,
        corpus_sha256: corpus_sha256.to_owned(),
        cases: results,
        status_counts: counts,
    }
}

fn unsupported(case: &CorpusCase, reason: &'static str) -> CaseResult {
    CaseResult {
        id: case.id.clone(),
        function: case.function.clone(),
        status: "unsupported".to_owned(),
        value: None,
        matches_upstream: None,
        detail: Some(reason.to_owned()),
    }
}

fn anchor_for(case: &CorpusCase) -> String {
    case.check_range
        .as_deref()
        .and_then(|range| range.split(':').next())
        .unwrap_or(DEFAULT_ANCHOR)
        .to_owned()
}

fn read_range_for(case: &CorpusCase, options: &MeasureOptions) -> Option<String> {
    let range = case.check_range.as_deref()?;
    let (start, end) = range.split_once(':')?;
    let (start_row, start_col) = a1_coords(start)?;
    let (end_row, end_col) = a1_coords(end)?;
    if start_row == 0 || start_col == 0 || end_row < start_row || end_col < start_col {
        return None;
    }
    let cells = (end_row - start_row + 1) as usize * (end_col - start_col + 1) as usize;
    if cells == 0 || cells > options.max_grid_cells {
        return None;
    }
    Some(range.to_owned())
}

fn a1_coords(address: &str) -> Option<(u32, u32)> {
    let split = address.find(|character: char| character.is_ascii_digit())?;
    let (letters, digits) = address.split_at(split);
    if letters.is_empty() || digits.is_empty() {
        return None;
    }
    let mut col: u32 = 0;
    for character in letters.chars() {
        if !character.is_ascii_alphabetic() {
            return None;
        }
        col = col
            .checked_mul(26)?
            .checked_add(u32::from(character.to_ascii_uppercase() as u8 - b'A') + 1)?;
    }
    Some((digits.parse().ok()?, col))
}

fn staged_value(value: &serde_json::Value) -> std::result::Result<StagedValue, &'static str> {
    match value {
        serde_json::Value::Number(number) => number
            .as_f64()
            .map(StagedValue::Number)
            .ok_or("non-finite-setup-number"),
        serde_json::Value::String(text) if text.starts_with('=') => {
            Ok(StagedValue::Formula(text.clone()))
        }
        serde_json::Value::String(text) => Ok(StagedValue::Text(text.clone())),
        serde_json::Value::Bool(flag) => Ok(StagedValue::Bool(*flag)),
        serde_json::Value::Null => Ok(StagedValue::Blank),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => Err("nested-setup-value"),
    }
}

fn report_value(
    scalar: &CellValue,
    grid: Option<&Vec<Vec<CellValue>>>,
    expected: &serde_json::Value,
) -> serde_json::Value {
    match grid {
        None => cell_json(scalar),
        Some(cells) => {
            let flat_expected = expected
                .as_array()
                .is_some_and(|items| items.iter().all(|item| !item.is_array()));
            if flat_expected {
                serde_json::Value::Array(cells.iter().flatten().map(cell_json).collect())
            } else {
                serde_json::Value::Array(
                    cells
                        .iter()
                        .map(|row| serde_json::Value::Array(row.iter().map(cell_json).collect()))
                        .collect(),
                )
            }
        }
    }
}

fn cell_json(value: &CellValue) -> serde_json::Value {
    match value {
        CellValue::Blank => serde_json::Value::Null,
        CellValue::Number(number) => serde_json::Number::from_f64(*number)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        CellValue::Text(text) => serde_json::Value::String(text.clone()),
        CellValue::Bool(flag) => serde_json::Value::Bool(*flag),
        CellValue::Error(kind) => serde_json::Value::String(kind.clone()),
        CellValue::Array(rows) => serde_json::Value::Array(
            rows.iter()
                .map(|row| serde_json::Value::Array(row.iter().map(cell_json).collect()))
                .collect(),
        ),
    }
}

/// Corpus comparison: 1e-9 relative tolerance on finite numbers, exact on
/// strings/bools, bools never equal numbers, shape-exact on arrays.
fn same_value(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match (actual, expected) {
        (serde_json::Value::Bool(left), serde_json::Value::Bool(right)) => left == right,
        (serde_json::Value::Bool(_), _) | (_, serde_json::Value::Bool(_)) => false,
        (serde_json::Value::Number(left), serde_json::Value::Number(right)) => {
            match (left.as_f64(), right.as_f64()) {
                (Some(left), Some(right)) if left.is_finite() && right.is_finite() => {
                    (left - right).abs() <= 1e-9 * right.abs().max(1.0).max(left.abs())
                        || (left - right).abs() <= 1e-10
                }
                _ => false,
            }
        }
        (serde_json::Value::Array(left), serde_json::Value::Array(right)) => {
            left.len() == right.len()
                && left.iter().zip(right.iter()).all(|(a, b)| same_value(a, b))
        }
        (serde_json::Value::String(left), serde_json::Value::String(right)) => left == right,
        (serde_json::Value::Null, serde_json::Value::Null) => true,
        _ => false,
    }
}

fn error_detail(error: &FormulaError) -> String {
    match error {
        FormulaError::Engine(message) => format!("engine-error: {message}"),
        other => other.code().to_owned(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    // The fixture provenance pins sha256 over the raw corpus bytes.
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(
        id: &str,
        formula: &str,
        setup: BTreeMap<String, serde_json::Value>,
        expected: serde_json::Value,
        check_range: Option<String>,
    ) -> CorpusCase {
        CorpusCase {
            id: id.to_owned(),
            function: "TEST".to_owned(),
            formula: formula.to_owned(),
            setup_cells: setup,
            expected,
            check_range,
        }
    }

    #[test]
    fn honest_statuses_cover_ok_probe_unsupported_and_engine_error() {
        let options = MeasureOptions::default();
        let mut engine = FormualizerEngine::new();
        let ok = case("ok", "=1+1", BTreeMap::new(), serde_json::json!(2), None);
        let ok_result = evaluate_case(&ok, &options, &mut engine);
        assert_eq!(ok_result.status, "ok");
        assert_eq!(ok_result.matches_upstream, Some(true));

        let probe = case(
            "probe",
            "=1+1",
            BTreeMap::new(),
            serde_json::Value::Null,
            None,
        );
        let probe_result = evaluate_case(&probe, &options, &mut engine);
        assert_eq!(probe_result.status, "probe");
        assert_eq!(probe_result.matches_upstream, None);

        let mut nested = BTreeMap::new();
        nested.insert("A1".to_owned(), serde_json::json!([1, 2]));
        let unsupported = case("unsupported", "=A1", nested, serde_json::json!(1), None);
        let unsupported_result = evaluate_case(&unsupported, &options, &mut engine);
        assert_eq!(unsupported_result.status, "unsupported");

        let bad_range = case(
            "bad-range",
            "=SUM(A1)",
            BTreeMap::new(),
            serde_json::json!(1),
            Some("ZZZ".to_owned()),
        );
        assert_eq!(
            evaluate_case(&bad_range, &options, &mut engine).status,
            "unsupported"
        );
    }

    #[test]
    fn corpus_comparison_matches_scripts_office_corpus() {
        assert!(same_value(&serde_json::json!(1.0), &serde_json::json!(1)));
        assert!(same_value(
            &serde_json::json!(0.1 + 0.2),
            &serde_json::json!(0.3)
        ));
        assert!(!same_value(&serde_json::json!(true), &serde_json::json!(1)));
        assert!(!same_value(
            &serde_json::json!(f64::NAN),
            &serde_json::json!(1)
        ));
        assert!(same_value(
            &serde_json::json!([[1, 2], [3, 4]]),
            &serde_json::json!([[1, 2], [3, 4]])
        ));
        assert!(!same_value(
            &serde_json::json!([[1, 2]]),
            &serde_json::json!([[1, 2], [3, 4]])
        ));
    }

    #[test]
    fn sha256_pins_corpus_bytes() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
