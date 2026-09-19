//! Storage-independent recalc seam over the pinned upstream engine.
//!
//! [`RecalcEngine`] is the trait the docedit pipeline calls: pure over cell
//! maps, no vault, no filesystem, no clock. [`FormualizerEngine`] is the
//! unchanged-upstream implementation behind it, driving the workbook API from
//! `.w7/formula-engine-context.md` verbatim (ephemeral config, `S` sheet,
//! 1-based coordinates, demand-driven `evaluate_cell`, `read_range` spills).
//!
//! Determinism: without the `system-clock` feature there is no ambient clock;
//! volatile functions pin to [`PINNED_TIMESTAMP_UTC`] in UTC via
//! `set_deterministic_mode(Enabled{..})`, never `Local`. The engine stamp on
//! every report is a literal (the upstream crate exposes no version const; an
//! `env!` stamp would name this harness instead).

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, NaiveTime, Timelike, Utc};
use formualizer_common::{DateSystem, LiteralValue, RangeAddress, parse_a1_1based};
use formualizer_eval::engine::DeterministicMode;
use formualizer_eval::timezone::TimeZoneSpec;
use formualizer_workbook::{Workbook, WorkbookConfig};

use crate::error::{FormulaError, Result};

/// Pinned upstream identity. Literal: `formualizer-workbook` exposes no
/// version constant, and `env!` would stamp this harness, not the engine.
pub const ENGINE_NAME: &str = "formualizer-workbook";
/// Pinned upstream version.
pub const ENGINE_VERSION: &str = "0.9.3";
/// Pinned upstream commit (tag `v0.9.3`).
pub const ENGINE_UPSTREAM_REV: &str = "362becffa029d8f77349c2c477fc39eff7fc52d5";
/// Full deterministic stamp recorded on every evaluation report.
pub const ENGINE_STAMP: &str =
    "formualizer-workbook 0.9.3 upstream 362becffa029d8f77349c2c477fc39eff7fc52d5";

/// Fixed instant every volatile function observes. 2026-01-01T00:00:00Z in
/// UTC: deterministic across hosts and timezones, never the wall clock.
pub const PINNED_TIMESTAMP_UTC: &str = "2026-01-01T00:00:00Z";

/// Sheet name the corpus runner stages every case on.
pub const CORPUS_SHEET: &str = "S";

pub use oneiron_docedit::calc::{
    CalcReport as RecalcReport, CalcSetup as StagedValue, CalcValue as CellValue, EngineId,
    RecalcEngine,
};

fn current_engine_id() -> EngineId {
    EngineId {
        engine: ENGINE_NAME.into(),
        version: ENGINE_VERSION.into(),
    }
}

/// Unchanged-upstream [`RecalcEngine`]: `formualizer-workbook 0.9.3`,
/// ephemeral config, deterministic UTC clock.
#[derive(Debug)]
pub struct FormualizerEngine {
    engine_id: EngineId,
}

impl FormualizerEngine {
    /// Build the engine. No I/O; the workbook is created per evaluation so
    /// cases can never leak state into each other.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine_id: current_engine_id(),
        }
    }

    fn fresh_workbook() -> Result<Workbook> {
        let mut workbook = Self::configured_workbook(DateSystem::Excel1900)?;
        workbook
            .add_sheet(CORPUS_SHEET)
            .map_err(|error| FormulaError::Engine(error.to_string()))?;
        Ok(workbook)
    }

    pub(crate) fn configured_workbook(date_system: DateSystem) -> Result<Workbook> {
        let mut config = WorkbookConfig::ephemeral();
        config.eval.date_system = date_system;
        let mut workbook = Workbook::new_with_config(config);
        let timestamp: DateTime<Utc> = PINNED_TIMESTAMP_UTC
            .parse()
            .map_err(|_| FormulaError::Engine("pinned timestamp does not parse".to_owned()))?;
        workbook
            .set_deterministic_mode(DeterministicMode::Enabled {
                timestamp_utc: timestamp,
                timezone: TimeZoneSpec::Utc,
            })
            .map_err(|error| FormulaError::Engine(error.to_string()))?;
        Ok(workbook)
    }
}

impl Default for FormualizerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RecalcEngine for FormualizerEngine {
    type Error = FormulaError;
    fn engine_id(&self) -> EngineId {
        self.engine_id.clone()
    }

    fn evaluate(
        &mut self,
        setup: &BTreeMap<String, StagedValue>,
        formula: &str,
        anchor: &str,
        read_range: Option<&str>,
    ) -> Result<RecalcReport> {
        crate::context::inspect_formula(formula)?;
        for value in setup.values() {
            if let StagedValue::Formula(expression) = value {
                crate::context::inspect_formula(expression)?;
            }
        }
        let mut workbook = Self::fresh_workbook()?;
        for (address, value) in setup {
            let (row, col, _, _) = parse_a1_1based(address)
                .map_err(|_| FormulaError::InvalidAddress("bad setup cell"))?;
            match value {
                StagedValue::Formula(expression) => {
                    // `set_formula` adds a missing `=` itself, but `==1/0`
                    // (a doubled prefix) would not parse: strip the UI `=`.
                    let bare = expression.strip_prefix('=').unwrap_or(expression);
                    workbook
                        .set_formula(CORPUS_SHEET, row, col, bare)
                        .map_err(|error| FormulaError::Engine(error.to_string()))?;
                }
                StagedValue::Number(number) => {
                    stage_value(&mut workbook, row, col, LiteralValue::Number(*number))?;
                }
                StagedValue::Text(text) => {
                    stage_value(&mut workbook, row, col, LiteralValue::Text(text.clone()))?;
                }
                StagedValue::Bool(flag) => {
                    stage_value(&mut workbook, row, col, LiteralValue::Boolean(*flag))?;
                }
                StagedValue::Blank => {
                    stage_value(&mut workbook, row, col, LiteralValue::Empty)?;
                }
            }
        }
        let (anchor_row, anchor_col, _, _) =
            parse_a1_1based(anchor).map_err(|_| FormulaError::InvalidAddress("bad anchor cell"))?;
        // Strip the corpus UI `=` for the same reason as setup formulas.
        let bare_formula = formula.strip_prefix('=').unwrap_or(formula);
        workbook
            .set_formula(CORPUS_SHEET, anchor_row, anchor_col, bare_formula)
            .map_err(|error| FormulaError::Engine(error.to_string()))?;
        let scalar = workbook
            .evaluate_cell(CORPUS_SHEET, anchor_row, anchor_col)
            .map_err(|error| FormulaError::Engine(error.to_string()))?;
        let grid = read_range
            .map(|range| {
                let (start, end) = range
                    .split_once(':')
                    .ok_or(FormulaError::InvalidAddress("bad read range"))?;
                let (start_row, start_col, _, _) = parse_a1_1based(start)
                    .map_err(|_| FormulaError::InvalidAddress("bad read range"))?;
                let (end_row, end_col, _, _) = parse_a1_1based(end)
                    .map_err(|_| FormulaError::InvalidAddress("bad read range"))?;
                let address =
                    RangeAddress::new(CORPUS_SHEET, start_row, start_col, end_row, end_col)
                        .map_err(|_| FormulaError::InvalidAddress("bad read range"))?;
                Ok::<_, FormulaError>(
                    workbook
                        .read_range(&address)
                        .into_iter()
                        .map(|row| row.into_iter().map(from_literal).collect())
                        .collect(),
                )
            })
            .transpose()?;
        Ok(RecalcReport {
            engine: self.engine_id(),
            value: from_literal(scalar),
            grid,
        })
    }
}

/// Stage one literal setup cell, mapping upstream failures to the seam error.
fn stage_value(workbook: &mut Workbook, row: u32, col: u32, staged: LiteralValue) -> Result<()> {
    workbook
        .set_value(CORPUS_SHEET, row, col, staged)
        .map_err(|error| FormulaError::Engine(error.to_string()))
}

/// Convert an upstream scalar to the seam value. Errors collapse to their
/// Excel kind (`#DIV/0!`); the upstream `Display` appends message/context, so
/// only `kind` crosses the seam. Dates and times use Excel's numeric 1900
/// calendar storage representation; pending values are never silent blanks.
pub(crate) fn from_literal(value: LiteralValue) -> CellValue {
    match value {
        LiteralValue::Empty => CellValue::Blank,
        LiteralValue::Number(number) => CellValue::Number(number),
        LiteralValue::Int(int) => CellValue::Number(int as f64),
        LiteralValue::Text(text) => CellValue::Text(text),
        LiteralValue::Boolean(flag) => CellValue::Bool(flag),
        LiteralValue::Error(error) => CellValue::Error(error.kind.to_string()),
        LiteralValue::Array(rows) => CellValue::Array(
            rows.into_iter()
                .map(|row| row.into_iter().map(from_literal).collect())
                .collect(),
        ),
        LiteralValue::Date(date) => CellValue::Number(excel_date(date)),
        LiteralValue::DateTime(datetime) => {
            CellValue::Number(excel_date(datetime.date()) + excel_time(datetime.time()))
        }
        LiteralValue::Time(time) => CellValue::Number(excel_time(time)),
        LiteralValue::Duration(duration) => {
            CellValue::Number(duration.num_milliseconds() as f64 / 86_400_000.0)
        }
        LiteralValue::Pending => CellValue::Error("#CANCELLED!".to_owned()),
    }
}

/// Serialize temporal values using the workbook's own epoch, not the host.
pub(crate) fn from_literal_for_date_system(value: LiteralValue, system: DateSystem) -> CellValue {
    if system == DateSystem::Excel1904 {
        let epoch = NaiveDate::from_ymd_opt(1904, 1, 1).unwrap_or(NaiveDate::MIN);
        match value {
            LiteralValue::Date(date) => {
                return CellValue::Number(date.signed_duration_since(epoch).num_days() as f64);
            }
            LiteralValue::DateTime(datetime) => {
                return CellValue::Number(
                    datetime.date().signed_duration_since(epoch).num_days() as f64
                        + excel_time(datetime.time()),
                );
            }
            other => return from_literal(other),
        }
    }
    from_literal(value)
}

// Serialization only: upstream date evaluation remains unchanged. Excel stores
// dates as serial numbers, including its fictional 1900-02-29 leap day.
fn excel_date(date: NaiveDate) -> f64 {
    let epoch = NaiveDate::from_ymd_opt(1899, 12, 31).unwrap_or(NaiveDate::MIN);
    let leap_cutover = NaiveDate::from_ymd_opt(1900, 3, 1).unwrap_or(NaiveDate::MIN);
    date.signed_duration_since(epoch).num_days() as f64
        + if date >= leap_cutover { 1.0 } else { 0.0 }
}
fn excel_time(time: NaiveTime) -> f64 {
    (f64::from(time.num_seconds_from_midnight()) + f64::from(time.nanosecond()) / 1_000_000_000.0)
        / 86_400.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_time_serialization_matches_excel_storage_not_display_text() {
        let date = NaiveDate::from_ymd_opt(2024, 3, 15).expect("date");
        assert_eq!(
            from_literal(LiteralValue::Date(date)),
            CellValue::Number(45366.0)
        );
        let early = NaiveDate::from_ymd_opt(1900, 2, 28).expect("early date");
        assert_eq!(excel_date(early), 59.0);
        assert_eq!(excel_date(early.succ_opt().expect("March")), 61.0);
        let time = NaiveTime::from_hms_opt(13, 30, 0).expect("time");
        assert_eq!(
            from_literal(LiteralValue::Time(time)),
            CellValue::Number(0.5625)
        );
        assert_eq!(
            from_literal(LiteralValue::DateTime(date.and_time(time))),
            CellValue::Number(45366.5625)
        );
    }
    #[test]
    fn stamp_is_deterministic_and_pinned() {
        assert_eq!("formualizer-workbook/0.9.3", current_engine_id().stamp());
        assert_eq!(ENGINE_NAME, "formualizer-workbook");
        assert_eq!(ENGINE_VERSION, "0.9.3");
        assert_eq!(ENGINE_UPSTREAM_REV.len(), 40);
    }

    #[test]
    fn literal_conversion_keeps_kinds_not_messages() {
        let error = formualizer_common::error::ExcelError::new(
            formualizer_common::error::ExcelErrorKind::Div,
        );
        assert_eq!(
            from_literal(LiteralValue::Error(error)),
            CellValue::Error("#DIV/0!".to_owned())
        );
        assert_eq!(from_literal(LiteralValue::Empty), CellValue::Blank);
        assert_eq!(from_literal(LiteralValue::Int(3)), CellValue::Number(3.0));
    }
}
