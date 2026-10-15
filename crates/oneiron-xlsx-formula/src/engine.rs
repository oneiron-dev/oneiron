//! The owned formualizer engine behind the [`RecalcEngine`] seam.
//!
//! [`FormualizerEngine`] drives the upstream workbook API with an ephemeral
//! config, the `S` corpus sheet, 1-based coordinates, demand-driven
//! `evaluate_cell` and `read_range` spills.
//!
//! Determinism: the corpus workbook pins volatile functions to
//! [`PINNED_TIMESTAMP_UTC`] in UTC via `set_deterministic_mode(Enabled{..})`,
//! never `Local`, although the cache writer's `xlsx-recalc` feature turns on
//! the upstream `system-clock` feature. The engine stamp on
//! every report is a literal (the upstream crate exposes no version const; an
//! `env!` stamp would name this harness instead).

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, NaiveTime, Timelike, Utc};
use formualizer_common::{DateSystem, LiteralValue, RangeAddress, parse_a1_1based};
use formualizer_eval::engine::DeterministicMode;
use formualizer_eval::timezone::TimeZoneSpec;
use formualizer_workbook::{Workbook, WorkbookConfig};

use crate::error::{FormulaError, Result};
use crate::xml::unsupported;

/// Pinned upstream identity. Literal: `formualizer-workbook` exposes no
/// version constant, and `env!` would stamp this harness, not the engine.
pub const ENGINE_NAME: &str = "formualizer-workbook";
/// Owned evaluator version; upstream plus the error-concatenation repair and the Excel
/// parity work on the fork's `oneiron/parity` branch (ONE-2700 part 1).
pub const ENGINE_VERSION: &str = "0.9.3-oneiron.12";
/// Pinned upstream commit (tag `v0.9.3`).
pub const ENGINE_UPSTREAM_REV: &str = "362becffa029d8f77349c2c477fc39eff7fc52d5";
/// Full deterministic stamp recorded on every evaluation report.
pub const ENGINE_STAMP: &str =
    "formualizer-workbook 0.9.3-oneiron.12 upstream 362becffa029d8f77349c2c477fc39eff7fc52d5";

/// Fixed instant every volatile function observes. 2026-01-01T00:00:00Z in
/// UTC: deterministic across hosts and timezones, never the wall clock.
pub const PINNED_TIMESTAMP_UTC: &str = "2026-01-01T00:00:00Z";

/// Sheet name the corpus runner stages every case on.
pub const CORPUS_SHEET: &str = "S";

/// The most cells [`FormualizerEngine`] reads back through `read_range` in
/// one [`RecalcEngine::evaluate`]. A larger rectangle is refused before the
/// workbook materializes it, whoever the caller is.
pub const MAX_READ_RANGE_CELLS: usize = 4096;

/// The largest sheet extent (last row times last column) one
/// [`RecalcEngine::evaluate`] may stage its anchor and setup cells in. The
/// workbook allocates storage for the whole rectangle up to the farthest cell
/// it writes, so one cell at `XFD1048576` would cost gigabytes; the formula
/// corpus stays within 128 cells.
pub const MAX_STAGED_EXTENT_CELLS: u64 = 1 << 20;

pub use crate::calc::{
    CalcReport as RecalcReport, CalcSetup as StagedValue, CalcValue as CellValue, EngineId,
    RecalcEngine,
};

fn current_engine_id() -> EngineId {
    EngineId {
        engine: ENGINE_NAME.into(),
        version: ENGINE_VERSION.into(),
    }
}

/// Owned [`RecalcEngine`], based on `formualizer-workbook 0.9.3`,
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
        let mut config = WorkbookConfig::ephemeral();
        config.eval.date_system = DateSystem::Excel1900;
        config.eval.worker_stack_bytes = Some(crate::context::EVAL_STACK_BYTES);
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
        workbook
            .add_sheet(CORPUS_SHEET)
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
        check_addresses(setup, anchor, read_range)?;
        crate::context::inspect_formula(formula)?;
        for value in setup.values() {
            if let StagedValue::Formula(expression) = value {
                crate::context::inspect_formula(expression)?;
            }
        }
        let engine = self.engine_id();
        // Evaluate where the writer does: on a stack for the longest formula
        // Excel saves (`crate::context`).
        crate::context::on_eval_stack(|| {
            Self::evaluate_here(setup, formula, anchor, read_range, engine)
        })
    }
}

impl FormualizerEngine {
    fn evaluate_here(
        setup: &BTreeMap<String, StagedValue>,
        formula: &str,
        anchor: &str,
        read_range: Option<&str>,
        engine: EngineId,
    ) -> Result<RecalcReport> {
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
                let address = read_range_address(range)?;
                Ok::<_, FormulaError>(
                    workbook
                        .read_range(&address)
                        .into_iter()
                        .map(|row| row.into_iter().map(from_literal).collect())
                        .collect(),
                )
            })
            .transpose()?;
        // What the engine notes out of band, where a formula may have caught
        // the cell error it returned, the writer refuses (`cache_recalculate`),
        // and so does this door.
        let noted = workbook.engine();
        for (seen, feature) in [
            (
                noted.split_character(),
                "a join cut through a character outside the Basic Multilingual Plane",
            ),
            (
                noted.spill_reference_cycle(),
                "a circular reference through a spill reference",
            ),
            (
                noted.text_named_workbook(),
                "INDIRECT text that names a workbook",
            ),
        ] {
            if seen {
                return Err(unsupported(format!("{feature} (workbook)")));
            }
        }
        Ok(RecalcReport {
            engine,
            value: from_literal(scalar),
            grid,
        })
    }
}

/// Check every address before a workbook exists: the anchor and setup cells
/// must parse and stay within [`MAX_STAGED_EXTENT_CELLS`], and the read range
/// within [`MAX_READ_RANGE_CELLS`].
fn check_addresses(
    setup: &BTreeMap<String, StagedValue>,
    anchor: &str,
    read_range: Option<&str>,
) -> Result<()> {
    let cell = |address: &str, reason| {
        parse_a1_1based(address)
            .map(|(row, col, _, _)| (row, col))
            .map_err(|_| FormulaError::InvalidAddress(reason))
    };
    let (mut rows, mut cols) = cell(anchor, "bad anchor cell")?;
    for address in setup.keys() {
        let (row, col) = cell(address, "bad setup cell")?;
        rows = rows.max(row);
        cols = cols.max(col);
    }
    if u64::from(rows) * u64::from(cols) > MAX_STAGED_EXTENT_CELLS {
        return Err(FormulaError::InvalidAddress(
            "staged cells over the extent limit",
        ));
    }
    read_range.map(read_range_address).transpose()?;
    Ok(())
}

/// The read range's address, refused over [`MAX_READ_RANGE_CELLS`].
fn read_range_address(range: &str) -> Result<RangeAddress> {
    let bad = || FormulaError::InvalidAddress("bad read range");
    let (start, end) = range.split_once(':').ok_or_else(bad)?;
    let (start_row, start_col, _, _) = parse_a1_1based(start).map_err(|_| bad())?;
    let (end_row, end_col, _, _) = parse_a1_1based(end).map_err(|_| bad())?;
    let address = RangeAddress::new(CORPUS_SHEET, start_row, start_col, end_row, end_col)
        .map_err(|_| bad())?;
    if u64::from(address.width()) * u64::from(address.height()) > MAX_READ_RANGE_CELLS as u64 {
        return Err(FormulaError::InvalidAddress(
            "read range over the cell limit",
        ));
    }
    Ok(address)
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
    fn evaluate_refuses_a_read_range_over_the_cell_limit_before_reading_it() {
        // C11: the read range was materialized whole, so `A1:XFD1048576`
        // asked for 17 billion cells.
        let mut engine = FormualizerEngine::new();
        let mut read = |range: &str| engine.evaluate(&BTreeMap::new(), "=1", "A1", Some(range));
        let over = FormulaError::InvalidAddress("read range over the cell limit");
        assert_eq!(read("A1:A4097"), Err(over.clone()));
        assert_eq!(read("A1:XFD1048576"), Err(over.clone()));
        assert_eq!(read("A1:BL65"), Err(over));
        // Exactly at the limit still evaluates and reads back every cell.
        for range in ["A1:A4096", "A1:BL64"] {
            let grid = read(range).expect("a read range at the limit").grid;
            let cells: usize = grid.expect("grid").iter().map(Vec::len).sum();
            assert_eq!(cells, MAX_READ_RANGE_CELLS);
        }
    }

    #[test]
    fn evaluate_refuses_a_far_cell_before_the_workbook_allocates_up_to_it() {
        // C11 (Sol r1): one cell at the sheet's far corner made the workbook
        // allocate every row of every column up to it, 16 GiB, before the
        // read range was checked.
        let mut engine = FormualizerEngine::new();
        let over = Err(FormulaError::InvalidAddress(
            "staged cells over the extent limit",
        ));
        let far = BTreeMap::from([("XFD1048576".to_owned(), StagedValue::Number(1.0))]);
        assert_eq!(engine.evaluate(&far, "=1", "A1", Some("A1:A1")), over);
        assert_eq!(
            engine.evaluate(&BTreeMap::new(), "=1", "XFD1048576", None),
            over
        );
        assert_eq!(
            engine.evaluate(&BTreeMap::new(), "=1", "B1048576", None),
            over
        );
        // A sheet as wide or as tall as Excel's still stages its far cell.
        for anchor in ["A1048576", "XFD64"] {
            let report = engine.evaluate(&BTreeMap::new(), "=1", anchor, None);
            assert_eq!(
                report.expect("within the extent").value,
                CellValue::Number(1.0)
            );
        }
        // The corpus case with the widest extent (WRAPROWS_2: 31 rows by 4
        // columns) still evaluates and reads back its spill.
        let setup = BTreeMap::from(
            [("A1", 1.0), ("B1", 2.0), ("C1", 3.0), ("D1", 4.0)]
                .map(|(cell, value)| (cell.to_owned(), StagedValue::Number(value))),
        );
        let report = engine
            .evaluate(&setup, "=WRAPROWS(A1:D1,2)", "A30", Some("A30:B31"))
            .expect("corpus case");
        let number = CellValue::Number;
        assert_eq!(
            report.grid,
            Some(vec![
                vec![number(1.0), number(2.0)],
                vec![number(3.0), number(4.0)]
            ])
        );
    }

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
}
