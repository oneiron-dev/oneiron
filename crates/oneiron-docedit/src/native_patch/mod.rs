//! Native tables and bounded classic charts (ARCH-0077 "Creation operation",
//! "Chart and table edits"). One [`native_patch`] call writes a table, or a
//! chart's XML, its caches and its embedded workbook, as one checked
//! operation: it runs on a copy of the package, compares the parts it
//! actually changed with the parts the edit may touch, re-imports a chart to
//! prove every touched cache equals its workbook cells, and only then lands.
//! Formula-backed, external, shared and length-changing writes refuse.
mod chart;
mod table;
mod workbook;

use crate::deck::Placeholder;
use crate::design_plan::{Cell, Dataset, Rect};
use crate::ooxml::XmlError;
use crate::retained_opc::{self, Package};

pub use chart::{ChartData, Sequence, SeriesData, chart_data};
pub(crate) use table::{insert_frame, placeholder_xml};
pub(crate) use workbook::{header, number, serial};

/// Where a new graphic frame goes: the slide part, its new `p:cNvPr` id
/// (unique in the slide) and name, its bounds, and the layout placeholder it
/// fills, if any.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub slide: &'a str,
    pub id: u32,
    pub name: &'a str,
    pub bounds: Rect,
    pub placeholder: Option<&'a Placeholder>,
}

/// A merge rectangle over the table grid, header row 0 included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Merge {
    pub row: usize,
    pub col: usize,
    pub rows: usize,
    pub cols: usize,
}

/// The classic families creation writes. Edits accept every classic plot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChartFamily {
    Bar,
    Line,
    Pie,
}

/// One series sequence: its name, its categories (`c:cat`, or `c:xVal` on a
/// scatter plot), or its values (`c:val` or `c:yVal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Name,
    Categories,
    Values,
}

#[derive(Debug, Clone, Copy)]
pub enum NativeEdit<'a> {
    /// A table from a dataset: a header row of column names, then its rows.
    CreateTable {
        frame: Frame<'a>,
        dataset: &'a Dataset,
        merges: &'a [Merge],
    },
    /// A chart part and its embedded workbook from a dataset: the first
    /// column is the categories, every later column one series.
    CreateChart {
        frame: Frame<'a>,
        family: ChartFamily,
        dataset: &'a Dataset,
        chart: &'a str,
        workbook: &'a str,
        /// The workbook's one sheet name, from the caller's configuration.
        sheet: &'a str,
    },
    /// One table cell's text, by grid position; `expected` is the current
    /// text, paragraphs joined by `\n`.
    SetTableCell {
        slide: &'a str,
        table: u32,
        row: usize,
        col: usize,
        expected: &'a str,
        value: &'a str,
    },
    /// Same-length replacement of one series sequence, caches and source
    /// cells together.
    SetSeries {
        chart: &'a str,
        series: usize,
        target: Target,
        values: &'a [Cell],
    },
}

/// What one operation changed, as an export would carry it.
#[derive(Debug, Clone, PartialEq)]
pub struct NativeReport {
    pub changed_parts: Vec<String>,
    pub workbook: Option<WorkbookReport>,
}

/// The nested report of the embedded workbook write.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkbookReport {
    /// The workbook's part in the deck.
    pub part: String,
    /// Parts changed inside the workbook package.
    pub changed_parts: Vec<String>,
    pub cells: Vec<CellWrite>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CellWrite {
    pub sheet: String,
    /// A1 reference.
    pub cell: String,
    pub value: Cell,
}

/// A typed refusal; the package is unchanged after every one of them.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum NativeRefusal {
    #[error("external chart source: {0}")]
    ExternalChartSource(&'static str),
    #[error("formula-backed series: {0}")]
    FormulaBackedSeries(&'static str),
    #[error("ambiguous chart data: {0}")]
    AmbiguousChartData(&'static str),
    #[error("chart data shared with another part")]
    SharedChartData,
    #[error("unsupported chart family: {0}")]
    UnsupportedChartFamily(&'static str),
    #[error("write to a merged continuation cell")]
    MergedContinuationCell,
    #[error("unsupported merge topology: {0}")]
    UnsupportedMergeTopology(&'static str),
    /// Same-length replacement is the only supported chart write.
    #[error("series length change from {have} to {want}")]
    LengthChange { have: usize, want: usize },
    #[error("stale or missing target: {0}")]
    Stale(&'static str),
    #[error("invalid edit: {0}")]
    Invalid(&'static str),
    #[error("a re-imported cache differs from its workbook cells")]
    CacheMismatch,
    #[error("changed part outside the edit's allowed set: {0}")]
    OutsideAllowedParts(String),
    #[error("embedded workbook: {0}")]
    Workbook(retained_opc::Error),
    #[error(transparent)]
    Package(#[from] retained_opc::Error),
    #[error(transparent)]
    Xml(#[from] XmlError),
}

const CHART_TYPE: &str = "application/vnd.openxmlformats-officedocument.drawingml.chart+xml";
const XLSX_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/// A new embedded chart workbook for `dataset`, as chart creation writes
/// one: row 1 holds the headers, then one row per dataset row, on one sheet.
pub(crate) fn chart_workbook(
    dataset: &Dataset,
    sheet: &str,
    limits: retained_opc::Limits,
) -> Result<Vec<u8>, NativeRefusal> {
    workbook::create(dataset, sheet, limits)
}

/// Apply one native edit as a single checked operation; on any refusal the
/// package is left exactly as it was.
pub fn native_patch(
    package: &mut Package,
    edit: &NativeEdit<'_>,
) -> Result<NativeReport, NativeRefusal> {
    let mut next = package.clone();
    let mut workbook = None;
    let allowed: Vec<String> = match *edit {
        NativeEdit::CreateTable {
            frame,
            dataset,
            merges,
        } => {
            let xml = table::frame_xml(&frame, dataset, merges)?;
            table::insert_frame(&mut next, frame.slide, frame.id, &xml)?;
            vec![frame.slide.to_owned()]
        }
        NativeEdit::CreateChart {
            frame,
            family,
            dataset,
            chart,
            workbook: book,
            sheet,
        } => {
            let bytes = workbook::create(dataset, sheet, next.limits())?;
            next.add_part(book, XLSX_TYPE, bytes)?;
            let data = next.relate(chart, &format!("{REL}/package"), book)?;
            next.add_part(
                chart,
                CHART_TYPE,
                chart::create(family, dataset, sheet, &data)?,
            )?;
            let link = next.relate(frame.slide, &format!("{REL}/chart"), chart)?;
            table::insert_frame(
                &mut next,
                frame.slide,
                frame.id,
                &chart::frame_xml(&frame, &link),
            )?;
            check_reimport(&next, chart, None)?;
            [
                frame.slide.to_owned(),
                retained_opc::rels_name(frame.slide),
                chart.to_owned(),
                retained_opc::rels_name(chart),
                book.to_owned(),
                "[Content_Types].xml".to_owned(),
            ]
            .into()
        }
        NativeEdit::SetTableCell {
            slide,
            table,
            row,
            col,
            expected,
            value,
        } => {
            table::set_cell(&mut next, slide, table, (row, col), expected, value)?;
            vec![slide.to_owned()]
        }
        NativeEdit::SetSeries {
            chart,
            series,
            target,
            values,
        } => {
            let (report, written) = chart::set_series(&mut next, chart, series, target, values)?;
            let book = report.part.clone();
            workbook = Some(report);
            check_reimport(&next, chart, Some(&written))?;
            vec![chart.to_owned(), book]
        }
    };
    // The independent check: what the export would carry, not what the
    // writer meant to write. Only this operation's writes count, whatever
    // the package carried before it.
    let mut changed = Vec::new();
    for part in next.changed_parts() {
        if package.part(part)? != next.part(part)? {
            changed.push(part.to_owned());
        }
    }
    if let Some(outside) = changed.iter().find(|part| !allowed.contains(part)) {
        return Err(NativeRefusal::OutsideAllowedParts(outside.clone()));
    }
    *package = next;
    Ok(NativeReport {
        changed_parts: changed,
        workbook,
    })
}

/// Re-read the chart and its workbook from the candidate; every sequence
/// that holds a written cell (or, after creation, every sequence) must have
/// a cache equal to its cells.
fn check_reimport(
    package: &Package,
    chart: &str,
    written: Option<&[workbook::CellKey]>,
) -> Result<(), NativeRefusal> {
    let data = chart::read_back(package, chart, written)?;
    if data
        .iter()
        .all(|sequence| sequence.cache == sequence.workbook)
    {
        Ok(())
    } else {
        Err(NativeRefusal::CacheMismatch)
    }
}

#[cfg(test)]
mod tests;
