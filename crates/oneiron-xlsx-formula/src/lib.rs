//! In-process XLSX formula recalculation, the default of the edit round trip.
//!
//! [`FormualizerEngine::recalculate_xlsx`](engine::FormualizerEngine) runs the
//! owned formualizer fork's retained cache writer,
//! `formualizer_workbook::recalculate_xlsx_bytes` (upstream feature
//! `xlsx-recalc`, which also turns on calamine and `system-clock`). One
//! multi-sheet graph evaluates ordinary, shared and array formulas, dynamic
//! arrays inside their saved extent, defined names, tables and structured
//! references. Only formula caches, their value types, calculate-always flags
//! and Excel's rich error tags change; the package keeps every other byte.
//! The core's edit round trip wraps every host session in this engine unless
//! the host opts out, so this crate does not depend on the core.
//!
//! The corpus rule is met at fork rev `63e2ec69` (0.9.3-oneiron.8): through
//! the writer, 2,963 of the 2,967 scored fresh-Excel SpreadsheetBench
//! workbooks (Excel for Windows truth) are fully Excel-identical (LibreOffice
//! 25.8 matched 2,648 of the 2,951 it was measured on), and all 811 pinned
//! goldens (Excel for Windows 16.0.20430, rich-value error caches resolved)
//! against LibreOffice's 753. Through this adapter, 2,508 of the corpus's
//! 3,040 formula workbooks recalculate natively as saved, ZIP directory
//! entries included (see the README), and all 2,508 match Excel. The
//! host's LibreOffice recalc stays the precision fallback for refused
//! workbooks only: external links (their link-preserving route, see
//! [`routing`]), formulas needing caller context (the corpus clock is never
//! substituted for production time), functions the engine does not implement,
//! workbook names used as functions (LAMBDA names), string escapes the
//! writer's reader decodes differently from Excel, precision-as-displayed,
//! what the writer cannot write exactly, a result over the host's limits, and
//! a recalculation the edit round trip's corruption gate would refuse.
//! Malformed content is refused outright, as before the writer.

pub mod calc;
mod context;
pub mod engine;
pub mod error;
pub mod measure;
pub mod routing;
pub mod workbook;
mod xml;

pub use engine::{CellValue, EngineId, RecalcEngine, RecalcReport};
pub use error::{FormulaError, Result};
pub use measure::{CaseResult, CorpusReport, MeasureOptions, evaluate_case, read_corpus_cases};
pub use oneiron_docedit::xlfn::{storage_form, ui_form};
pub use routing::{RouteDecision, preserve_external_links, route_workbook};
pub use workbook::WorkbookRecalc;
