//! In-process XLSX formula recalculation, the default of the edit round trip.
//!
//! [`FormualizerEngine::recalculate_xlsx`](engine::FormualizerEngine)
//! recalculates a supported local workbook in one multi-sheet graph on the
//! owned formualizer fork (default features off: no `xlsx-recalc`, no
//! `system-clock`, no umya/calamine DOM). Only formula spellings and scalar
//! cached values change; the retained OPC package keeps every other record.
//! The core's edit round trip wraps every host session in this engine unless
//! the host opts out, so this crate does not depend on the core.
//!
//! The corpus rule is met at fork rev `e29e4ee7` (0.9.3-oneiron.3): 2,866 of
//! the 2,982 formula-bearing fresh-Excel SpreadsheetBench workbooks are fully
//! Excel-identical (2,835 of the 2,951 that LibreOffice 25.8 matches 2,648
//! of), and 809 of the 811 pinned goldens (Excel for Windows 16.0.20430) against LibreOffice's 753. The host's
//! LibreOffice recalc stays the precision fallback for refused workbooks
//! only: unsupported features and formulas needing caller context; the corpus
//! clock is never substituted for production time. External-link workbooks
//! stay on their link-preserving route (see [`routing`]).

mod cache;
pub mod calc;
mod context;
pub mod engine;
pub mod error;
mod mac_parity;
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
