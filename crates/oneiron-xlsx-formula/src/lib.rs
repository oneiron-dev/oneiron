//! Opt-in in-process XLSX formula recalculation for the edit round trip.
//!
//! [`InProcessSession`] implements the core's `EditSession`: it keeps the
//! caller's narrow editor and precision fallback, and recalculates supported
//! local workbooks in one multi-sheet graph on the owned formualizer fork
//! (default features off: no `xlsx-recalc`, no `system-clock`, no
//! umya/calamine DOM). Only formula spellings and scalar cached values change;
//! the retained OPC package keeps every other record.
//!
//! The compatibility subset cleared its threshold, but the complete
//! fresh-Excel SpreadsheetBench comparison did not reach parity, so native
//! recalculation stays opt-in: hosts construct the session explicitly.
//! Unsupported features and formulas needing caller context stay on the
//! precision fallback; the corpus clock is never substituted for production
//! time. External-link workbooks stay on their link-preserving route (see
//! [`routing`]).

mod cache;
pub mod calc;
mod context;
pub mod engine;
pub mod error;
mod mac_parity;
pub mod measure;
pub mod routing;
pub mod session;
pub mod workbook;
mod xml;

pub use engine::{CellValue, EngineId, RecalcEngine, RecalcReport};
pub use error::{FormulaError, Result};
pub use measure::{CaseResult, CorpusReport, MeasureOptions, evaluate_case, read_corpus_cases};
pub use oneiron_docedit::xlfn::{storage_form, ui_form};
pub use routing::{RouteDecision, route_workbook};
pub use session::InProcessSession;
pub use workbook::WorkbookRecalc;
