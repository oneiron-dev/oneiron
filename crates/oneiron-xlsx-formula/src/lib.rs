//! In-process xlsx formula evaluation behind the docedit recalc seam.
//!
//! Step 20 builds the decided engine as a standalone crate; step 19 measures
//! the pinned upstream unchanged first. This crate is the step-20 shell around
//! the step-19 baseline: it links `formualizer-workbook 0.9.3` with default
//! features off (no `xlsx-recalc`, no `system-clock`, no umya/calamine DOM),
//! drives the workbook API from `.w7/formula-engine-context.md` verbatim, and
//! exposes the result through a storage-independent [`RecalcEngine`] seam the
//! docedit pipeline can adopt without taking an engine dependency.
//!
//! The pinned native-Excel comparison meets the ARCH-0075 selection threshold.
//! Hosts construct the session explicitly. Unsupported features and formulas
//! needing caller context stay on the precision fallback; the corpus clock is
//! never substituted for production time. External-link workbooks stay on their
//! link-preserving route (see [`routing`]).

mod cache;
mod context;
pub mod engine;
pub mod error;
mod mac_parity;
pub mod measure;
pub mod routing;
pub mod session;
pub mod workbook;
pub mod xlfn;
mod xml;

pub use engine::{CellValue, EngineId, RecalcEngine, RecalcReport};
pub use error::{FormulaError, Result};
pub use measure::{CaseResult, CorpusReport, MeasureOptions, evaluate_case, read_corpus_cases};
pub use routing::{RouteDecision, route_workbook};
pub use session::InProcessSession;
pub use workbook::WorkbookRecalc;
pub use xlfn::{storage_form, ui_form};
