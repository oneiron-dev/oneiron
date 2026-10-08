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
//! The caller's [`RecalcClock`] gives NOW() and TODAY() their instant and
//! local offset and RAND, RANDBETWEEN and RANDARRAY their seed, as Excel
//! recalculating at edit time. The caller's [`DocumentLocation`], the folder
//! and file name the workbook was opened from, gives CELL("filename") its
//! text (`C:\Reports\[Budget.xlsx]Sheet1`) and CELL("address") of another
//! sheet's cell its file name; without one, the location Excel last saved in
//! the workbook's own CELL("filename") caches stands in. OFFSET, INDIRECT and
//! the workbook's other CELL info types read the workbook alone, and a defined
//! name evaluates for the formula that uses it. A call of a name outside
//! Excel's function list, as the file spells it, is `#NAME?`, as in Excel.
//! The core's edit round trip wraps every host session in this engine unless
//! the host opts out, so this crate does not depend on the core.
//!
//! The corpus rule is met at fork rev `468a333b` (0.9.3-oneiron.12): through
//! the writer, all 2,967 scored fresh-Excel SpreadsheetBench workbooks (Excel
//! for Windows truth) are fully Excel-identical (LibreOffice 25.8 matched
//! 2,648 of the 2,951 it was measured on), and all 811 pinned goldens (Excel
//! for Windows 16.0.20430, rich-value error caches resolved) against
//! LibreOffice's 753. Through this adapter, 2,986 of the corpus's 3,040
//! formula workbooks recalculate natively as saved, ZIP directory entries and
//! closed linked workbooks included (see the README), and all of them match
//! Excel on their scored cells. The
//! host's LibreOffice recalc stays the precision fallback for refused
//! workbooks only: the external links the engine cannot read as Excel does
//! with the linked workbook closed (the others recalculate here from the
//! values their links save; [`routing`] checks that the fallback keeps every
//! link), formulas needing what only the host knows (INFO's description of
//! the application, CELL's active cell, the file's location when neither the
//! caller nor the workbook's caches give it, and cell formatting the engine
//! does not model), INDIRECT text that names a workbook
//! (the writer refuses it as evaluation meets it), Excel functions the engine
//! does not implement, calls an XLL add-in or the workbook's VBA project may
//! resolve, workbook and linked-workbook names used as functions (LAMBDA
//! names, add-in workbooks' functions), string escapes the
//! writer's reader decodes differently from Excel, precision-as-displayed,
//! what the writer cannot write exactly, a result over the host's limits, and
//! a recalculation the edit round trip's corruption gate would refuse.
//! Malformed content is refused outright, as before the writer.

pub mod calc;
mod clock;
mod context;
pub mod engine;
pub mod error;
mod links;
mod location;
pub mod measure;
pub mod routing;
pub mod workbook;
mod xml;

pub use clock::RecalcClock;
pub use engine::{CellValue, EngineId, RecalcEngine, RecalcReport};
pub use error::{FormulaError, Result};
pub use location::DocumentLocation;
pub use measure::{CaseResult, CorpusReport, MeasureOptions, evaluate_case, read_corpus_cases};
pub use oneiron_docedit::xlfn::{storage_form, ui_form};
pub use routing::{RouteDecision, preserve_external_links, route_workbook};
pub use workbook::WorkbookRecalc;
