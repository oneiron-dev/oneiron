//! Recalculate a local XLSX through the fork's retained cache writer.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use formualizer_eval::engine::DeterministicMode;
use formualizer_eval::timezone::TimeZoneSpec;
use formualizer_workbook::{
    IoError, XlsxRecalculateLimits, XlsxRecalculateOptions, recalculate_xlsx_bytes,
};
use oneiron_docedit::retained_opc::{Limits, Package};

use crate::clock::RecalcClock;
use crate::engine::{EngineId, FormualizerEngine};
use crate::links::LinkedBooks;
use crate::location::DocumentLocation;
use crate::xml::{DOC_REL, MAIN, REL, Xml, invalid, parse_part, unsupported};
use crate::{FormulaError, Result, route_workbook};

use edit_gate::keep_gated_bytes;

mod admission;
mod edit_gate;
mod read;

/// A retained XLSX output, ready for the EditSession corruption gate.
#[derive(Debug)]
pub struct WorkbookRecalc {
    pub bytes: Vec<u8>,
    pub engine: EngineId,
    pub formula_count: usize,
}

/// The formulas the engine evaluates: cell formulas by worksheet part, and
/// defined names. A shared formula's text sits on its anchor cell only.
struct Formulas {
    sheets: BTreeMap<String, Vec<String>>,
    names: Vec<DefinedName>,
    /// Table names, lowercase.
    tables: BTreeSet<String>,
    /// Valid content the writer cannot reproduce exactly, noted while the
    /// rest of the workbook is still checked for malformed content.
    refusal: Option<Cow<'static, str>>,
    /// The package holds a VBA project, whose functions Excel calls once
    /// macros are enabled.
    vba_project: bool,
    /// The worksheets' names, as the workbook spells them.
    sheet_names: Vec<String>,
    /// Each formula that may be a CELL("filename") call (a shared formula's
    /// anchor text once) and the text cached by every cell it computes,
    /// `None` when the reader does not decode it.
    filename_caches: Vec<(String, Vec<Option<String>>)>,
}

struct DefinedName {
    name: String,
    formula: String,
    /// Defined for one sheet (`localSheetId`), not the whole workbook.
    sheet_level: bool,
}

impl FormualizerEngine {
    /// Recalculate a real package with the fork's cache writer
    /// (`formualizer_workbook::recalculate_xlsx_bytes`).
    ///
    /// The edit round trip's default recalc. One multi-sheet graph evaluates
    /// ordinary, shared and array formulas, defined names and table
    /// references. Only formula caches, their value types and the error tags
    /// Excel saves with them change; every other byte of the package is kept.
    /// NOW() and TODAY() read `clock`'s instant at its local offset, and RAND,
    /// RANDBETWEEN and RANDARRAY draw from its seed, as Excel recalculating
    /// at that moment would. CELL("filename") prints `location`, the folder
    /// and file name the workbook was opened from
    /// (`C:\Reports\[Budget.xlsx]Sheet1`), and CELL("address") of another
    /// sheet's cell names its file (`[Budget.xlsx]Other!$B$2`); without a
    /// location they read the one Excel last saved in the workbook's own
    /// CELL("filename") caches, when each such cached text names a folder,
    /// file and sheet of the workbook and they agree. OFFSET and INDIRECT
    /// follow the workbook alone,
    /// and a defined name evaluates for the formula that uses it (its relative
    /// R1C1 text reads the calling cell, its random calls are that formula's
    /// draws). A call of a name outside Excel's function list as the file
    /// spells it is `#NAME?`, as in Excel. With "Set precision as displayed"
    /// on (`fullPrecision="0"`), each formula result is stored as its cell's
    /// number format shows it and formulas read the stored value, as in
    /// Excel.
    /// `UnsupportedWorkbook` is returned before bytes are emitted, so the
    /// caller's precision fallback recalculates, for: the external links the
    /// engine cannot read as Excel does with the linked workbook closed (see
    /// `links.rs`), formulas needing what only the host knows (the active
    /// cell, the application's environment, cell formatting the engine does
    /// not model, and the file's location when neither the caller nor the
    /// workbook's caches give it), INDIRECT text that names a
    /// workbook (the writer refuses it as evaluation meets it), Excel
    /// functions the engine does not implement, a call Excel may resolve
    /// through an XLL add-in or the workbook's VBA project, a workbook or
    /// linked-workbook name used as a function or a workbook name
    /// holding a LAMBDA, string escapes the writer's reader does not decode as
    /// Excel does (in strings, formulas, and sheet, defined and table names),
    /// under precision as displayed a number format whose stored values the
    /// writer does not know, anything the writer cannot write exactly (such
    /// as a dynamic array larger than its saved extent), a result over the
    /// host's limits and a recalculation the edit round trip's corruption gate
    /// would refuse. Malformed content (such as
    /// a repeated cell, a boolean other than 0 or 1, a repeated sheet ID or a
    /// broken table part) and a part the writer reads over the host's XML
    /// limits, wherever a relationship puts it, are `InvalidWorkbook`,
    /// refused outright as before the writer.
    /// `limits` are the host's document ceilings (the vault's resolved
    /// `docedit_package_limits`); the writer runs under the stricter of each
    /// of them and its own, and every part it reads or changes fits them.
    /// `resources` is the caller's port: the package and every part it reads
    /// reserve through it (FIX 10588).
    pub fn recalculate_xlsx(
        &self,
        bytes: &[u8],
        limits: Limits,
        clock: &RecalcClock,
        location: Option<&DocumentLocation>,
        resources: &oneiron_docedit::resource::Resources,
    ) -> Result<WorkbookRecalc> {
        let package = Package::open(bytes, limits, resources)?;
        crate::links::external_targets(&package)?;
        // Malformed content is refused outright before any link is read.
        let formulas = Formulas::read(&package)?;
        let links = LinkedBooks::read(&package)?;
        let reads_location = formulas.admit(&links)?;
        let saved;
        let location = match (location, reads_location) {
            (Some(location), _) => Some(location),
            (None, Some(need)) => {
                saved = formulas.saved_location()?.ok_or_else(|| {
                    unsupported(format!(
                        "formula needs host context: {need}; neither the caller nor a cached \
                         CELL(\"filename\") value gives it"
                    ))
                })?;
                Some(&saved)
            }
            (None, None) => None,
        };
        let mut options = options(limits, clock, location);
        let checkpoint_resources = resources.clone();
        options.cancel = Some(
            formualizer_eval::engine::CancelToken::new()
                .with_checkpoint(move || checkpoint_resources.checkpoint().is_err()),
        );
        let result = match recalculate_xlsx_bytes(bytes, options) {
            Ok(result) => result,
            Err(error) => {
                if matches!(
                    &error,
                    IoError::Engine(error)
                        if error.kind == formualizer_common::ExcelErrorKind::Cancelled
                ) {
                    resources.checkpoint()?;
                }
                return Err(retained_writer_error(error));
            }
        };
        if result.bytes != bytes {
            keep_gated_bytes(&package, &result.bytes, &formulas)?;
        }
        Ok(WorkbookRecalc {
            bytes: result.bytes,
            engine: EngineId {
                engine: env!("CARGO_PKG_NAME").to_owned(),
                version: format!(
                    "{}+formualizer.{}",
                    env!("CARGO_PKG_VERSION"),
                    crate::engine::ENGINE_VERSION,
                ),
            },
            formula_count: result.formula_cells,
        })
    }
}

/// The host's byte ceilings over the writer's own defaults, the stricter of
/// each; counts are the writer's own (FIX 10590). The output is a package
/// the host reads back, so it fits the archive limit. The writer reads the
/// clock once, at `clock`'s instant and offset, and seeds the random
/// functions from it; CELL names `location`.
fn options(
    limits: Limits,
    clock: &RecalcClock,
    location: Option<&DocumentLocation>,
) -> XlsxRecalculateOptions {
    let own = XlsxRecalculateLimits::default();
    let mut options = XlsxRecalculateOptions {
        limits: XlsxRecalculateLimits {
            max_input_bytes: own.max_input_bytes.min(limits.archive_bytes),
            max_expanded_bytes: own.max_expanded_bytes.min(limits.expanded_bytes),
            max_worksheet_bytes: own.max_worksheet_bytes.min(limits.part_bytes),
            max_output_bytes: own.max_output_bytes.min(limits.archive_bytes),
            ..own
        },
        ..XlsxRecalculateOptions::default()
    };
    options.eval_config.deterministic_mode = DeterministicMode::Enabled {
        timestamp_utc: clock.now(),
        timezone: TimeZoneSpec::FixedOffsetSeconds(i32::from(clock.utc_offset_minutes()) * 60),
    };
    options.eval_config.workbook_seed = clock.seed();
    // Long formulas recurse deeply; the writer evaluates on threads with a
    // stack for the longest Excel saves (`crate::context`).
    options.eval_config.worker_stack_bytes = Some(crate::context::EVAL_STACK_BYTES);
    if let Some(location) = location {
        options.eval_config.workbook_directory = Some(location.directory().to_owned());
        options.eval_config.workbook_file_name = Some(location.file_name().to_owned());
    }
    options
}

/// The writer refuses what it cannot write exactly, before any output; the
/// caller's fallback takes those. Any other failure is the engine's.
fn retained_writer_error(error: IoError) -> FormulaError {
    match error {
        IoError::Unsupported { feature, context } => unsupported(format!("{feature} ({context})")),
        other => FormulaError::Engine(other.to_string()),
    }
}

pub(crate) const ESCAPED_TEXT: &str = "escaped text the reader does not decode as Excel does";

/// Whether `text` holds an OOXML `_xHHHH_` escape.
pub(crate) fn escaped(text: &str) -> bool {
    text.as_bytes().windows(7).any(|window| {
        window.starts_with(b"_x")
            && window[6] == b'_'
            && window[2..6].iter().all(u8::is_ascii_hexdigit)
    })
}

/// Worksheet parts, located by the workbook's relationship targets.
fn worksheet_parts(package: &Package) -> Result<Vec<String>> {
    let rels = parse_part(package, "xl/_rels/workbook.xml.rels")?;
    rels.root(REL, "Relationships")?;
    let worksheet_type = format!("{DOC_REL}/worksheet");
    rels.children(0)
        .filter(|(_, relation)| {
            relation.is(REL, "Relationship")
                && relation.attr("Type") == Some(worksheet_type.as_str())
        })
        .map(|(_, relation)| {
            resolve(
                "xl",
                relation
                    .attr("Target")
                    .ok_or_else(|| invalid("worksheet target missing"))?,
            )
        })
        .collect()
}

/// Preserve external formula text as well as externalLink ZIP parts. Sheet
/// relationship targets, not filename guesses, locate the cells to protect.
pub(crate) fn external_formulas(package: &Package) -> Result<BTreeMap<(String, String), String>> {
    let mut formulas = BTreeMap::new();
    for part in worksheet_parts(package)? {
        let xml: Xml = parse_part(package, &part)?;
        for (index, cell) in xml
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.is(MAIN, "c"))
        {
            if let Some((_, formula)) = xml.child(index, MAIN, "f")?
                && !route_workbook([], [], [formula.text.as_str()], package.resources())
                    .is_in_process()
            {
                let address = cell
                    .attr("r")
                    .ok_or_else(|| invalid("linked cell address missing"))?;
                if formulas
                    .insert((part.clone(), address.into()), formula.text.clone())
                    .is_some()
                {
                    return Err(invalid("duplicate linked cell"));
                }
            }
        }
    }
    Ok(formulas)
}

/// The part a relationship `target` names, relative to `folder`.
fn resolve(folder: &str, target: &str) -> Result<String> {
    let path = target
        .strip_prefix('/')
        .map_or_else(|| format!("{folder}/{target}"), str::to_owned);
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments
                    .pop()
                    .ok_or_else(|| invalid("relationship path escapes package"))?;
            }
            segment if segment.contains(['\\', ':', '#', '?', '%']) => {
                return Err(unsupported("encoded relationship target"));
            }
            segment => segments.push(segment),
        }
    }
    Ok(segments.join("/"))
}
