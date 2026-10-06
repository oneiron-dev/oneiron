//! Recalculate a local XLSX through the fork's retained cache writer.
use std::collections::{BTreeMap, BTreeSet};

use formualizer_workbook::{
    IoError, XlsxRecalculateLimits, XlsxRecalculateOptions, recalculate_xlsx_bytes,
};
use oneiron_docedit::retained_opc::{Limits, Package};

use crate::engine::{EngineId, FormualizerEngine};
use crate::xml::{DOC_REL, MAIN, REL, Xml, invalid, parse_part, unsupported};
use crate::{FormulaError, Result, RouteDecision, route_workbook, storage_form};

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
    names: Vec<String>,
}

impl FormualizerEngine {
    /// Recalculate a real package with the fork's cache writer
    /// (`formualizer_workbook::recalculate_xlsx_bytes`).
    ///
    /// The edit round trip's default recalc. One multi-sheet graph evaluates
    /// ordinary, shared and array formulas, defined names and table
    /// references. Only formula caches, their value types and the error tags
    /// Excel saves with them change; every other byte of the package is kept.
    /// `UnsupportedWorkbook` is returned before bytes are emitted, so the
    /// caller's precision fallback recalculates, for: external links,
    /// formulas needing caller context or volatile reference semantics,
    /// functions the engine does not implement, precision-as-displayed,
    /// anything the writer cannot write exactly (such as a dynamic array
    /// larger than its saved extent) and a recalculation the edit round
    /// trip's corruption gate would refuse.
    /// `limits` are the host's document ceilings (the vault's resolved
    /// `docedit_package_limits`); the writer runs under the stricter of each
    /// of them and its own.
    pub fn recalculate_xlsx(&self, bytes: &[u8], limits: Limits) -> Result<WorkbookRecalc> {
        let package = Package::open(bytes, limits)?;
        require_local(&package)?;
        let formulas = Formulas::read(&package)?;
        formulas.admit(limits)?;
        let result =
            recalculate_xlsx_bytes(bytes, options(limits)).map_err(retained_writer_error)?;
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

/// The host's ceilings over the writer's own defaults, the stricter of each.
/// The output is a package the host reads back, so it fits the archive limit.
fn options(limits: Limits) -> XlsxRecalculateOptions {
    let own = XlsxRecalculateLimits::default();
    XlsxRecalculateOptions {
        limits: XlsxRecalculateLimits {
            max_input_bytes: own.max_input_bytes.min(limits.archive_bytes),
            max_entries: own.max_entries.min(limits.entries),
            max_expanded_bytes: own.max_expanded_bytes.min(limits.expanded_bytes),
            max_worksheet_bytes: own.max_worksheet_bytes.min(limits.part_bytes),
            max_output_bytes: own.max_output_bytes.min(limits.archive_bytes),
            max_xml_depth: own.max_xml_depth.min(limits.xml.max_depth),
            ..own
        },
        ..XlsxRecalculateOptions::default()
    }
}

/// The writer refuses what it cannot write exactly, before any output; the
/// caller's fallback takes those. Any other failure is the engine's.
fn retained_writer_error(error: IoError) -> FormulaError {
    match error {
        IoError::Unsupported { feature, context } => unsupported(format!("{feature} ({context})")),
        other => FormulaError::Engine(other.to_string()),
    }
}

impl Formulas {
    fn read(package: &Package) -> Result<Self> {
        let workbook = parse_part(package, "xl/workbook.xml")?;
        workbook.root(MAIN, "workbook")?;
        // The writer calculates at full precision; Excel would round to the
        // displayed format first.
        if let Some((_, settings)) = workbook.child(0, MAIN, "calcPr")?
            && settings
                .attr("fullPrecision")
                .is_some_and(|v| matches!(v, "0" | "false"))
        {
            return Err(unsupported("precision-as-displayed"));
        }
        let names = workbook
            .nodes
            .iter()
            .filter(|node| node.is(MAIN, "definedName"))
            .map(|node| node.text.clone())
            .collect();
        let mut sheets = BTreeMap::new();
        for part in worksheet_parts(package)? {
            let xml = parse_part(package, &part)?;
            let formulas = xml
                .nodes
                .iter()
                .filter(|node| node.is(MAIN, "f") && !node.text.is_empty())
                .map(|node| node.text.clone())
                .collect();
            sheets.insert(part, formulas);
        }
        Ok(Self { sheets, names })
    }

    fn all(&self) -> impl Iterator<Item = &str> {
        self.sheets
            .values()
            .flatten()
            .chain(&self.names)
            .map(String::as_str)
    }

    /// Refuse what the engine must not evaluate natively, before it runs.
    fn admit(&self, limits: Limits) -> Result<()> {
        for formula in self.all() {
            let inspection = crate::context::inspect_formula(formula)?;
            if inspection.contextual {
                return Err(unsupported(
                    "formula needs caller context or volatile reference semantics",
                ));
            }
            if let Some(name) = inspection.unknown_function {
                return Err(unsupported(format!(
                    "function the engine does not implement: {name}"
                )));
            }
        }
        if let RouteDecision::Openpyxl { reason } = route_workbook([], [], self.all(), limits.xml) {
            return Err(unsupported(reason));
        }
        Ok(())
    }
}

/// The edit round trip's corruption gate keeps every part outside its
/// supported set byte for byte and requires the OOXML function prefix in each
/// worksheet whose bytes change (`oneiron::edit_roundtrip`'s
/// `session_validate`). A recalculation that would fail either check goes to
/// the fallback instead: the writer adds or edits `xl/richData/` rich values
/// when it tags a new #SPILL! or #CALC!, and never rewrites formula text.
/// Its other edits (worksheets, `xl/metadata.xml`, and the content types and
/// relationships of added parts) are parts the gate lets change.
fn keep_gated_bytes(before: &Package, after: &[u8], formulas: &Formulas) -> Result<()> {
    let after = Package::open(after, before.limits())?;
    let kept: BTreeSet<&str> = after.names().collect();
    if before.names().any(|name| !kept.contains(name)) {
        return Err(unsupported("recalculation drops a package part"));
    }
    for name in after.names() {
        if before.part(name)? == after.part(name)? {
            continue;
        }
        match formulas.sheets.get(name) {
            Some(sheet)
                if sheet
                    .iter()
                    .all(|formula| storage_form(formula) == *formula) => {}
            Some(_) => {
                return Err(unsupported(
                    "recalculated worksheet has a formula without its OOXML function prefix",
                ));
            }
            None if name == "xl/metadata.xml"
                || name == "[Content_Types].xml"
                || name.ends_with(".rels") => {}
            None => {
                return Err(unsupported(format!(
                    "recalculation changes {name}, a part the edit gate passes through"
                )));
            }
        }
    }
    Ok(())
}

/// Cheap external-parts admission runs before semantic import, including on
/// workbooks whose local features are not yet handled by this adapter.
fn require_local(package: &Package) -> Result<()> {
    let rels = package
        .names()
        .filter(|name| name.ends_with(".rels"))
        .map(|name| package.part(name))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let route = route_workbook(
        package.names(),
        rels.iter().flatten().map(Vec::as_slice),
        [],
        package.limits().xml,
    );
    if let RouteDecision::Openpyxl { reason } = route {
        return Err(unsupported(reason));
    }
    Ok(())
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
                && !route_workbook([], [], [formula.text.as_str()], package.limits().xml)
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

fn resolve(target: &str) -> Result<String> {
    let path = target
        .strip_prefix('/')
        .map_or_else(|| format!("xl/{target}"), str::to_owned);
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
