//! Recalculate a local XLSX through the fork's retained cache writer.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use formualizer_common::parse_a1_1based;
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
    names: Vec<DefinedName>,
    /// Valid content the writer cannot reproduce exactly, noted while the
    /// rest of the workbook is still checked for malformed content.
    refusal: Option<Cow<'static, str>>,
}

struct DefinedName {
    name: String,
    formula: String,
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
    /// functions the engine does not implement, a workbook name used as a
    /// function or holding a LAMBDA, string escapes the writer's reader does
    /// not decode as Excel does, precision-as-displayed, anything the writer
    /// cannot write exactly (such as a dynamic array larger than its saved
    /// extent), a result over the host's limits and a recalculation the edit
    /// round trip's corruption gate would refuse. Malformed content (such as
    /// a repeated cell or a boolean other than 0 or 1) and a part the writer
    /// reads over the host's XML limits are `InvalidWorkbook`, refused
    /// outright as before the writer.
    /// `limits` are the host's document ceilings (the vault's resolved
    /// `docedit_package_limits`); the writer runs under the stricter of each
    /// of them and its own, and every part it reads or changes fits them.
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
    /// Read what the writer reads, as the reader before it did: every part
    /// under the host's XML limits, and malformed content refused.
    fn read(package: &Package) -> Result<Self> {
        let workbook = parse_part(package, "xl/workbook.xml")?;
        workbook.root(MAIN, "workbook")?;
        let mut refusal = None;
        // The writer calculates at full precision; Excel would round to the
        // displayed format first.
        if let Some((_, settings)) = workbook.child(0, MAIN, "calcPr")?
            && settings
                .attr("fullPrecision")
                .is_some_and(|v| matches!(v, "0" | "false"))
        {
            refusal = Some("precision-as-displayed".into());
        }
        if !matches!(
            workbook
                .child(0, MAIN, "workbookPr")?
                .and_then(|(_, node)| node.attr("date1904")),
            None | Some("0" | "false" | "1" | "true")
        ) {
            return Err(invalid("invalid date1904 flag"));
        }
        let names = workbook
            .nodes
            .iter()
            .filter(|node| node.is(MAIN, "definedName"))
            .map(|node| DefinedName {
                name: node.attr("name").unwrap_or_default().to_owned(),
                formula: node.text.clone(),
            })
            .collect();
        let targets = relationships(package)?;
        let strings_type = format!("{DOC_REL}/sharedStrings");
        let strings = match targets.values().find(|(_, kind)| *kind == strings_type) {
            Some((part, _)) => {
                let xml = parse_part(package, part)?;
                xml.root(MAIN, "sst")?;
                let mut count = 0;
                for (item, _) in xml.children(0).filter(|(_, node)| node.is(MAIN, "si")) {
                    check_string(&xml, item, &mut refusal)?;
                    count += 1;
                }
                count
            }
            None => 0,
        };
        let (sheet_list, _) = workbook
            .child(0, MAIN, "sheets")?
            .ok_or_else(|| invalid("missing sheets"))?;
        let worksheet_type = format!("{DOC_REL}/worksheet");
        let mut sheets = BTreeMap::new();
        let mut sheet_names = BTreeSet::new();
        for (_, node) in workbook
            .children(sheet_list)
            .filter(|(_, node)| node.is(MAIN, "sheet"))
        {
            let name = node
                .attr("name")
                .ok_or_else(|| invalid("sheet name missing"))?;
            if !sheet_names.insert(name.to_lowercase()) {
                return Err(invalid("duplicate sheet name"));
            }
            let id = node
                .attr_ns(DOC_REL, "id")
                .ok_or_else(|| invalid("sheet relationship missing"))?;
            let (part, kind) = targets
                .get(id)
                .ok_or_else(|| invalid("unresolved sheet relationship"))?;
            if *kind != worksheet_type {
                refusal.get_or_insert_with(|| "non-worksheet sheet".into());
                continue;
            }
            if sheets.contains_key(part) {
                return Err(invalid("duplicate worksheet target"));
            }
            let xml = parse_part(package, part)?;
            xml.root(MAIN, "worksheet")?;
            check_cells(&xml, strings, &mut refusal)?;
            let formulas = xml
                .nodes
                .iter()
                .filter(|node| node.is(MAIN, "f") && !node.text.is_empty())
                .map(|node| node.text.clone())
                .collect();
            sheets.insert(part.clone(), formulas);
        }
        if sheet_names.is_empty() {
            return Err(invalid("empty workbook"));
        }
        for name in package.names().filter(|name| reader_part(name)) {
            parse_part(package, name)?;
        }
        Ok(Self {
            sheets,
            names,
            refusal,
        })
    }

    fn all(&self) -> impl Iterator<Item = &str> {
        self.sheets
            .values()
            .flatten()
            .chain(self.names.iter().map(|name| &name.formula))
            .map(String::as_str)
    }

    fn defines(&self, name: &str) -> bool {
        self.names
            .iter()
            .any(|defined| defined.name.eq_ignore_ascii_case(name))
    }

    /// Refuse what the engine must not evaluate natively, before it runs.
    fn admit(&self, limits: Limits) -> Result<()> {
        if let Some(reason) = &self.refusal {
            return Err(unsupported(reason.clone()));
        }
        let cells = self
            .sheets
            .values()
            .flatten()
            .map(|formula| (formula, None));
        let names = self
            .names
            .iter()
            .map(|name| (&name.formula, Some(name.name.as_str())));
        for (formula, defined) in cells.chain(names) {
            let inspection = crate::context::inspect_formula(formula)?;
            if inspection.contextual {
                return Err(unsupported(
                    "formula needs caller context or volatile reference semantics",
                ));
            }
            // The engine does not resolve a workbook name to its LAMBDA yet:
            // MAP over one, or a call of one, would cache #NAME?.
            if let Some(name) = defined
                && inspection.lambda
            {
                return Err(unsupported(format!("defined name holds a LAMBDA: {name}")));
            }
            let called_name = inspection
                .unknown_function
                .as_deref()
                .filter(|function| self.defines(function));
            if let Some(name) = inspection.callable_name.as_deref().or(called_name) {
                return Err(unsupported(format!("name used as a function: {name}")));
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

/// The workbook's relationships by id: the resolved target part and the type.
fn relationships(package: &Package) -> Result<BTreeMap<String, (String, String)>> {
    let rels = parse_part(package, "xl/_rels/workbook.xml.rels")?;
    rels.root(REL, "Relationships")?;
    let mut targets = BTreeMap::new();
    for (_, node) in rels
        .children(0)
        .filter(|(_, node)| node.is(REL, "Relationship"))
    {
        let id = node
            .attr("Id")
            .ok_or_else(|| invalid("relationship id missing"))?;
        let target = node
            .attr("Target")
            .ok_or_else(|| invalid("relationship target missing"))?;
        let kind = node
            .attr("Type")
            .ok_or_else(|| invalid("relationship type missing"))?;
        if targets
            .insert(id.to_owned(), (resolve(target)?, kind.to_owned()))
            .is_some()
        {
            return Err(invalid("duplicate relationship id"));
        }
    }
    Ok(targets)
}

/// The parts the writer and its reader parse besides the workbook, its
/// relationships, the shared strings and the worksheets. `require_local`
/// reads every relationship part under the host's XML limits.
fn reader_part(name: &str) -> bool {
    matches!(
        name,
        "[Content_Types].xml" | "xl/styles.xml" | "xl/metadata.xml"
    ) || ((name.starts_with("xl/richData/") || name.starts_with("xl/tables/"))
        && name.ends_with(".xml"))
}

/// Refuse a malformed cell as the reader before this writer did: a missing,
/// unreadable, off-grid or repeated address, or a value its type cannot hold
/// (a number that is not one, a boolean other than 0 or 1, a shared string
/// past the table). A cell without `<v>` is blank whatever its type, and a
/// formula's cache is the writer's to replace.
fn check_cells(xml: &Xml, strings: usize, refusal: &mut Option<Cow<'static, str>>) -> Result<()> {
    let Some((data, _)) = xml.child(0, MAIN, "sheetData")? else {
        return Ok(());
    };
    let mut addresses = BTreeSet::new();
    for (row, _) in xml.children(data).filter(|(_, node)| node.is(MAIN, "row")) {
        for (index, cell) in xml.children(row).filter(|(_, node)| node.is(MAIN, "c")) {
            let address = cell
                .attr("r")
                .ok_or_else(|| invalid("cell address missing"))?;
            let (row, col, _, _) =
                parse_a1_1based(address).map_err(|_| invalid("invalid cell address"))?;
            if row == 0
                || row > 1_048_576
                || col == 0
                || col > 16_384
                || !addresses.insert((row, col))
            {
                return Err(invalid("duplicate or out-of-grid cell"));
            }
            if xml.child(index, MAIN, "f")?.is_some() {
                continue;
            }
            let value = xml
                .child(index, MAIN, "v")?
                .map(|(_, node)| node.text.as_str());
            match (cell.attr("t"), value) {
                (Some("inlineStr"), value) => match xml.child(index, MAIN, "is")? {
                    Some((inline, _)) => check_string(xml, inline, refusal)?,
                    None if value.is_none_or(str::is_empty) => {}
                    None => return Err(invalid("missing inline string")),
                },
                (_, None) | (None | Some("n"), Some("")) => {}
                (None | Some("n"), Some(number)) => {
                    let number: f64 = number.parse().map_err(|_| invalid("non-numeric value"))?;
                    if !number.is_finite() {
                        return Err(invalid("non-finite value"));
                    }
                }
                (Some("s"), Some(item)) => {
                    let item: usize = item.parse().map_err(|_| invalid("shared string index"))?;
                    if item >= strings {
                        return Err(invalid("missing shared string"));
                    }
                }
                (Some("b"), Some(flag)) if !matches!(flag, "0" | "1") => {
                    return Err(invalid("invalid boolean"));
                }
                // Calamine decodes no escape in a literal string's `<v>`.
                (Some("str"), Some(text)) if escaped(text) => {
                    refusal.get_or_insert_with(|| ESCAPED_TEXT.into());
                }
                _ => {}
            }
        }
    }
    Ok(())
}

const ESCAPED_TEXT: &str = "escaped text the reader does not decode as Excel does";

/// Note an escape in a string item (`si` or `is`) that Calamine, the writer's
/// reader, decodes differently from Excel. Phonetic runs are not read.
fn check_string(xml: &Xml, item: usize, refusal: &mut Option<Cow<'static, str>>) -> Result<()> {
    for (child, node) in xml.children(item) {
        let text = if node.is(MAIN, "t") {
            Some(node)
        } else if node.is(MAIN, "r") {
            xml.child(child, MAIN, "t")?.map(|(_, text)| text)
        } else {
            None
        };
        if text.is_some_and(|text| !decodes_like_excel(&text.text)) {
            refusal.get_or_insert_with(|| ESCAPED_TEXT.into());
        }
    }
    Ok(())
}

/// Whether Calamine decodes every OOXML escape in `text` as Excel does.
/// Excel reads each `_xHHHH_` as the UTF-16 unit HHHH. Calamine decodes only
/// `_x00HH_`, and reads a sign there as a digit (`_x00+A_`).
fn decodes_like_excel(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut at = 0;
    while let Some(window) = bytes.get(at..at + 7) {
        if window.starts_with(b"_x") && window[6] == b'_' {
            let digits = &window[2..6];
            if digits.iter().all(u8::is_ascii_hexdigit) {
                if !digits.starts_with(b"00") {
                    return false;
                }
                at += 7;
                continue;
            }
            if digits.starts_with(b"00+") && digits[3].is_ascii_hexdigit() {
                return false;
            }
        }
        at += 1;
    }
    true
}

/// Whether `text` holds an OOXML `_xHHHH_` escape.
fn escaped(text: &str) -> bool {
    text.as_bytes().windows(7).any(|window| {
        window.starts_with(b"_x")
            && window[6] == b'_'
            && window[2..6].iter().all(u8::is_ascii_hexdigit)
    })
}

/// The edit round trip's corruption gate keeps every part outside its
/// supported set byte for byte and requires the OOXML function prefix in each
/// worksheet whose bytes change (`oneiron::edit_roundtrip`'s
/// `session_validate`). A recalculation that would fail either check goes to
/// the fallback instead: the writer adds or edits `xl/richData/` rich values
/// when it tags a new #SPILL! or #CALC!, and never rewrites formula text.
/// Its other edits (worksheets, `xl/metadata.xml`, and the content types and
/// relationships of added parts) are parts the gate lets change. The host
/// reads the result back under its own limits, so the result must fit them.
fn keep_gated_bytes(before: &Package, after: &[u8], formulas: &Formulas) -> Result<()> {
    let after = Package::open(after, before.limits())
        .map_err(|_| unsupported("recalculated package exceeds the host's package limits"))?;
    let kept: BTreeSet<&str> = after.names().collect();
    if before.names().any(|name| !kept.contains(name)) {
        return Err(unsupported("recalculation drops a package part"));
    }
    for name in after.names() {
        let part = after.part(name)?;
        if before.part(name)? == part {
            continue;
        }
        if let Some(xml) = &part
            && Xml::parse(xml, before.limits().xml).is_err()
        {
            return Err(unsupported(format!(
                "recalculated {name} does not read back under the host's XML limits"
            )));
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
