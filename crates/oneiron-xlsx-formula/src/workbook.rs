//! Recalculate a local XLSX through the fork's retained cache writer.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use formualizer_common::parse_a1_1based;
use formualizer_eval::engine::DeterministicMode;
use formualizer_eval::timezone::TimeZoneSpec;
use formualizer_workbook::{
    IoError, XlsxRecalculateLimits, XlsxRecalculateOptions, recalculate_xlsx_bytes,
};
use oneiron_docedit::retained_opc::{Limits, Package};

use crate::clock::RecalcClock;
use crate::engine::{EngineId, FormualizerEngine};
use crate::links::LinkedBooks;
use crate::xml::{DOC_REL, MAIN, REL, Xml, invalid, parse_part, unsupported};
use crate::{FormulaError, Result, route_workbook, storage_form};

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
    /// at that moment would; OFFSET and INDIRECT follow the workbook alone,
    /// and a defined name evaluates for the formula that uses it (its relative
    /// R1C1 text reads the calling cell, its random calls are that formula's
    /// draws). A call of a name outside Excel's function list as the file
    /// spells it is `#NAME?`, as in Excel.
    /// `UnsupportedWorkbook` is returned before bytes are emitted, so the
    /// caller's precision fallback recalculates, for: the external links the
    /// engine cannot read as Excel does with the linked workbook closed (see
    /// `links.rs`), formulas needing what only the host knows (the file's
    /// path, the active cell, the environment), INDIRECT text that names a
    /// workbook (the writer refuses it as evaluation meets it), Excel
    /// functions the engine does not implement, a call Excel may resolve
    /// through an XLL add-in or the workbook's VBA project, a workbook or
    /// linked-workbook name used as a function or a workbook name
    /// holding a LAMBDA, string escapes the writer's reader does not decode as
    /// Excel does (in strings, formulas, and sheet, defined and table names),
    /// precision-as-displayed, anything the writer cannot write exactly (such
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
    pub fn recalculate_xlsx(
        &self,
        bytes: &[u8],
        limits: Limits,
        clock: &RecalcClock,
    ) -> Result<WorkbookRecalc> {
        let package = Package::open(bytes, limits)?;
        crate::links::external_targets(&package)?;
        // Malformed content is refused outright before any link is read.
        let formulas = Formulas::read(&package)?;
        let links = LinkedBooks::read(&package)?;
        formulas.admit(&links)?;
        let result =
            recalculate_xlsx_bytes(bytes, options(limits, clock)).map_err(retained_writer_error)?;
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
/// The writer reads the clock once, at `clock`'s instant and offset, and
/// seeds the random functions from it.
fn options(limits: Limits, clock: &RecalcClock) -> XlsxRecalculateOptions {
    let own = XlsxRecalculateLimits::default();
    let mut options = XlsxRecalculateOptions {
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
    };
    options.eval_config.deterministic_mode = DeterministicMode::Enabled {
        timestamp_utc: clock.now(),
        timezone: TimeZoneSpec::FixedOffsetSeconds(i32::from(clock.utc_offset_minutes()) * 60),
    };
    options.eval_config.workbook_seed = clock.seed();
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
        // A defined name and its formula are OOXML escaped strings, like sheet
        // and table names and cell formulas, and the reader decodes no escape
        // in any of them: Excel reads `_x20AC_` there as the euro sign.
        let mut names = Vec::new();
        let mut scopes = BTreeSet::new();
        for node in workbook
            .nodes
            .iter()
            .filter(|node| node.is(MAIN, "definedName"))
        {
            let name = node
                .attr("name")
                .ok_or_else(|| invalid("defined name missing"))?;
            let scope = node
                .attr("localSheetId")
                .map(str::parse::<usize>)
                .transpose()
                .map_err(|_| invalid("invalid defined-name scope"))?;
            if !scopes.insert((scope, name.to_lowercase())) {
                return Err(invalid("duplicate defined name"));
            }
            if escaped(name) || escaped(&node.text) {
                refusal.get_or_insert_with(|| ESCAPED_TEXT.into());
            }
            names.push(DefinedName {
                name: name.to_owned(),
                formula: node.text.clone(),
                sheet_level: scope.is_some(),
            });
        }
        // The writer reads the package's own relationships first.
        relationships(package, "")?;
        let targets = relationships(package, "xl/workbook.xml")?;
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
        let table_type = format!("{DOC_REL}/table");
        let mut sheets = BTreeMap::new();
        let mut sheet_names = BTreeSet::new();
        let mut sheet_ids = BTreeSet::new();
        let mut tables = BTreeSet::new();
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
            if escaped(name) {
                refusal.get_or_insert_with(|| ESCAPED_TEXT.into());
            }
            // Zero is valid XML the writer refuses; the fallback takes it.
            let sheet_id: u32 = node
                .attr("sheetId")
                .and_then(|id| id.parse().ok())
                .ok_or_else(|| invalid("invalid sheet ID"))?;
            if !sheet_ids.insert(sheet_id) {
                return Err(invalid("duplicate sheet ID"));
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
            let formulas: Vec<String> = xml
                .nodes
                .iter()
                .filter(|node| node.is(MAIN, "f") && !node.text.is_empty())
                .map(|node| node.text.clone())
                .collect();
            if formulas.iter().any(|formula| escaped(formula)) {
                refusal.get_or_insert_with(|| ESCAPED_TEXT.into());
            }
            // The writer registers every table a worksheet relates, wherever
            // the part lives.
            let rels = rels_part(part);
            if package.names().any(|name| name == rels) {
                for (table, kind) in relationships(package, part)?.values() {
                    if *kind == table_type {
                        check_table(package, table, &mut tables, &mut refusal)?;
                    }
                }
            }
            sheets.insert(part.clone(), formulas);
        }
        if sheet_names.is_empty() {
            return Err(invalid("empty workbook"));
        }
        if scopes
            .iter()
            .any(|(scope, _)| scope.is_some_and(|sheet| sheet >= sheet_names.len()))
        {
            return Err(invalid("defined-name scope past the sheets"));
        }
        for name in package.names().filter(|name| reader_part(name)) {
            parse_part(package, name)?;
        }
        Ok(Self {
            sheets,
            names,
            tables,
            refusal,
            vba_project: vba_project(package)?,
        })
    }

    /// Whether the workbook names `name`: a defined name or a table.
    fn defines(&self, name: &str) -> bool {
        self.names
            .iter()
            .any(|defined| defined.name.eq_ignore_ascii_case(name))
            || self.tables.contains(&name.to_lowercase())
    }

    /// Refuse what the engine must not evaluate natively, before it runs.
    fn admit(&self, links: &LinkedBooks) -> Result<()> {
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
        // The engine reads `[0]!Rate` as `Rate`: on a sheet with its own
        // `Rate` that is the sheet's, where Excel reads the workbook's.
        let sheet_level: BTreeSet<String> = self
            .names
            .iter()
            .filter(|name| name.sheet_level)
            .map(|name| name.name.to_lowercase())
            .collect();
        for (formula, defined) in cells.chain(names) {
            if let Some(name) = crate::links::workbook_qualified_names(formula)
                .into_iter()
                .find(|name| sheet_level.contains(&name.to_lowercase()))
            {
                return Err(unsupported(format!(
                    "workbook-qualified name with a sheet-level definition ([0]!{name})"
                )));
            }
            let inspection = crate::context::inspect_formula(formula)?;
            if let Some(need) = inspection.host_context {
                return Err(unsupported(format!("formula needs host context: {need}")));
            }
            // The engine does not resolve a workbook name to its LAMBDA yet:
            // MAP over one, or a call of one, would cache #NAME?.
            if let Some(name) = defined
                && inspection.lambda
            {
                return Err(unsupported(format!("defined name holds a LAMBDA: {name}")));
            }
            // The engine evaluates a call it does not resolve to #NAME?, and
            // so does Excel for a name outside its function list as the file
            // spells it (IMAGE without `_xlfn.`, EOM, a Google Sheets export's
            // __xludf.DUMMYFUNCTION): an undefined name. Such a call stays
            // native unless something Excel would call defines the name: the
            // workbook (a defined name or a table) or a linked workbook
            // (`[1]!Fn`), Excel itself, an XLL add-in or the workbook's VBA
            // project.
            let unknown = &inspection.unknown_functions;
            let defined = unknown
                .iter()
                .find(|function| self.defines(function) || function.contains('!'));
            if let Some(name) = inspection
                .callable_name
                .as_deref()
                .or(defined.map(String::as_str))
            {
                return Err(unsupported(format!("name used as a function: {name}")));
            }
            if let Some(name) = unknown.iter().find(|function| excel_function(function)) {
                return Err(unsupported(format!(
                    "function the engine does not implement: {name}"
                )));
            }
            if let Some(name) = unknown.iter().find(|function| prefixed(function, "_xll.")) {
                return Err(unsupported(format!("XLL add-in function: {name}")));
            }
            if self.vba_project
                && let Some(name) = unknown.first()
            {
                return Err(unsupported(format!(
                    "function the workbook's VBA project may define: {name}"
                )));
            }
        }
        // Every formula is bounded now. A linked workbook is written `[1]`, a
        // file name `[Book.xlsx]` and a linked name `[1]!Rate`, so only a
        // formula with `[`, or one using a workbook name that reads such a
        // reference (itself or through another name), reads another workbook.
        let mut parsed = Vec::new();
        for name in &self.names {
            parsed.push((
                name.name.as_str(),
                crate::context::parse_bounded(&name.formula)?,
            ));
        }
        let linked = links.names(parsed.iter().map(|(name, formula)| (*name, formula)));
        let reads_a_link = |formula: &str| {
            formula.contains('[') || {
                let upper = formula.to_ascii_uppercase();
                linked.keys().any(|name| upper.contains(name.as_str()))
            }
        };
        for formula in self.sheets.values().flatten() {
            if reads_a_link(formula) {
                links.admit(&crate::context::parse_bounded(formula)?, &linked)?;
            }
        }
        for name in &self.names {
            if reads_a_link(&name.formula) {
                links.admit_name(&crate::context::parse_bounded(&name.formula)?, &linked)?;
            }
        }
        Ok(())
    }
}

/// Whether `name`, as the file spells it, is one of Excel's functions: a bare
/// name of the Excel 2007 file format, one written `_xlfn.` or `_xlws.`, one
/// passed by name (Excel writes `_xleta.` only for its own functions), or an
/// Excel 4.0 macro function, which a defined name may call
/// (`GET.WORKBOOK(1)`, `EVALUATE(...)`; Excel runs them as macros).
fn excel_function(name: &str) -> bool {
    formualizer_workbook::is_excel_function(name)
        || prefixed(name, "_xleta.")
        || prefixed(name, "GET.")
        || EXCEL_BARE
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
}

/// Excel's functions a file names without a prefix that the fork's Excel 2007
/// list (`is_excel_function`) lacks, from the BIFF function tables of
/// LibreOffice's OOXML filter and Apache POI: DBCS (the stored name of JIS),
/// USDOLLAR and YEN (older names of DOLLAR), DATESTRING and NUMBERSTRING, the
/// Thai functions and the Euro tool's EUROCONVERT, then the Excel 4.0 macro
/// functions besides the `GET.` ones.
const EXCEL_BARE: &[&str] = &[
    "DATESTRING",
    "DBCS",
    "EUROCONVERT",
    "ISTHAIDIGIT",
    "NUMBERSTRING",
    "ROUNDBAHTDOWN",
    "ROUNDBAHTUP",
    "THAIDAYOFWEEK",
    "THAIDIGIT",
    "THAIMONTHOFYEAR",
    "THAINUMSOUND",
    "THAINUMSTRING",
    "THAISTRINGLENGTH",
    "THAIYEAR",
    "USDOLLAR",
    "YEN",
    "ABSREF",
    "ACTIVE.CELL",
    "APP.TITLE",
    "ARGUMENT",
    "CALL",
    "CALLER",
    "DEREF",
    "DIRECTORY",
    "DOCUMENTS",
    "ENABLE.TOOL",
    "END.IF",
    "ERROR",
    "EVALUATE",
    "EXEC",
    "FILES",
    "FORMULA.CONVERT",
    "GOTO",
    "LAST.ERROR",
    "LINKS",
    "NAMES",
    "PRESS.TOOL",
    "REFTEXT",
    "REGISTER",
    "REGISTER.ID",
    "RELREF",
    "RETURN",
    "SAVE.TOOLBAR",
    "SELECTION",
    "STEP",
    "TEXTREF",
    "WINDOW.TITLE",
    "WINDOWS",
];

fn prefixed(name: &str, prefix: &str) -> bool {
    crate::context::strip_prefix(name, prefix).is_some()
}

/// Whether the package holds a VBA project, whose functions Excel calls once
/// macros are enabled: `xl/vbaProject.bin`, or any part whose content type
/// (its `Override`, else its extension's `Default`) is a VBA project's.
fn vba_project(package: &Package) -> Result<bool> {
    const VBA_PROJECT: &str = "application/vnd.ms-office.vbaProject";
    // Part names and content types compare without case, as OPC compares them.
    let parts: Vec<String> = package
        .names()
        .map(|name| format!("/{}", name.to_ascii_lowercase()))
        .collect();
    if parts.iter().any(|part| part == "/xl/vbaproject.bin") {
        return Ok(true);
    }
    if !package.names().any(|name| name == "[Content_Types].xml") {
        return Ok(false);
    }
    let types = parse_part(package, "[Content_Types].xml")?;
    let mut overrides = BTreeMap::new();
    let mut defaults = BTreeMap::new();
    for node in &types.nodes {
        let kind = node.attr("ContentType").unwrap_or_default();
        if node.name == "Override"
            && let Some(part) = node.attr("PartName")
        {
            overrides.insert(part.to_ascii_lowercase(), kind);
        } else if node.name == "Default"
            && let Some(extension) = node.attr("Extension")
        {
            defaults.insert(extension.to_ascii_lowercase(), kind);
        }
    }
    Ok(parts.iter().any(|part| {
        let extension = part
            .rsplit('/')
            .next()
            .and_then(|file| file.rsplit_once('.'))
            .map(|(_, extension)| extension);
        overrides
            .get(part)
            .or_else(|| extension.and_then(|extension| defaults.get(extension)))
            .is_some_and(|kind| kind.eq_ignore_ascii_case(VBA_PROJECT))
    }))
}

/// The relationships of part `source` (the package's own for `""`) by id: the
/// target part, resolved from the source's folder, and the type. An external
/// target (a hyperlink, a linked workbook's path) names no part; the link
/// check admits only those external targets.
fn relationships(package: &Package, source: &str) -> Result<BTreeMap<String, (String, String)>> {
    let folder = source.rsplit_once('/').map_or("", |(folder, _)| folder);
    let rels = parse_part(package, &rels_part(source))?;
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
        if node.attr("TargetMode") == Some("External") {
            continue;
        }
        if targets
            .insert(id.to_owned(), (resolve(folder, target)?, kind.to_owned()))
            .is_some()
        {
            return Err(invalid("duplicate relationship id"));
        }
    }
    Ok(targets)
}

/// The relationship part of `source` (`_rels/.rels` for the package).
fn rels_part(source: &str) -> String {
    match source.rsplit_once('/') {
        Some((folder, name)) => format!("{folder}/_rels/{name}.rels"),
        None => format!("_rels/{source}.rels"),
    }
}

/// The parts the writer and its reader parse at fixed names, besides the
/// workbook and the relationship parts. The shared strings, worksheets and
/// tables are found through relationships.
fn reader_part(name: &str) -> bool {
    matches!(
        name,
        "[Content_Types].xml" | "xl/styles.xml" | "xl/metadata.xml"
    ) || (name.starts_with("xl/richData/") && name.ends_with(".xml"))
}

/// Check a table part the writer registers, as Excel would read it: malformed
/// content (an unnamed table, a range that is not one, a column list that
/// does not span it, a second table of the same name) is refused, and an
/// escaped table or column name is noted for the fallback.
fn check_table(
    package: &Package,
    part: &str,
    names: &mut BTreeSet<String>,
    refusal: &mut Option<Cow<'static, str>>,
) -> Result<()> {
    let xml = parse_part(package, part)?;
    xml.root(MAIN, "table")?;
    let table = &xml.nodes[0];
    let name = table
        .attr("displayName")
        .or_else(|| table.attr("name"))
        .ok_or_else(|| invalid("unnamed table"))?;
    if !names.insert(name.to_lowercase()) {
        return Err(invalid("duplicate table name"));
    }
    let area = table
        .attr("ref")
        .ok_or_else(|| invalid("invalid table range"))?;
    let (start, end) = area.split_once(':').unwrap_or((area, area));
    let column = |cell: &str| {
        parse_a1_1based(cell)
            .map(|(_, column, _, _)| column)
            .map_err(|_| invalid("invalid table range"))
    };
    let (first, last) = (column(start)?, column(end)?);
    for count in ["headerRowCount", "totalsRowCount"] {
        if table.attr(count).is_some_and(|n| n.parse::<u32>().is_err()) {
            return Err(invalid("invalid table row count"));
        }
    }
    let (list, _) = xml
        .child(0, MAIN, "tableColumns")?
        .ok_or_else(|| invalid("table columns missing"))?;
    let mut columns = 0u32;
    let mut escapes = escaped(name);
    for (_, node) in xml
        .children(list)
        .filter(|(_, node)| node.is(MAIN, "tableColumn"))
    {
        let header = node
            .attr("name")
            .ok_or_else(|| invalid("table column name missing"))?;
        escapes |= escaped(header);
        columns += 1;
    }
    // A reversed range is the writer's to refuse.
    if first <= last && columns != last - first + 1 {
        return Err(invalid("table column count mismatch"));
    }
    if escapes {
        refusal.get_or_insert_with(|| ESCAPED_TEXT.into());
    }
    Ok(())
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

pub(crate) const ESCAPED_TEXT: &str = "escaped text the reader does not decode as Excel does";

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
pub(crate) fn escaped(text: &str) -> bool {
    text.as_bytes().windows(7).any(|window| {
        window.starts_with(b"_x")
            && window[6] == b'_'
            && window[2..6].iter().all(u8::is_ascii_hexdigit)
    })
}

/// The edit round trip's corruption gate keeps every part outside its
/// supported set byte for byte, keeps every external link with its part,
/// relationship and content type, and requires the OOXML function prefix in
/// each worksheet whose bytes change (`oneiron::edit_roundtrip`'s
/// `session_validate`). A recalculation that would fail any check goes to
/// the fallback instead: the writer adds or edits `xl/richData/` rich values
/// when it tags a new #SPILL! or #CALC!, and never rewrites formula text.
/// Its other edits (worksheets, `xl/metadata.xml`, and the content types and
/// relationships of added parts) are parts the gate lets change, so long as
/// a relationship part holding an external target, the workbook's link
/// relationships and the links' content types stay as they were. The host
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
            None if name.starts_with("xl/externalLinks/") => {
                return Err(unsupported("recalculation changes an external link part"));
            }
            None if name == "[Content_Types].xml" => {
                let before_types = before.part(name)?;
                if link_content_types(before, before_types.as_deref())?
                    != link_content_types(before, part.as_deref())?
                {
                    return Err(unsupported(
                        "recalculation changes the content type of an external link",
                    ));
                }
            }
            None if name.ends_with(".rels") => {
                let before_rels = before.part(name)?;
                if before_rels.as_deref().is_some_and(|rels| {
                    !route_workbook([], [rels], [], before.limits().xml).is_in_process()
                }) {
                    return Err(unsupported(
                        "recalculation changes a relationship part with an external target",
                    ));
                }
                if name == "xl/_rels/workbook.xml.rels"
                    && link_relationships(before, before_rels.as_deref())?
                        != link_relationships(before, part.as_deref())?
                {
                    return Err(unsupported(
                        "recalculation changes the workbook's external link relationships",
                    ));
                }
            }
            None if name == "xl/metadata.xml" => {}
            None => {
                return Err(unsupported(format!(
                    "recalculation changes {name}, a part the edit gate passes through"
                )));
            }
        }
    }
    Ok(())
}

/// The workbook's external link relationships (`Id`, `Target`, `TargetMode`),
/// which the edit gate joins to its `<externalReference>` list.
fn link_relationships(
    package: &Package,
    rels: Option<&[u8]>,
) -> Result<Vec<(String, String, String)>> {
    let Some(rels) = rels else {
        return Ok(Vec::new());
    };
    let xml = Xml::parse(rels, package.limits().xml)?;
    let mut links: Vec<_> = xml
        .nodes
        .iter()
        .filter(|node| {
            node.is(REL, "Relationship")
                && node
                    .attr("Type")
                    .is_some_and(|kind| kind.ends_with("/externalLink"))
        })
        .map(|node| {
            let attr = |name| node.attr(name).unwrap_or_default().to_owned();
            (attr("Id"), attr("Target"), attr("TargetMode"))
        })
        .collect();
    links.sort();
    Ok(links)
}

/// The content-type entries (`Override` by part name, `Default` by extension)
/// that type the link parts of `package`, from content types `types`.
fn link_content_types(
    package: &Package,
    types: Option<&[u8]>,
) -> Result<Vec<(String, String, String)>> {
    let Some(types) = types else {
        return Ok(Vec::new());
    };
    let xml = Xml::parse(types, package.limits().xml)?;
    let links: BTreeSet<String> = package
        .names()
        .filter(|name| name.starts_with("xl/externalLinks/"))
        .map(|name| format!("/{name}").to_ascii_lowercase())
        .collect();
    let extensions: BTreeSet<String> = links
        .iter()
        .filter_map(|name| {
            name.rsplit_once('.')
                .map(|(_, extension)| extension.to_owned())
        })
        .collect();
    let mut entries: Vec<_> = xml
        .nodes
        .iter()
        .filter_map(|node| {
            let attr = |name| node.attr(name).unwrap_or_default().to_owned();
            if node.name == "Override" && links.contains(&attr("PartName").to_ascii_lowercase()) {
                Some(("Override".to_owned(), attr("PartName"), attr("ContentType")))
            } else if node.name == "Default"
                && extensions.contains(&attr("Extension").to_ascii_lowercase())
            {
                Some(("Default".to_owned(), attr("Extension"), attr("ContentType")))
            } else {
                None
            }
        })
        .collect();
    entries.sort();
    Ok(entries)
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
