//! Load a bounded XLSX graph and update only formula XML and cached values.
use std::collections::{BTreeMap, BTreeSet};

use formualizer_common::{
    CellAddress, DateSystem, ExcelError, ExcelErrorKind, LiteralValue, parse_a1_1based,
};
use formualizer_eval::engine::inspect::{SnapshotOptions, SpillRole};
use oneiron_docedit::opc::{Limits, Package};

use crate::cache::{Patch, apply_patches, cache_patches};
use crate::engine::{EngineId, FormualizerEngine};
use crate::xml::{DOC_REL, MAIN, REL, Xml, invalid, unsupported};
use crate::{Result, RouteDecision, route_workbook};

/// A retained XLSX output, ready for the EditSession corruption gate.
#[derive(Debug)]
pub struct WorkbookRecalc {
    pub bytes: Vec<u8>,
    pub engine: EngineId,
    pub formula_count: usize,
}

struct Sheet {
    name: String,
    part: String,
    xml: Xml,
    cells: Vec<Cell>,
}
struct Cell {
    node: usize,
    row: u32,
    col: u32,
    formula: Option<(usize, String)>,
    value: LiteralValue,
}

impl FormualizerEngine {
    /// Recalculate a real package in one multi-sheet dependency graph.
    ///
    /// This is opt-in, not the default session. External links and unsupported
    /// workbook semantics return `UnsupportedWorkbook` before bytes are emitted.
    /// Only existing scalar formula caches and `_xlfn` spellings are patched.
    /// Shared/array/table formulas, defined names and spill serialization stay
    /// on the caller's precision fallback until their retained writer exists.
    pub fn recalculate_xlsx(&self, bytes: &[u8]) -> Result<WorkbookRecalc> {
        let mut package = Package::open(bytes, Limits::default())?;
        require_local(&package)?;
        let (sheets, date_system) = load(&package)?;
        let route = route_workbook(
            [],
            [],
            sheets.iter().flat_map(|sheet| {
                sheet
                    .cells
                    .iter()
                    .filter_map(|cell| cell.formula.as_ref().map(|(_, text)| text.as_str()))
            }),
        );
        if let RouteDecision::Openpyxl { reason } = route {
            return Err(unsupported(reason));
        }
        let mut workbook = Self::configured_workbook(date_system)?;
        crate::mac_parity::apply(&mut workbook)?;
        // All sheet identities exist before references or cells enter the graph.
        for sheet in &sheets {
            workbook.add_sheet(&sheet.name).map_err(engine_error)?;
        }
        for sheet in &sheets {
            for cell in &sheet.cells {
                if let Some((_, formula)) = &cell.formula {
                    if crate::context::inspect_formula(formula)? {
                        return Err(unsupported(
                            "formula needs caller context or volatile reference semantics",
                        ));
                    }
                    workbook
                        .set_formula(&sheet.name, cell.row, cell.col, formula)
                        .map_err(engine_error)?;
                } else {
                    workbook
                        .set_value(&sheet.name, cell.row, cell.col, cell.value.clone())
                        .map_err(engine_error)?;
                }
            }
        }
        workbook.evaluate_all().map_err(engine_error)?;
        let mut formula_count = 0;
        for sheet in &sheets {
            let source = package
                .part(&sheet.part)
                .ok_or_else(|| invalid("missing sheet part"))?;
            let mut patches: Vec<Patch> = Vec::new();
            for cell in &sheet.cells {
                let Some((formula_node, _)) = &cell.formula else {
                    continue;
                };
                let address = CellAddress {
                    sheet: sheet.name.clone(),
                    row: cell.row,
                    column: cell.col,
                };
                let snapshot = workbook
                    .engine()
                    .inspect_cell(&address, &SnapshotOptions::default())
                    .map_err(engine_error)?;
                match snapshot.cell.spill {
                    None => {}
                    Some(SpillRole::Anchor { extent })
                        if extent.start_row == extent.end_row
                            && extent.start_col == extent.end_col => {}
                    Some(_) => return Err(unsupported("spill cache serialization")),
                }
                let value = workbook
                    .get_value(&sheet.name, cell.row, cell.col)
                    .ok_or_else(|| unsupported("missing evaluated formula cache"))?;
                cache_patches(
                    source,
                    &sheet.xml,
                    cell.node,
                    *formula_node,
                    value,
                    date_system,
                    &mut patches,
                )?;
                formula_count += 1;
            }
            let edited = apply_patches(source, patches)?;
            package.replace(&sheet.part, edited)?;
        }
        Ok(WorkbookRecalc {
            bytes: package.write()?,
            engine: EngineId {
                engine: env!("CARGO_PKG_NAME").to_owned(),
                version: format!(
                    "{}+formualizer.{}",
                    env!("CARGO_PKG_VERSION"),
                    crate::engine::ENGINE_VERSION,
                ),
            },
            formula_count,
        })
    }
}

fn engine_error(error: impl std::fmt::Display) -> crate::FormulaError {
    crate::FormulaError::Engine(error.to_string())
}

/// Cheap external-parts admission runs before semantic import, including on
/// workbooks whose local features are not yet handled by this adapter.
fn require_local(package: &Package) -> Result<()> {
    let route = route_workbook(
        package.names(),
        package
            .names()
            .filter(|name| name.ends_with(".rels"))
            .filter_map(|name| package.part(name)),
        [],
    );
    if let RouteDecision::Openpyxl { reason } = route {
        return Err(unsupported(reason));
    }
    Ok(())
}

fn load(package: &Package) -> Result<(Vec<Sheet>, DateSystem)> {
    let workbook = parse_part(package, "xl/workbook.xml")?;
    workbook.root(MAIN, "workbook")?;
    if workbook
        .nodes
        .iter()
        .any(|node| node.is(MAIN, "definedName"))
    {
        return Err(unsupported("defined names"));
    }
    if package.names().any(|name| name.starts_with("xl/tables/")) {
        return Err(unsupported("table references"));
    }
    if let Some((_, settings)) = workbook.child(0, MAIN, "calcPr")? {
        if settings
            .attr("iterate")
            .is_some_and(|v| matches!(v, "1" | "true"))
        {
            return Err(unsupported("iterative calculation settings"));
        }
        if settings
            .attr("fullPrecision")
            .is_some_and(|v| matches!(v, "0" | "false"))
        {
            return Err(unsupported("precision-as-displayed"));
        }
    }
    let date_system = match workbook
        .child(0, MAIN, "workbookPr")?
        .and_then(|(_, node)| node.attr("date1904"))
    {
        None | Some("0" | "false") => DateSystem::Excel1900,
        Some("1" | "true") => DateSystem::Excel1904,
        _ => return Err(invalid("invalid date1904 flag")),
    };
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
        if targets.insert(id, (resolve(target)?, kind)).is_some() {
            return Err(invalid("duplicate relationship id"));
        }
    }
    let strings_part = targets
        .values()
        .find(|(_, kind)| *kind == format!("{DOC_REL}/sharedStrings"));
    let strings = match strings_part {
        Some((part, _)) => shared_strings(&parse_part(package, part)?)?,
        None => Vec::new(),
    };
    let (sheet_list, _) = workbook
        .child(0, MAIN, "sheets")?
        .ok_or_else(|| invalid("missing sheets"))?;
    let mut sheets = Vec::new();
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for (_, node) in workbook
        .children(sheet_list)
        .filter(|(_, node)| node.is(MAIN, "sheet"))
    {
        let name = node
            .attr("name")
            .ok_or_else(|| invalid("sheet name missing"))?
            .to_owned();
        if !names.insert(name.to_lowercase()) {
            return Err(invalid("duplicate sheet name"));
        }
        let id = node
            .attr_ns(DOC_REL, "id")
            .ok_or_else(|| invalid("sheet relationship missing"))?;
        let (part, kind) = targets
            .get(id)
            .ok_or_else(|| invalid("unresolved sheet relationship"))?;
        if *kind != format!("{DOC_REL}/worksheet") {
            return Err(unsupported("non-worksheet sheet"));
        }
        if !paths.insert(part.clone()) {
            return Err(invalid("duplicate worksheet target"));
        }
        let xml = parse_part(package, part)?;
        xml.root(MAIN, "worksheet")?;
        let cells = cells(&xml, &strings)?;
        sheets.push(Sheet {
            name,
            part: part.clone(),
            xml,
            cells,
        });
    }
    if sheets.is_empty() {
        return Err(invalid("empty workbook"));
    }
    Ok((sheets, date_system))
}

/// Preserve external formula text as well as externalLink ZIP parts. Sheet
/// relationship targets, not filename guesses, locate the cells to protect.
pub(crate) fn external_formulas(package: &Package) -> Result<BTreeMap<(String, String), String>> {
    let rels = parse_part(package, "xl/_rels/workbook.xml.rels")?;
    rels.root(REL, "Relationships")?;
    let mut formulas = BTreeMap::new();
    let worksheet_type = format!("{DOC_REL}/worksheet");
    for (_, relation) in rels.children(0) {
        if !relation.is(REL, "Relationship")
            || relation.attr("Type") != Some(worksheet_type.as_str())
        {
            continue;
        }
        let target = relation
            .attr("Target")
            .ok_or_else(|| invalid("worksheet target missing"))?;
        let part = resolve(target)?;
        let xml = parse_part(package, &part)?;
        for (index, cell) in xml
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.is(MAIN, "c"))
        {
            if let Some((_, formula)) = xml.child(index, MAIN, "f")?
                && !route_workbook([], [], [formula.text.as_str()]).is_in_process()
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

fn parse_part(package: &Package, name: &str) -> Result<Xml> {
    Xml::parse(
        package
            .part(name)
            .ok_or_else(|| invalid("missing workbook part"))?,
    )
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

fn shared_strings(xml: &Xml) -> Result<Vec<String>> {
    xml.root(MAIN, "sst")?;
    xml.children(0)
        .filter(|(_, node)| node.is(MAIN, "si"))
        .map(|(index, _)| rich_text(xml, index))
        .collect()
}
fn rich_text(xml: &Xml, index: usize) -> Result<String> {
    let mut text = String::new();
    for (child, node) in xml.children(index) {
        if node.is(MAIN, "t") {
            text.push_str(&node.text);
        } else if node.is(MAIN, "r")
            && let Some((_, value)) = xml.child(child, MAIN, "t")?
        {
            text.push_str(&value.text);
        }
    }
    // OOXML's escape alphabet is not XML entity syntax. Until that codec is
    // implemented, refuse rather than compute a different text value.
    if text
        .as_bytes()
        .windows(7)
        .any(|w| w[0..2] == *b"_x" && w[6] == b'_' && w[2..6].iter().all(u8::is_ascii_hexdigit))
    {
        return Err(unsupported("OOXML escaped input text"));
    }
    Ok(text)
}

fn cells(xml: &Xml, strings: &[String]) -> Result<Vec<Cell>> {
    let Some((data, _)) = xml.child(0, MAIN, "sheetData")? else {
        return Ok(Vec::new());
    };
    let mut cells = Vec::new();
    let mut addresses = BTreeSet::new();
    for (row, _) in xml.children(data).filter(|(_, node)| node.is(MAIN, "row")) {
        for (index, node) in xml.children(row).filter(|(_, node)| node.is(MAIN, "c")) {
            let address = node
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
            if node.attr("cm").is_some() || node.attr("vm").is_some() {
                return Err(unsupported("cell value metadata"));
            }
            let formula = xml
                .child(index, MAIN, "f")?
                .map(|(i, formula)| {
                    if formula.attr("t").is_some_and(|t| t != "normal")
                        || formula.attr("ref").is_some()
                        || formula.attr("si").is_some()
                    {
                        return Err(unsupported("shared, array, or data-table formula"));
                    }
                    if formula.text.is_empty() {
                        return Err(invalid("empty formula"));
                    }
                    Ok((i, formula.text.clone()))
                })
                .transpose()?;
            let value = if formula.is_some() {
                LiteralValue::Empty
            } else {
                cell_value(xml, index, strings)?
            };
            cells.push(Cell {
                node: index,
                row,
                col,
                formula,
                value,
            });
        }
    }
    Ok(cells)
}
fn cell_value(xml: &Xml, index: usize, strings: &[String]) -> Result<LiteralValue> {
    let node = &xml.nodes[index];
    let value = xml
        .child(index, MAIN, "v")?
        .map_or("", |(_, node)| node.text.as_str());
    Ok(match node.attr("t") {
        None | Some("n") if value.is_empty() => LiteralValue::Empty,
        None | Some("n") => {
            let number: f64 = value.parse().map_err(|_| invalid("non-numeric value"))?;
            if !number.is_finite() {
                return Err(invalid("non-finite value"));
            }
            LiteralValue::Number(number)
        }
        Some("s") => {
            let index: usize = value.parse().map_err(|_| invalid("shared string index"))?;
            LiteralValue::Text(
                strings
                    .get(index)
                    .ok_or_else(|| invalid("missing shared string"))?
                    .clone(),
            )
        }
        Some("inlineStr") => match xml.child(index, MAIN, "is")? {
            Some((inline, _)) => LiteralValue::Text(rich_text(xml, inline)?),
            None if value.is_empty() => LiteralValue::Empty,
            None => return Err(invalid("missing inline string")),
        },
        Some("str") => LiteralValue::Text(value.into()),
        Some("b") => LiteralValue::Boolean(match value {
            "0" => false,
            "1" => true,
            _ => return Err(invalid("invalid boolean")),
        }),
        Some("e") => LiteralValue::Error(ExcelError::new(
            ExcelErrorKind::try_parse(value).ok_or_else(|| unsupported("unknown Excel error"))?,
        )),
        _ => return Err(unsupported("cell value type")),
    })
}
