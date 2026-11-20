//! Reading the formulas the writer evaluates (`Formulas::read`), with the
//! reader's checks of malformed content: cells, strings, tables,
//! relationships and the parts the writer parses at fixed names.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use formualizer_common::parse_a1_1based;
use oneiron_docedit::ooxml::Node;
use oneiron_docedit::retained_opc::Package;

use super::{DefinedName, ESCAPED_TEXT, Formulas, escaped, resolve};
use crate::Result;
use crate::xml::{DOC_REL, MAIN, REL, Xml, invalid, parse_part};

impl Formulas {
    /// Read what the writer reads, as the reader before it did: every part
    /// under the host's XML limits, and malformed content refused.
    pub(super) fn read(package: &Package) -> Result<Self> {
        let workbook = parse_part(package, "xl/workbook.xml")?;
        workbook.root(MAIN, "workbook")?;
        // Precision as displayed (`fullPrecision="0"`) is the writer's: it
        // stores each formula result as its cell's format shows it, as Excel
        // does, and refuses a format whose stored values it does not know.
        let mut refusal = None;
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
        let mut names_in_order = Vec::new();
        let mut filename_caches = Vec::new();
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
            names_in_order.push(name.to_owned());
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
            filename_caches.extend(text_caches(&xml, "CELL(")?);
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
            sheet_names: names_in_order,
            filename_caches,
        })
    }
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

/// Each formula of `xml` that holds `call`, without case, with the text cached
/// by every cell it computes (a shared formula's anchor computes the cells
/// sharing it, wherever the anchor sits): Excel caches a formula's text
/// result as `t="str"`. `None` for a cached text with an escape the reader
/// does not decode. A formula's text is read and held once, however many
/// cells share it, since it is bounded only after this scan.
fn text_caches(xml: &Xml, call: &str) -> Result<Vec<(String, Vec<Option<String>>)>> {
    fn group(formula: &Node) -> Option<u32> {
        formula
            .attr("si")
            .filter(|_| formula.attr("t") == Some("shared"))
            .and_then(|index| index.parse().ok())
    }
    let mut caches = Vec::new();
    let Some((data, _)) = xml.child(0, MAIN, "sheetData")? else {
        return Ok(caches);
    };
    let mut cells = Vec::new();
    for (row, _) in xml.children(data).filter(|(_, node)| node.is(MAIN, "row")) {
        for (index, cell) in xml.children(row).filter(|(_, node)| node.is(MAIN, "c")) {
            if let Some((_, formula)) = xml.child(index, MAIN, "f")? {
                cells.push((index, cell, formula));
            }
        }
    }
    // Grouped as the writer groups them: by the index's number (`si="00"` is
    // group 0), a formula of blank text a member.
    let member = |formula: &Node| formula.text.trim().is_empty();
    // Each formula that holds `call`, by its place in `caches`.
    let mut own = Vec::with_capacity(cells.len());
    let mut shared = BTreeMap::new();
    for (_, _, formula) in &cells {
        if member(formula) {
            own.push(None);
            continue;
        }
        let entry = formula.text.to_ascii_uppercase().contains(call).then(|| {
            caches.push((formula.text.clone(), Vec::new()));
            caches.len() - 1
        });
        if let Some(group) = group(formula) {
            shared.insert(group, entry);
        }
        own.push(entry);
    }
    for ((index, cell, formula), entry) in cells.iter().zip(own) {
        let entry = if member(formula) {
            group(formula).and_then(|group| shared.get(&group).copied().flatten())
        } else {
            entry
        };
        let Some(entry) = entry.filter(|_| cell.attr("t") == Some("str")) else {
            continue;
        };
        if let Some((_, value)) = xml.child(*index, MAIN, "v")? {
            let value = (!escaped(&value.text)).then(|| value.text.clone());
            caches[entry].1.push(value);
        }
    }
    caches.retain(|(_, texts)| !texts.is_empty());
    Ok(caches)
}

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
