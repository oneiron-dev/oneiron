//! The embedded workbook: direct A1 ranges, a SpreadsheetML cell reader,
//! and a writer that rebuilds only the rows it touches. Every write refuses
//! a workbook holding formulas, since a dependent formula's cached value
//! would go stale.
use super::{CellWrite, NativeRefusal, REL, WorkbookReport};
use crate::design_plan::{Cell, Column, ColumnKind, Dataset, calendar_date};
use crate::ooxml::{SPREADSHEET_MAIN as SML, XmlTree, escape_text};
use crate::retained_opc::{Limits, Package};
use std::collections::{BTreeMap, BTreeSet};

const BOOK_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
const SHEET_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";
const STYLES_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml";
/// The `cellXfs` index of the date style in a created workbook.
const DATE_STYLE: &str = "1";
/// The number format of date cells and date caches.
pub(super) const DATE_FORMAT: &str = "yyyy-mm-dd";
const MAX_COLUMN: u32 = 16_384;
const MAX_ROW: u32 = 1_048_576;

/// One worksheet cell: sheet name, 1-based column and row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct CellKey {
    pub sheet: String,
    pub col: u32,
    pub row: u32,
}

/// A direct one-row or one-column range on one sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Range {
    pub sheet: String,
    first: (u32, u32),
    last: (u32, u32),
}

impl Range {
    /// Parse a chart `c:f`: `Sheet1!$B$2:$B$5`, `'My sheet'!B1`.
    pub(super) fn parse(formula: &str) -> Result<Self, NativeRefusal> {
        let range = Self::parse_block(formula)?;
        if range.first.0 != range.last.0 && range.first.1 != range.last.1 {
            return Err(NativeRefusal::AmbiguousChartData(
                "series range is not one row or one column",
            ));
        }
        Ok(range)
    }

    /// Parse a multi-level category reference: a rectangle, one line of
    /// cells per level (FIX 3493). Every other sequence is one line.
    pub(super) fn parse_block(formula: &str) -> Result<Self, NativeRefusal> {
        let direct =
            NativeRefusal::AmbiguousChartData("series reference is not a direct cell range");
        if formula.contains('[') {
            return Err(NativeRefusal::ExternalChartSource(
                "the reference names another workbook",
            ));
        }
        let (sheet, area) = formula.trim().rsplit_once('!').ok_or(direct.clone())?;
        let sheet = match sheet.strip_prefix('\'') {
            Some(quoted) => quoted
                .strip_suffix('\'')
                .ok_or(direct.clone())?
                .replace("''", "'"),
            None if !sheet.is_empty() && !sheet.contains([' ', '\'', '(', ',']) => sheet.to_owned(),
            None => return Err(direct),
        };
        let (first, last) = area.split_once(':').unwrap_or((area, area));
        let (Some(first), Some(last)) = (cell_ref(first), cell_ref(last)) else {
            return Err(direct);
        };
        Ok(Self {
            sheet,
            first: (first.0.min(last.0), first.1.min(last.1)),
            last: (first.0.max(last.0), first.1.max(last.1)),
        })
    }

    /// Its first and last cells, (column, row).
    pub(super) fn corners(&self) -> ((u32, u32), (u32, u32)) {
        (self.first, self.last)
    }

    pub(super) fn column(sheet: &str, col: u32, rows: (u32, u32)) -> Self {
        Self {
            sheet: sheet.to_owned(),
            first: (col, rows.0),
            last: (col, rows.1),
        }
    }

    /// Cells in sequence order.
    pub(super) fn cells(&self) -> Vec<CellKey> {
        (self.first.1..=self.last.1)
            .flat_map(|row| {
                (self.first.0..=self.last.0).map(move |col| CellKey {
                    sheet: self.sheet.clone(),
                    col,
                    row,
                })
            })
            .collect()
    }

    pub(super) fn formula(&self) -> String {
        let sheet = format!("'{}'", self.sheet.replace('\'', "''"));
        let first = format!("${}${}", letters(self.first.0), self.first.1);
        if self.first == self.last {
            return format!("{sheet}!{first}");
        }
        format!("{sheet}!{first}:${}${}", letters(self.last.0), self.last.1)
    }
}

/// `$B$12` → (2, 12).
fn cell_ref(text: &str) -> Option<(u32, u32)> {
    let text = text.strip_prefix('$').unwrap_or(text);
    let split = text.find(|c: char| !c.is_ascii_uppercase())?;
    let (letters, digits) = text.split_at(split);
    let digits = digits.strip_prefix('$').unwrap_or(digits);
    if letters.is_empty() || letters.len() > 3 || digits.starts_with('0') {
        return None;
    }
    let col = letters
        .bytes()
        .fold(0u32, |sum, byte| sum * 26 + u32::from(byte - b'A' + 1));
    let row = digits.parse::<u32>().ok()?;
    (col <= MAX_COLUMN && (1..=MAX_ROW).contains(&row)).then_some((col, row))
}

fn letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        let digit = (col - 1) % 26;
        out.push(b'A' + digit as u8);
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

pub(super) fn a1(key: &CellKey) -> String {
    format!("{}{}", letters(key.col), key.row)
}

/// The shortest text that parses back to the same number.
pub(crate) fn number(value: f64) -> String {
    format!("{value}")
}

/// A `YYYY-MM-DD` date as a serial day. The 1900 system counts 1900-01-01 as
/// 1 and, from 1900-03-01, Lotus's phantom 1900-02-29; the 1904 system counts
/// 1904-01-01 as 0. A day before the system's first has no serial.
pub(crate) fn serial(date: &str, date1904: bool) -> Result<f64, NativeRefusal> {
    let (year, month, day) =
        calendar_date(date).ok_or(NativeRefusal::Invalid("a date that is not YYYY-MM-DD"))?;
    // Days from 1970-01-01 in the proleptic Gregorian calendar (Hinnant).
    let (month, day) = (i64::from(month), i64::from(day));
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + of_era * 365 + of_era / 4 - of_era / 100 + of_year - 719_468;
    let (day, first) = if date1904 {
        (days + 24_107, 0)
    } else {
        let day = days + 25_569;
        (if day < 61 { day - 1 } else { day }, 1)
    };
    if day < first {
        return Err(NativeRefusal::Invalid("a date before its date system"));
    }
    Ok(day as f64)
}

/// A column header: its name, and its unit in parentheses.
pub(crate) fn header(column: &Column) -> String {
    match &column.unit {
        Some(unit) => format!("{} ({unit})", column.name),
        None => column.name.clone(),
    }
}

/// An opened embedded workbook.
pub(super) struct Workbook {
    package: Package,
    /// Sheet name → worksheet part.
    sheets: BTreeMap<String, String>,
    shared: Vec<String>,
    /// Serial days count from 1904-01-01 rather than 1900-01-01.
    pub(super) date1904: bool,
}

#[derive(Debug)]
struct Stored {
    value: Cell,
    formula: bool,
    style: Option<String>,
}

impl Workbook {
    pub(super) fn open(bytes: &[u8], limits: Limits) -> Result<Self, NativeRefusal> {
        let package = Package::open(bytes, limits).map_err(NativeRefusal::Workbook)?;
        let rels = package.relationships("").map_err(NativeRefusal::Workbook)?;
        let book = rels
            .iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/officeDocument"))
            .ok_or(NativeRefusal::AmbiguousChartData(
                "embedded package holds no workbook",
            ))?
            .target
            .clone();
        let tree = parse(&package, &book)?;
        tree.root(SML, "workbook")
            .map_err(|_| NativeRefusal::AmbiguousChartData("embedded package holds no workbook"))?;
        let date1904 = tree
            .child(0, SML, "workbookPr")?
            .and_then(|(_, node)| node.attr("date1904"))
            .is_some_and(|value| matches!(value.trim(), "1" | "true"));
        let links = package
            .relationships(&book)
            .map_err(NativeRefusal::Workbook)?;
        let mut sheets = BTreeMap::new();
        if let Some((list, _)) = tree.child(0, SML, "sheets")? {
            for (_, sheet) in tree
                .children(list)
                .filter(|(_, node)| node.is(SML, "sheet"))
            {
                let target = sheet
                    .attr_ns(REL, "id")
                    .and_then(|id| links.iter().find(|rel| rel.id == id && !rel.external));
                if let (Some(name), Some(rel)) = (sheet.attr("name"), target) {
                    sheets.insert(name.to_owned(), rel.target.clone());
                }
            }
        }
        let mut shared = Vec::new();
        if let Some(rel) = links
            .iter()
            .find(|rel| rel.kind.ends_with("/sharedStrings"))
        {
            let sst = parse(&package, &rel.target)?;
            for (item, _) in sst.children(0).filter(|(_, node)| node.is(SML, "si")) {
                shared.push(string_item(&sst, item));
            }
        }
        Ok(Self {
            package,
            sheets,
            shared,
            date1904,
        })
    }

    /// The typed value of each cell; an absent cell or one without a value is
    /// missing.
    pub(super) fn read(&self, keys: &[CellKey]) -> Result<Vec<Cell>, NativeRefusal> {
        let mut by_sheet: BTreeMap<&str, BTreeMap<(u32, u32), Stored>> = BTreeMap::new();
        keys.iter()
            .map(|key| {
                if !by_sheet.contains_key(key.sheet.as_str()) {
                    by_sheet.insert(&key.sheet, self.cells(&key.sheet)?);
                }
                Ok(by_sheet[key.sheet.as_str()]
                    .get(&(key.col, key.row))
                    .map_or(Cell::Missing, |stored| stored.value.clone()))
            })
            .collect()
    }

    /// Write every cell as one workbook package edit, after refusing any
    /// workbook formula. Returns the new package bytes and the nested report.
    pub(super) fn write(
        mut self,
        part: &str,
        writes: &[(CellKey, Cell)],
    ) -> Result<(Vec<u8>, WorkbookReport), NativeRefusal> {
        for sheet in self.sheets.keys() {
            let cells = self.cells(sheet)?;
            if cells.values().any(|stored| stored.formula) {
                let touched = writes.iter().any(|(key, _)| {
                    key.sheet == *sheet
                        && cells
                            .get(&(key.col, key.row))
                            .is_some_and(|stored| stored.formula)
                });
                return Err(NativeRefusal::FormulaBackedSeries(if touched {
                    "a source cell holds a formula"
                } else {
                    "the workbook holds formulas a write could make stale"
                }));
            }
        }
        let mut by_sheet: BTreeMap<&str, Vec<&(CellKey, Cell)>> = BTreeMap::new();
        for write in writes {
            by_sheet
                .entry(write.0.sheet.as_str())
                .or_default()
                .push(write);
        }
        let mut parts = BTreeSet::new();
        for (sheet, writes) in by_sheet {
            let name = self
                .sheets
                .get(sheet)
                .ok_or(NativeRefusal::AmbiguousChartData(
                    "the referenced sheet does not exist",
                ))?
                .clone();
            let styles = self.cells(sheet)?;
            let bytes = self.rewrite_sheet(&name, &writes, &styles)?;
            self.package
                .replace_xml_part(&name, bytes)
                .map_err(NativeRefusal::Workbook)?;
            parts.insert(name);
        }
        let changed: Vec<String> = self
            .package
            .changed_parts()
            .into_iter()
            .map(str::to_owned)
            .collect();
        if changed.iter().any(|name| !parts.contains(name)) {
            return Err(NativeRefusal::OutsideAllowedParts(part.to_owned()));
        }
        let bytes = self.package.export().map_err(NativeRefusal::Workbook)?;
        let report = WorkbookReport {
            part: part.to_owned(),
            changed_parts: changed,
            cells: writes
                .iter()
                .map(|(key, value)| CellWrite {
                    sheet: key.sheet.clone(),
                    cell: a1(key),
                    value: value.clone(),
                })
                .collect(),
        };
        Ok((bytes, report))
    }

    fn cells(&self, sheet: &str) -> Result<BTreeMap<(u32, u32), Stored>, NativeRefusal> {
        let part = self
            .sheets
            .get(sheet)
            .ok_or(NativeRefusal::AmbiguousChartData(
                "the referenced sheet does not exist",
            ))?;
        let tree = parse(&self.package, part)?;
        let mut out = BTreeMap::new();
        for (index, node) in tree.nodes.iter().enumerate() {
            if !node.is(SML, "c") {
                continue;
            }
            let key =
                node.attr("r")
                    .and_then(cell_ref)
                    .ok_or(NativeRefusal::AmbiguousChartData(
                        "a worksheet cell has no reference",
                    ))?;
            let text = |name: &str| -> Result<Option<String>, NativeRefusal> {
                Ok(tree
                    .child(index, SML, name)?
                    .map(|(_, child)| child.text.clone()))
            };
            let formula = tree.child(index, SML, "f")?.is_some();
            let value =
                match (node.attr("t").unwrap_or("n"), text("v")?) {
                    ("inlineStr", _) => match tree.child(index, SML, "is")? {
                        Some((item, _)) => Cell::Text(string_item(&tree, item)),
                        None => Cell::Missing,
                    },
                    (_, None) => Cell::Missing,
                    ("n", Some(value)) => Cell::Number(value.trim().parse().map_err(|_| {
                        NativeRefusal::AmbiguousChartData("unreadable number cell")
                    })?),
                    ("s", Some(at)) => Cell::Text(
                        at.trim()
                            .parse::<usize>()
                            .ok()
                            .and_then(|at| self.shared.get(at))
                            .ok_or(NativeRefusal::AmbiguousChartData("dangling shared string"))?
                            .clone(),
                    ),
                    ("str", Some(value)) => Cell::Text(value),
                    _ => {
                        return Err(NativeRefusal::AmbiguousChartData(
                            "a cell type the chart cache cannot mirror",
                        ));
                    }
                };
            out.insert(
                key,
                Stored {
                    value,
                    formula,
                    style: node.attr("s").map(str::to_owned),
                },
            );
        }
        Ok(out)
    }

    /// Rebuild `sheetData` with the touched rows rewritten in column order
    /// and new rows inserted in row order; untouched rows keep their bytes.
    fn rewrite_sheet(
        &self,
        part: &str,
        writes: &[&(CellKey, Cell)],
        styles: &BTreeMap<(u32, u32), Stored>,
    ) -> Result<Vec<u8>, NativeRefusal> {
        let bytes = self
            .package
            .part(part)
            .map_err(NativeRefusal::Workbook)?
            .ok_or(NativeRefusal::AmbiguousChartData("worksheet part missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let (data, data_node) =
            tree.child(0, SML, "sheetData")?
                .ok_or(NativeRefusal::AmbiguousChartData(
                    "worksheet has no sheetData",
                ))?;
        let mut rows: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let mut touched: BTreeMap<u32, BTreeMap<u32, &Cell>> = BTreeMap::new();
        for (key, value) in writes {
            touched.entry(key.row).or_default().insert(key.col, value);
        }
        let row_name = data_node.child_name("row");
        for (index, row) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
            let number = row.attr("r").and_then(|r| r.parse::<u32>().ok()).ok_or(
                NativeRefusal::AmbiguousChartData("a worksheet row has no number"),
            )?;
            let Some(cells) = touched.remove(&number) else {
                rows.insert(number, bytes[row.span.clone()].to_vec());
                continue;
            };
            let mut line: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
            for (_, cell) in tree.children(index).filter(|(_, node)| node.is(SML, "c")) {
                let col = cell
                    .attr("r")
                    .and_then(cell_ref)
                    .ok_or(NativeRefusal::AmbiguousChartData(
                        "a worksheet cell has no reference",
                    ))?
                    .0;
                line.insert(col, bytes[cell.span.clone()].to_vec());
            }
            let cell_name = row.child_name("c");
            for (col, value) in cells {
                let key = CellKey {
                    sheet: String::new(),
                    col,
                    row: number,
                };
                let style = styles.get(&(col, number)).and_then(|s| s.style.as_deref());
                line.insert(col, cell_xml(&cell_name, &key, style, value)?.into_bytes());
            }
            let open = &bytes[row.span.start..row.open_end];
            let open = if row.empty {
                open.strip_suffix(b"/>").unwrap_or(open)
            } else {
                open.strip_suffix(b">").unwrap_or(open)
            };
            let mut out = open.to_vec();
            out.push(b'>');
            line.into_values().for_each(|cell| out.extend(cell));
            out.extend_from_slice(format!("</{}>", row.qualified).as_bytes());
            rows.insert(number, out);
        }
        for (number, cells) in touched {
            let cell_name = data_node.child_name("c");
            let mut out = format!("<{row_name} r=\"{number}\">");
            for (col, value) in cells {
                let key = CellKey {
                    sheet: String::new(),
                    col,
                    row: number,
                };
                out.push_str(&cell_xml(&cell_name, &key, None, value)?);
            }
            out.push_str(&format!("</{row_name}>"));
            rows.insert(number, out.into_bytes());
        }
        let open = &bytes[data_node.span.start..data_node.open_end];
        let open = open
            .strip_suffix(b"/>")
            .or_else(|| open.strip_suffix(b">"))
            .unwrap_or(open);
        let mut out = bytes[..data_node.span.start].to_vec();
        out.extend_from_slice(open);
        out.push(b'>');
        rows.into_values().for_each(|row| out.extend(row));
        out.extend_from_slice(format!("</{}>", data_node.qualified).as_bytes());
        out.extend_from_slice(&bytes[data_node.span.end..]);
        Ok(out)
    }
}

fn parse(package: &Package, part: &str) -> Result<XmlTree, NativeRefusal> {
    let bytes = package
        .part(part)
        .map_err(NativeRefusal::Workbook)?
        .ok_or(NativeRefusal::AmbiguousChartData("workbook part missing"))?;
    Ok(XmlTree::parse(&bytes, package.limits().xml)?)
}

/// The text of a shared or inline string item, phonetic runs excluded.
fn string_item(tree: &XmlTree, item: usize) -> String {
    let mut out = String::new();
    for (index, node) in tree.children(item) {
        if node.is(SML, "t") {
            out.push_str(&node.text);
        } else if node.is(SML, "r") {
            out.push_str(&string_item(tree, index));
        }
    }
    out
}

fn cell_xml(
    name: &str,
    key: &CellKey,
    style: Option<&str>,
    value: &Cell,
) -> Result<String, NativeRefusal> {
    let prefix = name.strip_suffix('c').unwrap_or("");
    let style = style.map_or_else(String::new, |s| format!(" s=\"{}\"", escape_text(s)));
    let r = a1(key);
    Ok(match value {
        Cell::Missing => format!("<{name} r=\"{r}\"{style}/>"),
        Cell::Number(n) if n.is_finite() => {
            format!(
                "<{name} r=\"{r}\"{style}><{prefix}v>{}</{prefix}v></{name}>",
                number(*n)
            )
        }
        Cell::Number(_) => return Err(NativeRefusal::Invalid("a number must be finite")),
        // Only a created workbook takes a date: its system is 1900.
        Cell::Date(date) => format!(
            "<{name} r=\"{r}\"{style}><{prefix}v>{}</{prefix}v></{name}>",
            number(serial(date, false)?)
        ),
        Cell::Text(text) => format!(
            "<{name} r=\"{r}\"{style} t=\"inlineStr\"><{prefix}is><{prefix}t xml:space=\"preserve\">{}</{prefix}t></{prefix}is></{name}>",
            escape_text(text)
        ),
    })
}

/// A new workbook for a chart: row 1 holds the headers, then one row per
/// dataset row. A missing value leaves its cell absent, except in a date
/// column, whose cells all carry the date style.
pub(super) fn create(
    dataset: &Dataset,
    sheet: &str,
    limits: Limits,
) -> Result<Vec<u8>, NativeRefusal> {
    if sheet.is_empty()
        || sheet.chars().count() > 31
        || sheet.contains(['[', ']', ':', '*', '?', '/', '\\'])
        || sheet.starts_with('\'')
        || sheet.ends_with('\'')
    {
        return Err(NativeRefusal::Invalid("sheet name"));
    }
    // Style 0 is General, style 1 a date; each distinct number format of a
    // column takes the next style over its own format id from 165.
    let mut codes: Vec<String> = Vec::new();
    for column in &dataset.columns {
        if let Some(code) = column.format.map(|format| format.code())
            && !codes.contains(&code)
        {
            codes.push(code);
        }
    }
    let number_style: Vec<Option<String>> = dataset
        .columns
        .iter()
        .map(|column| {
            let code = column.format?.code();
            codes
                .iter()
                .position(|held| *held == code)
                .map(|index| (index + 2).to_string())
        })
        .collect();
    let mut data = String::new();
    let names = std::iter::once(
        dataset
            .columns
            .iter()
            .map(|column| Cell::Text(header(column)))
            .collect::<Vec<_>>(),
    );
    for (at, row) in names.chain(dataset.rows.iter().cloned()).enumerate() {
        let number = u32::try_from(at + 1).map_err(|_| NativeRefusal::Invalid("too many rows"))?;
        data.push_str(&format!("<row r=\"{number}\">"));
        for (col, value) in row.iter().enumerate() {
            let dated = at > 0
                && dataset
                    .columns
                    .get(col)
                    .is_some_and(|column| column.kind == ColumnKind::Date);
            if *value == Cell::Missing && !dated {
                continue;
            }
            let key = CellKey {
                sheet: String::new(),
                col: u32::try_from(col + 1)
                    .map_err(|_| NativeRefusal::Invalid("too many columns"))?,
                row: number,
            };
            let style = if dated {
                Some(DATE_STYLE)
            } else if at > 0 && matches!(value, Cell::Number(_)) {
                number_style.get(col).and_then(Option::as_deref)
            } else {
                None
            };
            data.push_str(&cell_xml("c", &key, style, value)?);
        }
        data.push_str("</row>");
    }
    let mut package = Package::create(limits)?;
    package.relate("", &format!("{REL}/officeDocument"), "xl/workbook.xml")?;
    let sheet_link = package.relate(
        "xl/workbook.xml",
        &format!("{REL}/worksheet"),
        "xl/worksheets/sheet1.xml",
    )?;
    package.relate("xl/workbook.xml", &format!("{REL}/styles"), "xl/styles.xml")?;
    let book = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<workbook xmlns=\"{SML}\" xmlns:r=\"{REL}\"><workbookPr date1904=\"0\"/><sheets><sheet name=\"{}\" sheetId=\"1\" r:id=\"{sheet_link}\"/></sheets></workbook>",
        escape_text(sheet)
    );
    package.add_part("xl/workbook.xml", BOOK_TYPE, book.into_bytes())?;
    let worksheet = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<worksheet xmlns=\"{SML}\"><sheetData>{data}</sheetData></worksheet>"
    );
    package.add_part(
        "xl/worksheets/sheet1.xml",
        SHEET_TYPE,
        worksheet.into_bytes(),
    )?;
    // Style 0 is General; style 1 shows a serial as a date.
    let formats: String = codes
        .iter()
        .enumerate()
        .map(|(index, code)| {
            format!(
                "<numFmt numFmtId=\"{}\" formatCode=\"{}\"/>",
                165 + index,
                escape_text(code)
            )
        })
        .collect();
    let number_xfs: String = (0..codes.len())
        .map(|index| {
            format!(
                "<xf numFmtId=\"{}\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyNumberFormat=\"1\"/>",
                165 + index
            )
        })
        .collect();
    let (format_count, xf_count) = (1 + codes.len(), 2 + codes.len());
    let styles = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<styleSheet xmlns=\"{SML}\"><numFmts count=\"{format_count}\"><numFmt numFmtId=\"164\" formatCode=\"{DATE_FORMAT}\"/>{formats}</numFmts><fonts count=\"1\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font></fonts><fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill></fills><borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs><cellXfs count=\"{xf_count}\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/><xf numFmtId=\"164\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyNumberFormat=\"1\"/>{number_xfs}</cellXfs><cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles></styleSheet>"
    );
    package.add_part("xl/styles.xml", STYLES_TYPE, styles.into_bytes())?;
    Ok(package.export()?)
}
