//! SpreadsheetML model, validation and A1 rules.
//! Entry: `XlsxBook`.
//! Definitions live here; xlsx_body retains the old API and shared Book state.

use super::*;

/// Excel's ceiling on one cell's text.
pub const MAX_TEXT_CHARS: usize = 32_767;

/// Excel's ceiling on one formula.
pub const MAX_FORMULA_CHARS: usize = 8_192;

pub(super) const MAX_COLUMN: u32 = 16_384;

pub(super) const MAX_ROW: u32 = 1_048_576;

/// Excel's ceiling on a sheet name.
pub(super) const MAX_SHEET_NAME: usize = 31;

/// The error values a cell may be written with.
pub(super) const ERRORS: &[&str] = &[
    "#NULL!",
    "#DIV/0!",
    "#VALUE!",
    "#REF!",
    "#NAME?",
    "#NUM!",
    "#N/A",
    "#GETTING_DATA",
];

/// A workbook as the body imports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxBook {
    /// Serial days count from 1904-01-01 rather than 1900-01-01.
    pub date1904: bool,
    /// Worksheets in workbook order; chart and dialog sheets hold no cells.
    pub sheets: Vec<XlsxSheet>,
    pub names: Vec<XlsxName>,
    /// The workbook's cell formats (`cellXfs`), by index. A workbook with no
    /// stylesheet has one, Excel's default (General).
    pub styles: Vec<XlsxStyle>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxSheet {
    pub name: String,
    /// Stored cells in row-major order.
    pub cells: Vec<XlsxCell>,
    /// Ranges the body may not write, stored cell or not: array formula and
    /// data table ranges, and table header and totals rows.
    pub locked: Vec<XlsxArea>,
    pub tables: Vec<XlsxTable>,
    pub visibility: XlsxSheetVisibility,
}

/// Whether a sheet's tab shows, as Excel's `<sheet state>` holds it. A
/// `veryHidden` sheet is left out of Excel's Unhide list too.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum XlsxSheetVisibility {
    #[default]
    Visible,
    Hidden,
    VeryHidden,
}

impl XlsxSheetVisibility {
    /// From a `<sheet state>` value; none, or any other, is visible.
    #[must_use]
    pub fn from_state(state: Option<&str>) -> Self {
        match state.map(str::trim) {
            Some("hidden") => Self::Hidden,
            Some("veryHidden") => Self::VeryHidden,
            _ => Self::Visible,
        }
    }

    /// The `<sheet state>` value; a visible sheet carries none.
    #[must_use]
    pub const fn state(self) -> Option<&'static str> {
        match self {
            Self::Visible => None,
            Self::Hidden => Some("hidden"),
            Self::VeryHidden => Some("veryHidden"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxCell {
    pub col: u32,
    pub row: u32,
    /// The stored value; a formula's is its cached result.
    pub value: XlsxValue,
    /// The formula as a person types it, without `=` or storage prefixes.
    pub formula: Option<String>,
    /// The cell format, an index into [`XlsxBook::styles`].
    pub style: Option<u32>,
    /// Why the body may not write this cell.
    pub locked: Option<XlsxLock>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XlsxValue {
    Blank,
    Number(f64),
    Text(String),
    Bool(bool),
    /// An error value such as `#N/A`.
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XlsxLock {
    /// A shared formula member whose anchor's text, moved to its cell, would
    /// leave the sheet, or one of a group with no anchor. Readable members
    /// carry their own text and are writable.
    SharedFormula,
    /// Inside an array formula's range, a dynamic array's spill included.
    ArrayFormula,
    /// Inside a what-if data table.
    DataTable,
    /// A rich value: an image in a cell, a linked data type.
    RichValue,
    /// A table's header or totals row, which the table part also names.
    TableRow,
    /// A value or name the body does not model: an ISO date cell, a macro name.
    Unsupported,
    /// A built-in name: a print area, a filter range.
    BuiltinName,
}

/// A rectangular range, 1-based `(column, row)` corners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxArea {
    pub first: (u32, u32),
    pub last: (u32, u32),
    pub lock: XlsxLock,
}

impl XlsxArea {
    /// `B2:D9`, `$B$2`, or one cell.
    #[must_use]
    pub fn parse(reference: &str, lock: XlsxLock) -> Option<Self> {
        let (first, last) = reference.split_once(':').unwrap_or((reference, reference));
        let (first, last) = (cell_ref(first.trim())?, cell_ref(last.trim())?);
        Some(Self {
            first: (first.0.min(last.0), first.1.min(last.1)),
            last: (first.0.max(last.0), first.1.max(last.1)),
            lock,
        })
    }

    #[must_use]
    pub fn contains(&self, col: u32, row: u32) -> bool {
        (self.first.0..=self.last.0).contains(&col) && (self.first.1..=self.last.1).contains(&row)
    }

    #[must_use]
    pub fn reference(&self) -> String {
        let first = a1(self.first.0, self.first.1);
        if self.first == self.last {
            return first;
        }
        format!("{first}:{}", a1(self.last.0, self.last.1))
    }
}

/// A table on a worksheet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxTable {
    /// The name formulas call it by (its `displayName`).
    pub name: String,
    /// Its range's 1-based `(column, row)` corners, header and totals rows
    /// included.
    pub first: (u32, u32),
    pub last: (u32, u32),
    /// Its header rows at the top of the range (0 or 1) and totals rows at
    /// the bottom.
    pub header_rows: u32,
    pub totals_rows: u32,
    /// Its columns' names, left to right.
    pub columns: Vec<String>,
    /// A worksheet table. A query or XML-mapped table takes its columns from
    /// its source, so no column edit goes inside it.
    pub worksheet: bool,
    /// Each column's calculated formula (`calculatedColumnFormula`, not an
    /// array one), as a person types it and as its first data row reads it,
    /// left to right; `None` for a column without one, and empty when no
    /// column has one. A row inserted inside the data area takes them
    /// ([`calculated_fill`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calculated: Vec<Option<String>>,
}

/// A table after a row or column edit to its sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XlsxTableShift {
    pub table: XlsxTable,
    /// The names of the columns the edit deleted from it.
    pub deleted: Vec<String>,
    /// The columns the edit inserted inside it: each one's sheet column and
    /// name.
    pub inserted: Vec<(u32, String)>,
}

impl XlsxTable {
    /// The table after `edit`, as Excel moves it: a column edit inside its
    /// range adds or removes its columns, an inserted one taking the first
    /// free `ColumnN` name, and one at or past either edge only moves it.
    /// `None` when the edit deletes all of it.
    #[must_use]
    pub fn shifted(&self, edit: &XlsxAxisEdit) -> Option<XlsxTableShift> {
        let (first, last) = edit.area(self.first, self.last)?;
        let mut table = Self {
            first,
            last,
            ..self.clone()
        };
        let (mut deleted, mut inserted) = (Vec::new(), Vec::new());
        // A table whose columns do not match its range refuses at export.
        let matched = self.columns.len() == (self.last.0 - self.first.0 + 1) as usize;
        if let Some(at) = column_span(self.first.0, self.last.0, edit).filter(|_| matched) {
            // The calculated formulas stay beside their columns.
            let formulas = table.calculated.len() == table.columns.len();
            if edit.delete {
                if formulas {
                    table.calculated.drain(at.clone());
                }
                deleted = table.columns.drain(at).collect();
            } else {
                let names = free_column_names(&self.columns, edit.count);
                for (offset, name) in names.iter().enumerate() {
                    table.columns.insert(at.start + offset, name.clone());
                    if formulas {
                        table.calculated.insert(at.start + offset, None);
                    }
                }
                inserted = (edit.at..).zip(names).collect();
            }
        }
        Some(XlsxTableShift {
            table,
            deleted,
            inserted,
        })
    }

    /// The row its header is on, when it has one.
    #[must_use]
    pub fn header_row(&self) -> Option<u32> {
        (self.header_rows > 0).then_some(self.first.1)
    }

    /// Whether cell `(col, row)` is inside its range: an unqualified
    /// structured reference there (`[@Price]`) is to this table.
    #[must_use]
    pub fn contains(&self, col: u32, row: u32) -> bool {
        (self.first.0..=self.last.0).contains(&col) && (self.first.1..=self.last.1).contains(&row)
    }
}

/// Where in a table spanning columns `left..=right` a column edit goes in or
/// deletes from, as indices into its columns; `None` when the edit only
/// moves the table or deletes all of it.
pub(super) fn column_span(
    left: u32,
    right: u32,
    edit: &XlsxAxisEdit,
) -> Option<std::ops::Range<usize>> {
    if edit.axis != XlsxAxis::Column {
        return None;
    }
    if edit.delete {
        let (low, high) = (edit.at.max(left), (edit.at + edit.count - 1).min(right));
        if low > high || (low == left && high == right) {
            return None;
        }
        return Some((low - left) as usize..(high - left + 1) as usize);
    }
    if edit.at <= left || edit.at > right {
        return None;
    }
    let at = (edit.at - left) as usize;
    Some(at..at)
}

/// `count` names for new table columns, as Excel gives them: `Column1`,
/// `Column2` and on, past those `taken` (without case).
pub(super) fn free_column_names(taken: &[String], count: u32) -> Vec<String> {
    let mut held: HashSet<String> = taken.iter().map(|name| name.to_lowercase()).collect();
    let mut names = Vec::with_capacity(count as usize);
    let mut n = 0;
    while names.len() < count as usize {
        n += 1;
        let name = format!("Column{n}");
        if held.insert(name.to_lowercase()) {
            names.push(name);
        }
    }
    names
}

/// `formula` after a row or column edit to worksheet `sheet`: its references
/// moved by [`shift_axis`], then its structured references to the columns
/// the edit deleted from a table rewritten as Excel does, a reference to a
/// deleted column reading `#REF!` and a column span shrinking. `dropped`
/// holds each table that lost columns, as it was before the edit, with the
/// names it lost. `own` is the table the formula belongs to (a cell's
/// inside its range, a table part's own), whose columns its unqualified
/// structured references (`[@Price]`) name; a defined name, chart or
/// hyperlink has none. `None` when nothing changed.
#[must_use]
pub fn shift_axis_formula(
    formula: &str,
    home: Option<&str>,
    sheet: &str,
    edit: &XlsxAxisEdit,
    dropped: &[(XlsxTable, Vec<String>)],
    own: Option<&str>,
) -> Option<String> {
    let own = own.map(str::to_lowercase);
    let mut out = shift_axis(formula, home, sheet, edit);
    for (table, deleted) in dropped {
        if let Some(next) = drop_table_columns(
            out.as_deref().unwrap_or(formula),
            &table.name,
            &table.columns,
            deleted,
            own.as_deref() == Some(table.name.to_lowercase().as_str()),
        ) {
            out = Some(next);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxName {
    pub name: String,
    /// The sheet a local name belongs to; `None` for a workbook name.
    pub sheet: Option<String>,
    /// What the name refers to, as a person types it.
    pub formula: String,
    pub hidden: bool,
    pub locked: Option<XlsxLock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxStyle {
    pub num_fmt: u32,
    /// The workbook's own format code; a built-in format id has none.
    pub format: Option<String>,
}

/// One change a body makes to its imported workbook.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum XlsxChange {
    /// The cell's whole new state: a formula is written without a cached
    /// value; a blank cell without a format is removed, unless the stored
    /// cell keeps other markup (an extension, a phonetic flag), which stays.
    Cell {
        sheet: String,
        col: u32,
        row: u32,
        value: XlsxValue,
        formula: Option<String>,
        style: Option<u32>,
    },
    /// Add or replace a defined name.
    SetName {
        name: String,
        sheet: Option<String>,
        formula: String,
        hidden: bool,
    },
    DeleteName {
        name: String,
        sheet: Option<String>,
    },
    /// The worksheets after the body's sheet operations, in workbook order.
    /// An imported worksheet left out is deleted, and the formulas naming it
    /// read `#REF!`; a renamed one's formulas follow it. Written before every
    /// other change, which names sheets as listed here.
    Sheets {
        sheets: Vec<XlsxSheetPlan>,
    },
    /// Insert or delete rows or columns in a worksheet, named as the sheet
    /// layout leaves it. Written in order after the layout and before every
    /// cell and name, which are addressed as the edits leave the sheet.
    Shift {
        sheet: String,
        edit: XlsxAxisEdit,
    },
    /// Cell formats the body composed, written into the stylesheet before
    /// the cells: a cell's `style` of the workbook's format count plus `k`
    /// names the `k`-th. An equal record the stylesheet holds is reused.
    Formats {
        formats: Vec<XlsxFormat>,
    },
    /// Rename column `column` of worksheet table `table` on `sheet` to
    /// `name` (FIX 6399): the table part's `tableColumn` name, and every
    /// structured reference to the column, follow. It pairs with the `Cell`
    /// change writing `name` as text into the column's header cell, the one
    /// table header write a body may make ([`header_rename`]).
    RenameColumn {
        sheet: String,
        table: String,
        column: String,
        name: String,
    },
}

/// One worksheet of a sheet layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxSheetPlan {
    pub name: String,
    /// The imported worksheet it is, by its imported name; `None` for a new,
    /// empty one.
    pub source: Option<String>,
    /// A layout that leaves no sheet visible shows its first worksheet.
    #[serde(default)]
    pub visibility: XlsxSheetVisibility,
}

/// A projected workbook and what the projection adapted on the way, as
/// Excel would (a pivot cache whose source sheet went, a picture its rows
/// collapsed, a note whose cell was deleted), one line each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XlsxProjection {
    pub bytes: Vec<u8>,
    pub effects: Vec<String>,
}

/// Refuse a value or formula Excel cannot hold. A formula is passed without
/// its leading `=`.
pub fn check_cell(value: &XlsxValue, formula: Option<&str>) -> Result<()> {
    if formula.is_some_and(|formula| {
        formula.trim().is_empty()
            || formula.starts_with('=')
            || formula.chars().count() > MAX_FORMULA_CHARS
    }) {
        return Err(refused(
            "a formula is 1 to 8,192 characters, without its `=`",
        ));
    }
    match value {
        XlsxValue::Number(number) if !number.is_finite() => Err(refused("a number must be finite")),
        XlsxValue::Text(text) if text.chars().count() > MAX_TEXT_CHARS => {
            Err(refused("a cell holds at most 32,767 characters"))
        }
        XlsxValue::Error(error) if !ERRORS.contains(&error.as_str()) => {
            Err(refused("an unknown error value"))
        }
        _ => Ok(()),
    }
}

/// Refuse a defined name Excel would not accept or that only Excel writes.
pub fn check_name(name: &str) -> Result<()> {
    let upper = name.to_ascii_uppercase();
    let valid = name
        .chars()
        .next()
        .is_some_and(|first| first.is_alphabetic() || matches!(first, '_' | '\\'))
        && name.chars().count() <= 255
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '\\'))
        && !upper.starts_with("_XLNM.")
        && cell_ref(&upper).is_none()
        && !matches!(upper.as_str(), "R" | "C");
    if !valid {
        return Err(refused("not a valid defined name"));
    }
    Ok(())
}

/// Refuse a worksheet name Excel would not accept: 1 to 31 characters, none
/// of `: \ / ? * [ ]`, no apostrophe at either end, and not `History`, which
/// Excel keeps for itself.
pub fn check_sheet_name(name: &str) -> Result<()> {
    let valid = (1..=MAX_SHEET_NAME).contains(&name.chars().count())
        && !name.contains(&[':', '\\', '/', '?', '*', '[', ']'][..])
        && !name.starts_with('\'')
        && !name.ends_with('\'')
        && !name.chars().any(char::is_control)
        && !name.eq_ignore_ascii_case("history");
    if !valid {
        return Err(refused("not a valid worksheet name"));
    }
    Ok(())
}

/// `B12` → `(2, 12)`; `$` anchors and lower case are accepted.
#[must_use]
pub fn parse_a1(text: &str) -> Option<(u32, u32)> {
    cell_ref(&text.trim().to_ascii_uppercase())
}

#[must_use]
pub fn a1(col: u32, row: u32) -> String {
    let mut letters = Vec::new();
    let mut col = col;
    while col > 0 {
        letters.push(b'A' + ((col - 1) % 26) as u8);
        col = (col - 1) / 26;
    }
    letters.reverse();
    format!("{}{row}", String::from_utf8(letters).unwrap_or_default())
}

/// `$B$12` → `(2, 12)`.
pub(super) fn cell_ref(text: &str) -> Option<(u32, u32)> {
    let text = text.strip_prefix('$').unwrap_or(text);
    let split = text.find(|c: char| !c.is_ascii_uppercase())?;
    let (letters, digits) = text.split_at(split);
    let digits = digits.strip_prefix('$').unwrap_or(digits);
    if letters.is_empty() || letters.len() > 3 || digits.starts_with('0') {
        return None;
    }
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let col = letters
        .bytes()
        .fold(0u32, |sum, byte| sum * 26 + u32::from(byte - b'A' + 1));
    let row = digits.parse::<u32>().ok()?;
    (col <= MAX_COLUMN && (1..=MAX_ROW).contains(&row)).then_some((col, row))
}
