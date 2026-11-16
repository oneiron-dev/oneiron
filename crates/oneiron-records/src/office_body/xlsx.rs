//! Moved from `crates/oneiron/src/office_body/xlsx.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_docedit::xlsx_body::XlsxArea;
use oneiron_docedit::xlsx_body::XlsxAxisEdit;
use oneiron_docedit::xlsx_body::XlsxConditionalFormat;
use oneiron_docedit::xlsx_body::XlsxFormat;
use oneiron_docedit::xlsx_body::XlsxLines;
use oneiron_docedit::xlsx_body::XlsxLock;
use oneiron_docedit::xlsx_body::XlsxSheetVisibility;
use oneiron_docedit::xlsx_body::XlsxStyle;
use oneiron_docedit::xlsx_body::XlsxTable;
use oneiron_docedit::xlsx_body::XlsxValue;
pub use oneiron_verb_wire::office_body::xlsx::XlsxBodyOp;
use std::collections::BTreeMap;

/// A typed read of the body at one frontier.
#[derive(Debug, Clone, PartialEq)]
pub struct XlsxBody {
    pub date1904: bool,
    pub sheets: Vec<BodySheet>,
    /// Defined names by key: the sheet's key and the name in lower case,
    /// `key!name`, the key empty for a workbook name.
    pub names: BTreeMap<String, BodyName>,
    /// The workbook's cell formats, by index.
    pub styles: Vec<XlsxStyle>,
    /// The row and column inserts and deletes since import, in order, by
    /// sheet key.
    pub axes: Vec<(String, XlsxAxisEdit)>,
    /// The cell formats the body composed, by id; each is immutable.
    pub formats: BTreeMap<String, XlsxFormat>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BodySheet {
    /// The sheet's key in the body: its imported name, or one minted when the
    /// body added it. A rename keeps it.
    pub key: String,
    pub name: String,
    /// `(row, col)` to cell, in row-major order.
    pub cells: BTreeMap<(u32, u32), BodyCell>,
    /// Ranges no operation writes.
    pub locked: Vec<XlsxArea>,
    pub tables: Vec<XlsxTable>,
    pub visibility: XlsxSheetVisibility,
    /// The conditional formats the body added, by id (FIX 3468).
    pub conditional: BTreeMap<String, XlsxConditionalFormat>,
    /// The rows with their own height or format, and the column ranges with
    /// their own width or format, as the row and column log leaves them
    /// (FIX 9081).
    pub rows: Vec<XlsxLines>,
    pub columns: Vec<XlsxLines>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BodyCell {
    pub address: String,
    /// A formula cell's value is its last computed result: the import's cache,
    /// blank once the formula is rewritten. A preview or export recomputes it.
    pub value: XlsxValue,
    pub formula: Option<String>,
    pub style: Option<u32>,
    /// A cell format the body composed, by id, in place of `style`.
    pub format: Option<String>,
    pub locked: Option<XlsxLock>,
}

/// A cell format the body composed, by its id.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BodyFormat {
    pub id: String,
    pub format: XlsxFormat,
}

/// A conditional format the body added to a sheet, by its id.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BodyConditionalFormat {
    pub id: String,
    pub format: XlsxConditionalFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BodyName {
    pub name: String,
    pub sheet: Option<String>,
    pub formula: String,
    pub hidden: bool,
    pub locked: Option<XlsxLock>,
}
