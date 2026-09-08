//! Cell addressing, ranges and op validation.

use super::EditOp;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

const XLSX_MEDIA_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

const XLSM_MEDIA_TYPE: &str = "application/vnd.ms-excel.sheet.macroEnabled.12";

const DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

const PPTX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.presentation";

/// Office Open XML family the pipeline operates on. P1 is xlsx; docx/pptx are
/// staged (D9) and already addressable so the manifest is format-stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeFormat {
    Xlsx,
    Docx,
    Pptx,
}

impl OfficeFormat {
    /// Maps an artifact media type to its format, erroring on anything the
    /// pipeline does not yet handle.
    pub fn from_media_type(media_type: &str) -> Result<Self> {
        match media_type {
            XLSX_MEDIA_TYPE | XLSM_MEDIA_TYPE => Ok(Self::Xlsx),
            DOCX_MEDIA_TYPE => Ok(Self::Docx),
            PPTX_MEDIA_TYPE => Ok(Self::Pptx),
            _ => Err(Error::EditRoundtripFailed(
                "media type is not a supported office format",
            )),
        }
    }

    /// The required "spine" part whose absence in an output means the package
    /// was gutted.
    #[must_use]
    pub const fn spine_part(self) -> &'static str {
        match self {
            Self::Xlsx => "xl/workbook.xml",
            Self::Docx => "word/document.xml",
            Self::Pptx => "ppt/presentation.xml",
        }
    }
}

/// The axis a structural op operates on, for anchor re-mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    Row,
    Column,
}

/// A single cell address, 1-based on both axes (A1 == col 1, row 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellRef {
    pub col: u32,
    pub row: u32,
}

impl CellRef {
    #[must_use]
    pub const fn new(col: u32, row: u32) -> Self {
        Self { col, row }
    }

    /// Parses an A1-style reference such as `"AB12"`.
    pub fn parse(text: &str) -> Result<Self> {
        let split = text
            .find(|c: char| c.is_ascii_digit())
            .ok_or(Error::EditRoundtripFailed("cell reference missing a row"))?;
        if split == 0 {
            return Err(Error::EditRoundtripFailed(
                "cell reference missing a column",
            ));
        }
        let (letters, digits) = text.split_at(split);
        let col = letters_to_column(letters)?;
        let row: u32 = digits
            .parse()
            .map_err(|_| Error::EditRoundtripFailed("cell reference row is not a number"))?;
        if row == 0 {
            return Err(Error::EditRoundtripFailed(
                "cell reference row must be >= 1",
            ));
        }
        Ok(Self { col, row })
    }

    /// Renders the reference in A1 notation.
    #[must_use]
    pub fn to_a1(self) -> String {
        format!("{}{}", column_to_letters(self.col), self.row)
    }
}

/// A rectangular range, inclusive of both corners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeRef {
    pub start: CellRef,
    pub end: CellRef,
}

impl RangeRef {
    #[must_use]
    pub const fn new(start: CellRef, end: CellRef) -> Self {
        Self { start, end }
    }

    /// Parses an `"A1:B2"` range.
    pub fn parse(text: &str) -> Result<Self> {
        let (start, end) = text
            .split_once(':')
            .ok_or(Error::EditRoundtripFailed("range reference missing ':'"))?;
        Ok(Self {
            start: CellRef::parse(start)?,
            end: CellRef::parse(end)?,
        })
    }

    /// Renders the range in A1 notation.
    #[must_use]
    pub fn to_a1(self) -> String {
        format!("{}:{}", self.start.to_a1(), self.end.to_a1())
    }
}

pub(super) fn column_to_letters(mut index: u32) -> String {
    // `index` is a validated 1-based column (see `validate_ops`), so 0 never
    // reaches the renderer and no placeholder is emitted.
    debug_assert!(index >= 1, "column index must be 1-based");
    let mut letters = Vec::new();
    while index > 0 {
        let rem = ((index - 1) % 26) as u8;
        letters.push((b'A' + rem) as char);
        index = (index - 1) / 26;
    }
    letters.iter().rev().collect()
}

fn letters_to_column(letters: &str) -> Result<u32> {
    if letters.is_empty() {
        return Err(Error::EditRoundtripFailed("column reference is empty"));
    }
    let mut col: u32 = 0;
    for ch in letters.chars() {
        if !ch.is_ascii_alphabetic() {
            return Err(Error::EditRoundtripFailed(
                "column reference has a non-letter",
            ));
        }
        let value = u32::from(ch.to_ascii_uppercase() as u8 - b'A') + 1;
        col = col
            .checked_mul(26)
            .and_then(|c| c.checked_add(value))
            .ok_or(Error::EditRoundtripFailed("column reference overflow"))?;
    }
    Ok(col)
}

/// Enforces the 1-based cell/range/axis invariant across a plan's ops before
/// any of them reaches a session or the renderer. [`CellRef::new`] and
/// [`RangeRef::new`] are unchecked constructors, so a caller can build an op
/// addressing column/row 0 or an inverted range; such an op names a
/// non-existent cell and would render a bogus address, so it is rejected as an
/// invalid manifest here rather than acted on.
pub(super) fn validate_ops(ops: &[EditOp]) -> Result<()> {
    for op in ops {
        match op {
            EditOp::SetCell { cell, .. } => check_cell(*cell)?,
            EditOp::SetRange { range, writes, .. } => {
                check_range(*range)?;
                for write in writes {
                    check_cell(write.cell)?;
                }
            }
            EditOp::AddFormulaColumn { column, .. } => ensure_one_based(*column)?,
            EditOp::InsertRows { at, .. }
            | EditOp::DeleteRows { at, .. }
            | EditOp::InsertColumns { at, .. }
            | EditOp::DeleteColumns { at, .. } => ensure_one_based(*at)?,
            EditOp::MoveRange { from, to, .. } => {
                check_range(*from)?;
                check_cell(*to)?;
            }
            EditOp::AddSheet { .. } | EditOp::RemoveSheet { .. } | EditOp::RenameSheet { .. } => {}
        }
    }
    Ok(())
}

fn check_cell(cell: CellRef) -> Result<()> {
    ensure_one_based(cell.col)?;
    ensure_one_based(cell.row)
}

fn check_range(range: RangeRef) -> Result<()> {
    check_cell(range.start)?;
    check_cell(range.end)?;
    if range.start.col > range.end.col || range.start.row > range.end.row {
        return Err(Error::InvalidEditManifest(
            "edit op range is inverted; start must be at or above-left of end",
        ));
    }
    Ok(())
}

fn ensure_one_based(index: u32) -> Result<()> {
    if index == 0 {
        return Err(Error::InvalidEditManifest(
            "edit op uses a 0 index; cells, ranges, and axis positions are 1-based",
        ));
    }
    Ok(())
}
