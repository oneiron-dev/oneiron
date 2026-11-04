//! XLSX annotation text and exact range offers.

use std::{collections::BTreeMap, io};

use oneiron_docedit::resource::Resources;
use oneiron_docedit::xlsx_body::read_xlsx_cells;
use oneiron_xlsx_formula::cell_display_text;

use super::super::model::{A1Range, Locator};
use super::{MAX_OFFERS, TextLimits};
use crate::edit_roundtrip::CellRef;

/// Cells joined in a range snapshot: across a row, then down rows.
const CELL_SEPARATOR: char = '\t';
const ROW_SEPARATOR: char = '\n';

/// Each sheet's cells that `wanted` picks, as a person sees them (a
/// formula's saved result under the cell's number format), in workbook
/// order. The workbook is read under the live package ceilings. A resource
/// refusal is the engine's error (FIX 10587), never `None`.
fn sheet_texts(
    bytes: &[u8],
    limits: &TextLimits,
    resources: &Resources,
    wanted: &dyn Fn(&str, &CellRef) -> bool,
) -> crate::Result<Option<Vec<(String, BTreeMap<CellRef, String>)>>> {
    let book = match read_xlsx_cells(bytes, limits.package, resources) {
        Ok(book) => book,
        Err(error) => {
            if let Some(refusal) = error.resource() {
                return Err(crate::office_body::document_refused(refusal));
            }
            return Ok(None);
        }
    };
    Ok(Some(
        book.sheets
            .iter()
            .map(|sheet| {
                let cells = sheet
                    .cells
                    .iter()
                    .map(|cell| {
                        let at = CellRef {
                            col: cell.col,
                            row: cell.row,
                        };
                        (at, cell)
                    })
                    .filter(|(at, _)| wanted(sheet.name.as_str(), at))
                    .map(|(at, cell)| (at, cell_display_text(&book, cell)))
                    .collect();
                (sheet.name.clone(), cells)
            })
            .collect(),
    ))
}

pub(super) fn xlsx_range_text(
    bytes: &[u8],
    sheet: &str,
    range: A1Range,
    limits: &TextLimits,
) -> crate::Result<Option<String>> {
    let resources = crate::office_body::document_resources();
    let Some(sheets) = sheet_texts(bytes, limits, &resources, &|name, cell| {
        name == sheet && in_range(cell, range)
    })?
    else {
        return Ok(None);
    };
    let Some((_, cells)) = sheets.into_iter().find(|(name, _)| name == sheet) else {
        return Ok(None);
    };
    if cells.values().all(|text| text.trim().is_empty()) {
        return Ok(None);
    }
    let (Some(width), Some(height)) = (
        range.col_end.checked_sub(range.col_start),
        range.row_end.checked_sub(range.row_start),
    ) else {
        return Ok(None);
    };
    let (width, height) = (u128::from(width) + 1, u128::from(height) + 1);
    let text_bytes = (width - 1) * height * CELL_SEPARATOR.len_utf8() as u128
        + (height - 1) * ROW_SEPARATOR.len_utf8() as u128
        + cells.values().map(|text| text.len() as u128).sum::<u128>();
    let _room = resources
        .reserve(u64::try_from(text_bytes).unwrap_or(u64::MAX))
        .map_err(crate::office_body::document_refused)?;
    let capacity = usize::try_from(text_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "annotation snapshot exceeds addressable memory",
        )
    })?;
    let mut text = String::new();
    text.try_reserve_exact(capacity)
        .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
    for row in range.row_start..=range.row_end {
        resources
            .checkpoint()
            .map_err(crate::office_body::document_refused)?;
        if row != range.row_start {
            text.push(ROW_SEPARATOR);
        }
        for col in range.col_start..=range.col_end {
            if col != range.col_start {
                text.push(CELL_SEPARATOR);
            }
            if let Some(value) = cells.get(&CellRef { col, row }) {
                text.push_str(value);
            }
        }
    }
    Ok((!text.trim().is_empty()).then_some(text))
}

fn in_range(cell: &CellRef, range: A1Range) -> bool {
    (range.col_start..=range.col_end).contains(&cell.col)
        && (range.row_start..=range.row_end).contains(&cell.row)
}

/// Same-shaped ranges whose cells read exactly as the snapshot. A resource
/// refusal is the engine's error (FIX 10587), never an empty offer list.
pub(super) fn find_in_sheets(
    bytes: &[u8],
    text: &str,
    limits: &TextLimits,
) -> crate::Result<Vec<Locator>> {
    let rows: Vec<Vec<&str>> = text
        .split(ROW_SEPARATOR)
        .map(|row| row.split(CELL_SEPARATOR).collect())
        .collect();
    let height = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    let width = u32::try_from(rows.first().map_or(0, Vec::len)).unwrap_or(u32::MAX);
    if height == 0 || width == 0 || rows.iter().any(|row| row.len() != width as usize) {
        return Ok(Vec::new());
    }
    let resources = crate::office_body::document_resources();
    let Some(sheets) = sheet_texts(bytes, limits, &resources, &|_, _| true)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (sheet, cells) in sheets {
        for (corner, value) in &cells {
            if value != rows[0][0] {
                continue;
            }
            let matches = (0..height).all(|dy| {
                (0..width).all(|dx| {
                    let cell = CellRef {
                        col: corner.col + dx,
                        row: corner.row + dy,
                    };
                    cells.get(&cell).map(String::as_str).unwrap_or_default()
                        == rows[dy as usize][dx as usize]
                })
            });
            if !matches {
                continue;
            }
            if let Some(range) = A1Range::new(
                corner.col,
                corner.col + width - 1,
                corner.row,
                corner.row + height - 1,
            ) {
                out.push(Locator::Xlsx {
                    sheet: sheet.clone(),
                    range,
                });
                if out.len() >= MAX_OFFERS {
                    return Ok(out);
                }
            }
        }
    }
    Ok(out)
}
