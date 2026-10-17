//! What an anchor says: the text under a locator in one version's bytes, the
//! exact places those words occur in another version, and how a Word span
//! moves across an edit (OF-368, owner ruling 2026-10-17).
//!
//! An edit inside the commented spot keeps the anchor; only deleting the spot
//! detaches it, and a partial delete shrinks the anchor to what remains. A
//! detached comment keeps a snapshot of its text, so a person can be offered
//! the exact words when they return; nothing here reattaches on a guess.

use std::collections::BTreeMap;

use oneiron_docedit::retained_opc::{Limits, Package};
use oneiron_docedit::xlsx_body::read_xlsx_cells;
use oneiron_xlsx_formula::cell_display_text;

use super::model::{A1Range, Locator};
use crate::edit_roundtrip::{CellRef, OfficeFormat};

/// Cells joined in a range snapshot: across a row, then down rows.
const CELL_SEPARATOR: char = '\t';
const ROW_SEPARATOR: char = '\n';
/// Paragraphs joined in a shape's text.
const PARAGRAPH_SEPARATOR: char = '\n';
/// The most places one reattach offer lists.
pub(super) const MAX_OFFERS: usize = 16;

/// The format readers' ceilings, resolved once per sweep from live policy.
#[derive(Clone)]
pub(super) struct TextLimits {
    pub(super) package: Limits,
    pub(super) docx: oneiron_docedit::ArchiveLimits,
}

/// The text under `locator` in `bytes`, or `None` when the spot cannot be read.
pub(super) fn anchor_text(bytes: &[u8], locator: &Locator, limits: &TextLimits) -> Option<String> {
    match locator {
        Locator::Xlsx { sheet, range } => xlsx_range_text(bytes, sheet, *range, limits),
        Locator::Docx {
            para_path,
            char_start,
            char_end,
        } => {
            let blocks = docx_blocks(bytes, limits)?;
            let (_, text) = blocks.iter().find(|(id, _)| id == para_path)?;
            char_slice(text, *char_start, *char_end)
        }
        Locator::Pptx { slide, shape_id } => {
            let deck = deck_view(bytes, limits)?;
            let slide = deck
                .slides
                .get(usize::try_from(*slide).ok()?.checked_sub(1)?)?;
            if shape_id == "slide" {
                let texts: Vec<String> = slide.shapes.iter().filter_map(shape_text).collect();
                return (!texts.is_empty()).then(|| texts.join(&PARAGRAPH_SEPARATOR.to_string()));
            }
            let wanted = guid_key(shape_id);
            let mut matches = slide.shapes.iter().filter(|shape| {
                shape
                    .creation_id
                    .as_deref()
                    .is_some_and(|guid| guid_key(guid) == wanted)
                    || shape.id.is_some_and(|id| id.to_string() == *shape_id)
            });
            let shape = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            shape_text(shape)
        }
        _ => None,
    }
}

/// Every place in `bytes` that holds exactly `text`, in document order. A
/// sheet offers same-shaped ranges, a Word document every exact run of the
/// words, a deck every shape whose whole text is the words.
pub(super) fn find_text(
    bytes: &[u8],
    format: OfficeFormat,
    text: &str,
    limits: &TextLimits,
) -> Vec<Locator> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let mut found = match format {
        OfficeFormat::Xlsx => find_in_sheets(bytes, text, limits),
        OfficeFormat::Docx => docx_blocks(bytes, limits)
            .map(|blocks| {
                blocks
                    .iter()
                    .flat_map(|(id, block)| {
                        char_occurrences(block, text)
                            .into_iter()
                            .filter_map(|(start, end)| Locator::docx(id.clone(), start, end).ok())
                    })
                    .collect()
            })
            .unwrap_or_default(),
        OfficeFormat::Pptx => deck_view(bytes, limits)
            .map(|deck| {
                deck.slides
                    .iter()
                    .enumerate()
                    .flat_map(|(index, slide)| {
                        slide.shapes.iter().filter_map(move |shape| {
                            let identity = shape
                                .creation_id
                                .clone()
                                .or_else(|| shape.id.map(|id| id.to_string()))?;
                            (shape_text(shape).as_deref() == Some(text)).then(|| {
                                Locator::pptx(u64::try_from(index).ok()? + 1, identity).ok()
                            })?
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    found.truncate(MAX_OFFERS);
    found
}

/// Moves a Word span across one paragraph's edit. The text both sides share
/// at the start and end is untouched; a boundary inside the changed stretch
/// moves to its edge. An edit inside the span keeps it, a deletion of the
/// whole span detaches it (`None`), a partial delete shrinks it.
pub(super) fn remap_span(before: &str, after: &str, start: u64, end: u64) -> Option<(u64, u64)> {
    let before: Vec<char> = before.chars().collect();
    let after: Vec<char> = after.chars().collect();
    let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
    if start >= end || end > before.len() {
        return None;
    }
    let shared = before.len().min(after.len());
    let prefix = before
        .iter()
        .zip(&after)
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = before
        .iter()
        .rev()
        .zip(after.iter().rev())
        .take(shared - prefix)
        .take_while(|(a, b)| a == b)
        .count();
    let before_end = before.len() - suffix;
    let after_end = after.len() - suffix;
    let map = |at: usize, inside: usize| {
        if at <= prefix {
            at
        } else if at >= before_end {
            at - before_end + after_end
        } else {
            inside
        }
    };
    let (new_start, new_end) = (map(start, prefix), map(end, after_end));
    (new_start < new_end).then(|| (new_start as u64, new_end as u64))
}

/// The body paragraphs of a Word document: block id and visible text.
pub(super) fn docx_blocks(bytes: &[u8], limits: &TextLimits) -> Option<Vec<(String, String)>> {
    oneiron_docedit::preflight_with_limits(bytes, limits.docx).ok()?;
    let document = oneiron_docedit::Document::parse(bytes).ok()?;
    Some(
        document
            .read()
            .blocks
            .into_iter()
            .map(|block| (block.id.to_string(), block.text))
            .collect(),
    )
}

fn deck_view(bytes: &[u8], limits: &TextLimits) -> Option<oneiron_docedit::deck::DeckView> {
    let package = Package::open(bytes, limits.package).ok()?;
    oneiron_docedit::deck::DeckView::read(&package).ok()
}

fn shape_text(shape: &oneiron_docedit::deck::ShapeView) -> Option<String> {
    let text = shape.text.as_ref()?;
    let paragraphs: Vec<String> = text
        .paragraphs
        .iter()
        .map(|paragraph| paragraph.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    let joined = paragraphs.join(&PARAGRAPH_SEPARATOR.to_string());
    (!joined.trim().is_empty()).then_some(joined)
}

fn guid_key(text: &str) -> String {
    text.trim_matches(|c| c == '{' || c == '}')
        .to_ascii_uppercase()
}

fn char_slice(text: &str, start: u64, end: u64) -> Option<String> {
    let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
    let chars: Vec<char> = text.chars().collect();
    (start < end && end <= chars.len()).then(|| chars[start..end].iter().collect())
}

/// Every non-overlapping exact occurrence of `needle`, in characters.
fn char_occurrences(haystack: &str, needle: &str) -> Vec<(u64, u64)> {
    let len = needle.chars().count() as u64;
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(found) = haystack[from..].find(needle) {
        let byte = from + found;
        let start = haystack[..byte].chars().count() as u64;
        out.push((start, start + len));
        from = byte + needle.len().max(1);
        if out.len() >= MAX_OFFERS {
            break;
        }
    }
    out
}

/// Each sheet's cells that `wanted` picks, as a person sees them (a
/// formula's saved result under the cell's number format), in workbook
/// order. The workbook is read under the live package ceilings.
fn sheet_texts(
    bytes: &[u8],
    limits: &TextLimits,
    wanted: &dyn Fn(&str, &CellRef) -> bool,
) -> Option<Vec<(String, BTreeMap<CellRef, String>)>> {
    let book = read_xlsx_cells(bytes, limits.package).ok()?;
    Some(
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
    )
}

fn xlsx_range_text(
    bytes: &[u8],
    sheet: &str,
    range: A1Range,
    limits: &TextLimits,
) -> Option<String> {
    let (_, cells) = sheet_texts(bytes, limits, &|name, cell| {
        name == sheet && in_range(cell, range)
    })?
    .into_iter()
    .find(|(name, _)| name == sheet)?;
    let rows: Vec<String> = (range.row_start..=range.row_end)
        .map(|row| {
            (range.col_start..=range.col_end)
                .map(|col| {
                    cells
                        .get(&CellRef { col, row })
                        .cloned()
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join(&CELL_SEPARATOR.to_string())
        })
        .collect();
    let text = rows.join(&ROW_SEPARATOR.to_string());
    (!text.trim().is_empty()).then_some(text)
}

fn in_range(cell: &CellRef, range: A1Range) -> bool {
    (range.col_start..=range.col_end).contains(&cell.col)
        && (range.row_start..=range.row_end).contains(&cell.row)
}

/// Same-shaped ranges whose cells read exactly as the snapshot.
fn find_in_sheets(bytes: &[u8], text: &str, limits: &TextLimits) -> Vec<Locator> {
    let rows: Vec<Vec<&str>> = text
        .split(ROW_SEPARATOR)
        .map(|row| row.split(CELL_SEPARATOR).collect())
        .collect();
    let height = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    let width = u32::try_from(rows.first().map_or(0, Vec::len)).unwrap_or(u32::MAX);
    if height == 0 || width == 0 || rows.iter().any(|row| row.len() != width as usize) {
        return Vec::new();
    }
    let Some(sheets) = sheet_texts(bytes, limits, &|_, _| true) else {
        return Vec::new();
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
                    return out;
                }
            }
        }
    }
    out
}
