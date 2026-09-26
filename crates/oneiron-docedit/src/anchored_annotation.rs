//! Format-typed office anchors and deterministic locator replay.

use crate::edit_roundtrip::{AnchorEffect, Axis, CellRef, RangeRef, StructuralShift};
use crate::error::{Error, Result};

pub const ANNOTATION_LOCATOR_TEXT_MAX_BYTES: usize = 1024;
pub const ANNOTATION_LOCATOR_RANGE_MAX_BYTES: usize = 64;
pub const FORMAT_XLSX: &str = "xlsx";
pub const FORMAT_DOCX: &str = "docx";
pub const FORMAT_PPTX: &str = "pptx";

fn validate_locator_text(text: &str, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > ANNOTATION_LOCATOR_TEXT_MAX_BYTES {
        return Err(Error::InvalidAnchor(match context {
            "xlsx locator sheet" => "xlsx locator sheet is empty or too long",
            "docx locator para_path" => "docx locator para_path is empty or too long",
            _ => "pptx locator shape_id is empty or too long",
        }));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// A1 ranges + format-typed locators
// ---------------------------------------------------------------------------

/// A rectangular xlsx cell range in 1-based inclusive `(col, row)` coordinates.
///
/// `B2:D5` parses to `{col_start: 2, col_end: 4, row_start: 2, row_end: 5}`;
/// a single cell `B2` parses to a 1x1 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct A1Range {
    /// 1-based inclusive first column.
    pub col_start: u32,
    /// 1-based inclusive last column.
    pub col_end: u32,
    /// 1-based inclusive first row.
    pub row_start: u32,
    /// 1-based inclusive last row.
    pub row_end: u32,
}

impl A1Range {
    /// Builds a range, rejecting non-positive bounds or start > end.
    #[must_use]
    pub fn new(col_start: u32, col_end: u32, row_start: u32, row_end: u32) -> Option<Self> {
        if col_start == 0 || row_start == 0 || col_start > col_end || row_start > row_end {
            return None;
        }
        Some(Self {
            col_start,
            col_end,
            row_start,
            row_end,
        })
    }

    /// Parses an A1 range (`B2:D5`) or single cell (`B2`), normalizing the
    /// corner order so start ≤ end on both axes.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if let Some((lhs, rhs)) = text.split_once(':') {
            let (c1, r1) = parse_a1_cell(lhs.trim())?;
            let (c2, r2) = parse_a1_cell(rhs.trim())?;
            Self::new(c1.min(c2), c1.max(c2), r1.min(r2), r1.max(r2))
        } else {
            let (col, row) = parse_a1_cell(text)?;
            Self::new(col, col, row, row)
        }
    }

    /// Renders the canonical A1 string (`B2` for a 1x1 range, else `B2:D5`).
    #[must_use]
    pub fn to_a1(&self) -> String {
        let start = format!("{}{}", col_to_letters(self.col_start), self.row_start);
        if self.col_start == self.col_end && self.row_start == self.row_end {
            start
        } else {
            format!("{start}:{}{}", col_to_letters(self.col_end), self.row_end)
        }
    }
}

/// A format-typed anchor locator.
///
/// Only the xlsx locator is parsed and re-anchored in P1. The docx and pptx
/// variants are registered locator TYPES (OF-368 D9 P2/P3) so anchors carry
/// them losslessly, but their span parsing and re-anchoring are deferred; a
/// version bump treats a non-xlsx locator as non-mappable (drifted) rather than
/// guessing a new position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locator {
    /// xlsx `{sheet, A1-range}` — IMPLEMENTED.
    Xlsx {
        /// Worksheet name.
        sheet: String,
        /// Cell range.
        range: A1Range,
    },
    /// docx `{para_path, char_span}` — TYPE registered, parsing deferred.
    Docx {
        /// Paragraph path within the document body.
        para_path: String,
        /// Inclusive character-span start.
        char_start: u64,
        /// Exclusive character-span end.
        char_end: u64,
    },
    /// pptx `{slide, shape_id}` — TYPE registered, parsing deferred.
    Pptx {
        /// 1-based slide index.
        slide: u64,
        /// Shape identifier on the slide.
        shape_id: String,
    },
}

impl Locator {
    /// Builds an xlsx locator, validating the sheet name and A1 range.
    pub fn xlsx(sheet: impl Into<String>, range: &str) -> Result<Self> {
        let sheet = sheet.into();
        validate_locator_text(&sheet, "xlsx locator sheet")?;
        if range.len() > ANNOTATION_LOCATOR_RANGE_MAX_BYTES {
            return Err(Error::InvalidAnchor("xlsx locator range is too long"));
        }
        let range =
            A1Range::parse(range).ok_or(Error::InvalidAnchor("xlsx locator range is not A1"))?;
        Ok(Self::Xlsx { sheet, range })
    }

    /// Builds a docx locator (span parsing deferred; bounds validated only).
    pub fn docx(para_path: impl Into<String>, char_start: u64, char_end: u64) -> Result<Self> {
        let para_path = para_path.into();
        validate_locator_text(&para_path, "docx locator para_path")?;
        if char_start > char_end {
            return Err(Error::InvalidAnchor("docx locator char span is inverted"));
        }
        Ok(Self::Docx {
            para_path,
            char_start,
            char_end,
        })
    }

    /// Builds a pptx locator (shape resolution deferred; fields validated only).
    pub fn pptx(slide: u64, shape_id: impl Into<String>) -> Result<Self> {
        let shape_id = shape_id.into();
        validate_locator_text(&shape_id, "pptx locator shape_id")?;
        if slide == 0 {
            return Err(Error::InvalidAnchor("pptx locator slide must be 1-based"));
        }
        Ok(Self::Pptx { slide, shape_id })
    }

    /// The format discriminator string.
    #[must_use]
    pub fn format(&self) -> &'static str {
        match self {
            Self::Xlsx { .. } => FORMAT_XLSX,
            Self::Docx { .. } => FORMAT_DOCX,
            Self::Pptx { .. } => FORMAT_PPTX,
        }
    }
}

// ---------------------------------------------------------------------------
// Re-anchor replay (D2 / D5 hook) — RECONCILIATION SEAM for ARTL-3
// ---------------------------------------------------------------------------

/// A minimal edit operation the re-anchor replay understands.
///
/// # Reconciliation with ARTL-3 (ONE-1553 / ONE-1554)
///
/// The canonical `EditManifest` type belongs to ARTL-3's edit-manifest
/// producer. This enum is deliberately NOT that type: it is the minimal subset
/// re-anchoring needs. ARTL-3 exposes [`crate::edit_roundtrip::AnchorEffect`]
/// as its self-contained reconciliation surface (one per structural op), and
/// ARTL-4 (settle, ONE-1554) lowers a manifest's anchor effects onto these
/// variants through [`From<&crate::edit_roundtrip::AnchorEffect>`], rather than
/// duplicating the manifest shape here. Rows and columns are 1-based; `count`
/// is a positive unit count.
///
/// The row/column/move variants were the original minimal subset; the two
/// sheet-level variants ([`ReanchorOp::RenameSheet`] /
/// [`ReanchorOp::RemoveSheet`]) were added with the ARTL-4 lowering so a
/// manifest that renames or deletes a sheet re-maps or drifts anchors on that
/// sheet rather than silently leaving them pinned to a stale sheet name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReanchorOp {
    /// Insert `count` rows above `at_row` on `sheet`.
    InsertRows {
        /// Target sheet.
        sheet: String,
        /// 1-based row the insertion happens above.
        at_row: u32,
        /// Number of rows inserted.
        count: u32,
    },
    /// Delete `count` rows starting at `at_row` on `sheet`.
    DeleteRows {
        /// Target sheet.
        sheet: String,
        /// 1-based first deleted row.
        at_row: u32,
        /// Number of rows deleted.
        count: u32,
    },
    /// Insert `count` columns left of `at_col` on `sheet`.
    InsertCols {
        /// Target sheet.
        sheet: String,
        /// 1-based column the insertion happens left of.
        at_col: u32,
        /// Number of columns inserted.
        count: u32,
    },
    /// Delete `count` columns starting at `at_col` on `sheet`.
    DeleteCols {
        /// Target sheet.
        sheet: String,
        /// 1-based first deleted column.
        at_col: u32,
        /// Number of columns deleted.
        count: u32,
    },
    /// Move the rectangular `from` range to `to` on `sheet`.
    MoveRange {
        /// Target sheet.
        sheet: String,
        /// Source range.
        from: A1Range,
        /// Destination range (same shape as `from`).
        to: A1Range,
    },
    /// Overwrite the values in `range` on `sheet` (no positional effect).
    WriteCells {
        /// Target sheet.
        sheet: String,
        /// The written range.
        range: A1Range,
    },
    /// Rename `from` to `to`. Anchors on `from` follow to the new sheet name.
    RenameSheet {
        /// The sheet name before the rename (the op's target).
        from: String,
        /// The sheet name after the rename.
        to: String,
    },
    /// Remove `sheet`. Anchors on it are destroyed and drift.
    RemoveSheet {
        /// The removed sheet (the op's target).
        sheet: String,
    },
}

impl ReanchorOp {
    /// The sheet an op targets — the name replay matches against the anchor's
    /// current sheet. For a rename this is the pre-rename (`from`) name.
    pub(super) fn sheet(&self) -> &str {
        match self {
            Self::InsertRows { sheet, .. }
            | Self::DeleteRows { sheet, .. }
            | Self::InsertCols { sheet, .. }
            | Self::DeleteCols { sheet, .. }
            | Self::MoveRange { sheet, .. }
            | Self::WriteCells { sheet, .. }
            | Self::RemoveSheet { sheet } => sheet,
            Self::RenameSheet { from, .. } => from,
        }
    }
}

/// The outcome of replaying an edit manifest against one locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReanchorOutcome {
    /// The anchor mapped to a new locator.
    Mapped(Locator),
    /// The anchor is non-mappable and must be marked drifted.
    Drifted,
}

/// Lowers an ARTL-3 [`AnchorEffect`] — the self-contained reconciliation surface
/// the edit manifest exposes, one per structural op — onto the minimal
/// [`ReanchorOp`] the replay understands (ONE-1554). This is the reconciliation
/// the module docs call for: ARTL-4 (settle) replays a manifest's anchor effects
/// onto the artifact's threads by mapping each through here.
impl From<&AnchorEffect> for ReanchorOp {
    fn from(effect: &AnchorEffect) -> Self {
        match effect {
            AnchorEffect::Shift(shift) => shift_to_reanchor_op(shift),
            AnchorEffect::RangeMoved { sheet, from, to } => Self::MoveRange {
                sheet: sheet.clone(),
                from: range_ref_to_a1(from),
                to: move_dest_to_a1(from, *to),
            },
            AnchorEffect::SheetRenamed { from, to } => Self::RenameSheet {
                from: from.clone(),
                to: to.clone(),
            },
            AnchorEffect::SheetRemoved { name } => Self::RemoveSheet {
                sheet: name.clone(),
            },
        }
    }
}

/// A positive-magnitude row/column shift becomes an insert; a negative one a
/// delete. A zero delta maps to a zero-`count` insert, which the replay skips.
fn shift_to_reanchor_op(shift: &StructuralShift) -> ReanchorOp {
    let sheet = shift.sheet.clone();
    let at = shift.at;
    // Saturate rather than panic on a pathological magnitude; a saturated count
    // that overflows the grid drifts the anchor, the safe outcome.
    let count = u32::try_from(shift.delta.unsigned_abs()).unwrap_or(u32::MAX);
    match (shift.axis, shift.delta >= 0) {
        (Axis::Row, true) => ReanchorOp::InsertRows {
            sheet,
            at_row: at,
            count,
        },
        (Axis::Row, false) => ReanchorOp::DeleteRows {
            sheet,
            at_row: at,
            count,
        },
        (Axis::Column, true) => ReanchorOp::InsertCols {
            sheet,
            at_col: at,
            count,
        },
        (Axis::Column, false) => ReanchorOp::DeleteCols {
            sheet,
            at_col: at,
            count,
        },
    }
}

/// The 1x1 A1 fallback used when a manifest corner is degenerate — unreachable
/// for a validated manifest (ARTL-3 rejects 0-indexed and inverted ranges), but
/// keeps the lowering total and panic-free.
fn a1_unit() -> A1Range {
    A1Range::new(1, 1, 1, 1).expect("A1 is a valid 1x1 range")
}

fn range_ref_to_a1(range: &RangeRef) -> A1Range {
    A1Range::new(
        range.start.col,
        range.end.col,
        range.start.row,
        range.end.row,
    )
    .unwrap_or_else(a1_unit)
}

/// The destination range a move lands on: the source range's shape translated so
/// its top-left corner sits at `to`.
fn move_dest_to_a1(from: &RangeRef, to: CellRef) -> A1Range {
    let width = from.end.col.saturating_sub(from.start.col);
    let height = from.end.row.saturating_sub(from.start.row);
    A1Range::new(
        to.col,
        to.col.saturating_add(width),
        to.row,
        to.row.saturating_add(height),
    )
    .unwrap_or_else(a1_unit)
}

/// Replays a sequence of edit ops against a locator, returning its new position
/// or [`ReanchorOutcome::Drifted`] when the anchored region is destroyed or
/// becomes ambiguous. Ops on a different sheet leave the locator untouched.
///
/// A [`ReanchorOp::RenameSheet`] retargets the locator's sheet name so later
/// ops in the same replay still match it; a [`ReanchorOp::RemoveSheet`] on the
/// anchor's sheet destroys it and drifts, never leaving a thread pinned to a
/// stale sheet name.
///
/// Only xlsx locators are replayed in P1; any other locator format is treated
/// as non-mappable so the thread pins to its origin version rather than being
/// silently repositioned.
#[must_use]
pub fn replay_locator(locator: &Locator, ops: &[ReanchorOp]) -> ReanchorOutcome {
    let Locator::Xlsx { sheet, range } = locator else {
        return ReanchorOutcome::Drifted;
    };
    let mut cur = *range;
    // The anchor's sheet name is mutable across the replay: a rename retargets
    // it so subsequent ops still match, and the final Mapped carries it.
    let mut cur_sheet = sheet.clone();
    for op in ops {
        if op.sheet() != cur_sheet.as_str() {
            continue;
        }
        match op {
            ReanchorOp::InsertRows { at_row, count, .. } => {
                if *count == 0 || *at_row == 0 {
                    continue;
                }
                match axis_insert(cur.row_start, cur.row_end, *at_row, *count) {
                    Some((start, end)) => {
                        cur.row_start = start;
                        cur.row_end = end;
                    }
                    None => return ReanchorOutcome::Drifted,
                }
            }
            ReanchorOp::DeleteRows { at_row, count, .. } => {
                if *count == 0 || *at_row == 0 {
                    continue;
                }
                match axis_delete(cur.row_start, cur.row_end, *at_row, *count) {
                    Some((start, end)) => {
                        cur.row_start = start;
                        cur.row_end = end;
                    }
                    None => return ReanchorOutcome::Drifted,
                }
            }
            ReanchorOp::InsertCols { at_col, count, .. } => {
                if *count == 0 || *at_col == 0 {
                    continue;
                }
                match axis_insert(cur.col_start, cur.col_end, *at_col, *count) {
                    Some((start, end)) => {
                        cur.col_start = start;
                        cur.col_end = end;
                    }
                    None => return ReanchorOutcome::Drifted,
                }
            }
            ReanchorOp::DeleteCols { at_col, count, .. } => {
                if *count == 0 || *at_col == 0 {
                    continue;
                }
                match axis_delete(cur.col_start, cur.col_end, *at_col, *count) {
                    Some((start, end)) => {
                        cur.col_start = start;
                        cur.col_end = end;
                    }
                    None => return ReanchorOutcome::Drifted,
                }
            }
            ReanchorOp::MoveRange { from, to, .. } => {
                if range_contains(from, &cur) {
                    let d_col = i64::from(to.col_start) - i64::from(from.col_start);
                    let d_row = i64::from(to.row_start) - i64::from(from.row_start);
                    match translate(&cur, d_col, d_row) {
                        Some(moved) => cur = moved,
                        None => return ReanchorOutcome::Drifted,
                    }
                } else if ranges_overlap(from, &cur) {
                    // Partial source overlap is ambiguous: never guess a position.
                    return ReanchorOutcome::Drifted;
                } else if ranges_overlap(to, &cur) {
                    // The anchor sits (partly) at the move's DESTINATION but is not
                    // part of the moved content, so that content was overwritten by
                    // the move. Its cells no longer hold what the anchor named — drift
                    // rather than point at replaced content.
                    return ReanchorOutcome::Drifted;
                }
            }
            ReanchorOp::WriteCells { .. } => {}
            ReanchorOp::RenameSheet { to, .. } => {
                cur_sheet = to.clone();
            }
            ReanchorOp::RemoveSheet { .. } => return ReanchorOutcome::Drifted,
        }
    }
    ReanchorOutcome::Mapped(Locator::Xlsx {
        sheet: cur_sheet,
        range: cur,
    })
}

// Axis transforms shared by the row and column cases. Bounds are 1-based.
// Arithmetic is checked: an anchor sitting near `u32::MAX` that a large insert
// (or delete-band) would push past the grid is non-mappable, so these return
// `None` and the caller drifts the thread rather than wrapping (release) or
// panicking (debug) into a corrupt locator.

fn axis_insert(start: u32, end: u32, at: u32, count: u32) -> Option<(u32, u32)> {
    let new_start = if start >= at {
        start.checked_add(count)?
    } else {
        start
    };
    let new_end = if end >= at {
        end.checked_add(count)?
    } else {
        end
    };
    Some((new_start, new_end))
}

fn axis_delete(start: u32, end: u32, at: u32, count: u32) -> Option<(u32, u32)> {
    let del_start = at;
    let del_end = at.checked_add(count)?.checked_sub(1)?;
    let new_start = if start < del_start {
        start
    } else if start > del_end {
        start - count
    } else {
        // Start sits inside the deleted band; it collapses to the band's edge.
        del_start
    };
    let new_end = if end < del_start {
        end
    } else if end > del_end {
        end - count
    } else {
        // End sits inside the deleted band; the last surviving row/col is just
        // before the band. If there is none, the whole region is destroyed.
        del_start.checked_sub(1)?
    };
    if new_start > new_end {
        None
    } else {
        Some((new_start, new_end))
    }
}

fn translate(range: &A1Range, d_col: i64, d_row: i64) -> Option<A1Range> {
    let col_start = u32::try_from(i64::from(range.col_start) + d_col).ok()?;
    let col_end = u32::try_from(i64::from(range.col_end) + d_col).ok()?;
    let row_start = u32::try_from(i64::from(range.row_start) + d_row).ok()?;
    let row_end = u32::try_from(i64::from(range.row_end) + d_row).ok()?;
    A1Range::new(col_start, col_end, row_start, row_end)
}

fn ranges_overlap(a: &A1Range, b: &A1Range) -> bool {
    a.col_start <= b.col_end
        && b.col_start <= a.col_end
        && a.row_start <= b.row_end
        && b.row_start <= a.row_end
}

fn range_contains(outer: &A1Range, inner: &A1Range) -> bool {
    outer.col_start <= inner.col_start
        && inner.col_end <= outer.col_end
        && outer.row_start <= inner.row_start
        && inner.row_end <= outer.row_end
}

pub(super) fn parse_a1_cell(text: &str) -> Option<(u32, u32)> {
    if text.is_empty() {
        return None;
    }
    let split = text.bytes().position(|b| b.is_ascii_digit())?;
    let (letters, digits) = text.split_at(split);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let col = letters_to_col(letters)?;
    let row: u32 = digits.parse().ok()?;
    if row == 0 { None } else { Some((col, row)) }
}

fn letters_to_col(letters: &str) -> Option<u32> {
    if letters.is_empty() {
        return None;
    }
    let mut col: u32 = 0;
    for byte in letters.bytes() {
        if !byte.is_ascii_alphabetic() {
            return None;
        }
        let upper = byte.to_ascii_uppercase();
        col = col
            .checked_mul(26)?
            .checked_add(u32::from(upper - b'A') + 1)?;
    }
    Some(col)
}

pub(super) fn col_to_letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        let rem = (col - 1) % 26;
        out.push(b'A' + u8::try_from(rem).unwrap_or(0));
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_renames_then_shifts_the_same_anchor() {
        let old = Locator::xlsx("Sheet1", "B2:C3").expect("valid locator");
        let ops = [
            ReanchorOp::RenameSheet {
                from: "Sheet1".into(),
                to: "New".into(),
            },
            ReanchorOp::InsertRows {
                sheet: "New".into(),
                at_row: 2,
                count: 2,
            },
        ];
        assert_eq!(
            replay_locator(&old, &ops),
            ReanchorOutcome::Mapped(Locator::xlsx("New", "B4:C5").expect("valid mapped locator"))
        );
    }

    #[test]
    fn destroyed_or_unsupported_location_drifts() {
        let old = Locator::xlsx("Sheet1", "B2").expect("valid locator");
        assert_eq!(
            replay_locator(
                &old,
                &[ReanchorOp::RemoveSheet {
                    sheet: "Sheet1".into()
                }]
            ),
            ReanchorOutcome::Drifted
        );
        assert_eq!(
            replay_locator(&Locator::docx("body/p[1]", 0, 1).expect("valid span"), &[]),
            ReanchorOutcome::Drifted
        );
    }
}
