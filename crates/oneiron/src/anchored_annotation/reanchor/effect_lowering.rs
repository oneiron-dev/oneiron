//! Lowering of edit-manifest anchor effects onto the replay's reanchor ops.

use super::*;

/// Lowers an ARTL-3 [`AnchorEffect`] — the self-contained reconciliation surface
/// the edit manifest exposes, one per structural op — onto the minimal
/// [`ReanchorOp`] the replay understands (ONE-1554). This is the reconciliation
/// the module docs call for: ARTL-4 (settle) replays a manifest's anchor effects
/// onto the artifact's threads by mapping each through here.
impl From<&AnchorEffect> for ReanchorOp {
    fn from(effect: &AnchorEffect) -> Self {
        match effect {
            AnchorEffect::PptxSlideCreationId { slide, creation_id } => Self::PptxSlideCreationId {
                slide: *slide,
                creation_id: *creation_id,
            },
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
