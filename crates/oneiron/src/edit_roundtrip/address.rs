//! Cell addressing, ranges and op validation.

use super::EditOp;
use crate::error::{ArtifactError, Error, Result};

pub(super) use crate::blob_artifact::office_address::column_to_letters;
pub use crate::blob_artifact::office_address::{Axis, CellRef, OfficeFormat, RangeRef};

/// Enforces the 1-based cell/range/axis invariant across a plan's ops before
/// any of them reaches a session or the renderer. [`CellRef::new`] and
/// [`RangeRef::new`] are unchecked constructors, so a caller can build an op
/// addressing column/row 0 or an inverted range; such an op names a
/// non-existent cell and would render a bogus address, so it is rejected as an
/// invalid manifest here rather than acted on.
pub(super) fn validate_ops(ops: &[EditOp]) -> Result<()> {
    for op in ops {
        match op {
            EditOp::PptxComment { .. }
            | EditOp::MintPptxSlideCreationId { .. }
            | EditOp::DeckTransaction { .. } => {
                return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                    "PowerPoint operations require the comment pipeline",
                )));
            }
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
            EditOp::DocxRevision { .. }
            | EditOp::AddSheet { .. }
            | EditOp::RemoveSheet { .. }
            | EditOp::RenameSheet { .. } => {}
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
        return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
            "edit op range is inverted; start must be at or above-left of end",
        )));
    }
    Ok(())
}

fn ensure_one_based(index: u32) -> Result<()> {
    if index == 0 {
        return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
            "edit op uses a 0 index; cells, ranges, and axis positions are 1-based",
        )));
    }
    Ok(())
}
