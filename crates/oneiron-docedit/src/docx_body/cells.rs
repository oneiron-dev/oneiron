//! Per-paragraph cell text, separate from the flat current-redline cell read.

use super::{DocxCell, DocxCellParagraph, DocxLock};
use crate::DoceditError;
use stemma::domain::{BlockNode, InlineNode, TrackedBlock, TrackingStatus, VerticalMerge};
use stemma::view::BlockView;

pub(super) fn read(
    view: &BlockView,
    blocks: &[TrackedBlock],
    comment: bool,
) -> Result<Vec<DocxCell>, DoceditError> {
    if view.cells.is_empty() {
        return Ok(Vec::new());
    }
    let table = blocks
        .iter()
        .find_map(|block| match &block.block {
            BlockNode::Table(table) if table.id.to_string() == view.id.to_string() => Some(table),
            _ => None,
        })
        .ok_or_else(|| invalid("table"))?;
    view.cells
        .iter()
        .map(|view_cell| {
            let row = table
                .rows
                .get(view_cell.row)
                .ok_or_else(|| invalid("row"))?;
            let mut col = row.grid_before as usize;
            let cell = row
                .cells
                .iter()
                .find(|cell| {
                    let at = col;
                    col += cell.grid_span.max(1) as usize;
                    at == view_cell.col
                })
                .ok_or_else(|| invalid("cell"))?;
            let structural = cell.v_merge == VerticalMerge::Continue
                || cell
                    .tracking_status
                    .as_ref()
                    .or(row.tracking_status.as_ref())
                    .is_some();
            let paragraphs = cell
                .blocks
                .iter()
                .filter_map(|block| match block {
                    BlockNode::Paragraph(paragraph) => Some(paragraph),
                    _ => None,
                })
                .map(|paragraph| {
                    // The native cell materializer diffs against accept-all, not the
                    // joined redline read (which includes Deleted tombstones).
                    let text = current_text(paragraph);
                    let locked = if structural
                        || paragraph
                            .para_mark_status
                            .as_ref()
                            .is_some_and(|status| status != &TrackingStatus::Normal)
                        || (comment
                            && paragraph
                                .segments
                                .iter()
                                .any(|segment| segment.status != TrackingStatus::Normal))
                    {
                        Some(DocxLock::Tracked)
                    } else if !paragraph.has_resolved_numbering()
                        && paragraph
                            .literal_prefix
                            .as_deref()
                            .is_some_and(|label| !label.trim().is_empty())
                    {
                        Some(DocxLock::LiteralPrefix)
                    } else if paragraph
                        .segments
                        .iter()
                        .flat_map(|segment| &segment.inlines)
                        .any(|inline| !matches!(inline, InlineNode::Text(_)))
                    {
                        Some(DocxLock::Anchors)
                    } else {
                        None
                    };
                    DocxCellParagraph {
                        id: paragraph.id.to_string(),
                        guard: stemma::semantic_hash::block_semantic_hash_for_paragraph(paragraph),
                        text,
                        locked,
                    }
                })
                .collect();
            Ok(DocxCell {
                row: view_cell.row,
                col: view_cell.col,
                text: view_cell.text.clone(),
                paragraphs,
            })
        })
        .collect()
}

/// Current direct cell paragraphs in native story-local identity space.
pub(super) fn anchor_blocks(blocks: &[TrackedBlock]) -> Vec<crate::DocxAnchorBlock> {
    let mut anchors = Vec::new();
    for tracked in blocks {
        if !current(&tracked.status) {
            continue;
        }
        let BlockNode::Table(table) = &tracked.block else {
            continue;
        };
        for row in &table.rows {
            if row
                .tracking_status
                .as_ref()
                .is_some_and(|status| !current(status))
            {
                continue;
            }
            for cell in &row.cells {
                if cell.v_merge == VerticalMerge::Continue
                    || cell
                        .tracking_status
                        .as_ref()
                        .is_some_and(|status| !current(status))
                {
                    continue;
                }
                for block in &cell.blocks {
                    if let BlockNode::Paragraph(paragraph) = block {
                        anchors.push(crate::DocxAnchorBlock {
                            block_id: paragraph.id.to_string(),
                            para_id: paragraph.para_id.clone(),
                            text: current_text(paragraph),
                        });
                    }
                }
            }
        }
    }
    anchors
}

fn current(status: &TrackingStatus) -> bool {
    matches!(status, TrackingStatus::Normal | TrackingStatus::Inserted(_))
}

fn current_text(paragraph: &stemma::domain::ParagraphNode) -> String {
    paragraph
        .segments
        .iter()
        .filter(|segment| current(&segment.status))
        .flat_map(|segment| &segment.inlines)
        .filter_map(|inline| match inline {
            InlineNode::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect()
}

fn invalid(part: &str) -> DoceditError {
    DoceditError::InvalidTransaction(format!("native table read lost its source {part}"))
}
