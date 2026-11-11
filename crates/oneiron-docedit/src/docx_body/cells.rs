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
    read_table(view, table, false, comment)
}

fn read_table(
    view: &BlockView,
    table: &stemma::domain::TableNode,
    ancestor_locked: bool,
    comment: bool,
) -> Result<Vec<DocxCell>, DoceditError> {
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
            let structural = ancestor_locked
                || cell.v_merge == VerticalMerge::Continue
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
                .map(|paragraph| read_paragraph(paragraph, structural, comment))
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

/// Actual nested tables, after every existing top-level story block.
pub(super) fn descendant_table_blocks(
    blocks: &[TrackedBlock],
    comment: bool,
) -> Result<Vec<super::DocxBlock>, DoceditError> {
    let mut tables = Vec::new();
    for tracked in blocks {
        if let BlockNode::Table(table) = &tracked.block {
            append_descendant_tables(
                table,
                tracked.status != TrackingStatus::Normal,
                comment,
                &mut tables,
            )?;
        }
    }
    Ok(tables)
}

fn append_descendant_tables(
    table: &stemma::domain::TableNode,
    ancestor_locked: bool,
    comment: bool,
    tables: &mut Vec<super::DocxBlock>,
) -> Result<(), DoceditError> {
    for row in &table.rows {
        for cell in &row.cells {
            let structural = ancestor_locked
                || cell.v_merge == VerticalMerge::Continue
                || cell
                    .tracking_status
                    .as_ref()
                    .or(row.tracking_status.as_ref())
                    .is_some();
            for block in &cell.blocks {
                if let BlockNode::Table(nested) = block {
                    let view = stemma::view::build_story_block_view(block, &TrackingStatus::Normal);
                    tables.push(super::DocxBlock {
                        id: view.id.to_string(),
                        kind: super::DocxBlockKind::Table,
                        role: None,
                        text: String::new(),
                        runs: Vec::new(),
                        cells: read_table(&view, nested, structural, comment)?,
                        locked: structural.then_some(DocxLock::Tracked),
                    });
                    append_descendant_tables(nested, structural, comment, tables)?;
                }
            }
        }
    }
    Ok(())
}

/// Find only an actual nested table; callers retain top-level lookup priority.
pub(super) fn descendant_table<'a>(blocks: &'a [TrackedBlock], id: &str) -> Option<&'a BlockNode> {
    blocks.iter().find_map(|tracked| match &tracked.block {
        BlockNode::Table(table) => table_descendant(table, id),
        _ => None,
    })
}

fn table_descendant<'a>(table: &'a stemma::domain::TableNode, id: &str) -> Option<&'a BlockNode> {
    for block in table
        .rows
        .iter()
        .flat_map(|row| &row.cells)
        .flat_map(|cell| &cell.blocks)
    {
        if let BlockNode::Table(nested) = block {
            if nested.id.to_string() == id {
                return Some(block);
            }
            if let Some(found) = table_descendant(nested, id) {
                return Some(found);
            }
        }
    }
    None
}

fn read_paragraph(
    paragraph: &stemma::domain::ParagraphNode,
    structural: bool,
    comment: bool,
) -> DocxCellParagraph {
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
}

/// Nested cell paragraphs appended after the scoped reader's existing results.
pub(super) fn descendant_paragraph_blocks(
    blocks: &[TrackedBlock],
    comment: bool,
) -> Vec<super::DocxBlock> {
    let mut paragraphs = Vec::new();
    for tracked in blocks {
        if let BlockNode::Table(table) = &tracked.block {
            append_descendant_paragraph_blocks(
                table,
                tracked.status != TrackingStatus::Normal,
                false,
                comment,
                &mut paragraphs,
            );
        }
    }
    paragraphs
}

fn append_descendant_paragraph_blocks(
    table: &stemma::domain::TableNode,
    ancestor_locked: bool,
    include_direct: bool,
    comment: bool,
    paragraphs: &mut Vec<super::DocxBlock>,
) {
    for row in &table.rows {
        for cell in &row.cells {
            let structural = ancestor_locked
                || cell.v_merge == VerticalMerge::Continue
                || cell
                    .tracking_status
                    .as_ref()
                    .or(row.tracking_status.as_ref())
                    .is_some();
            for block in &cell.blocks {
                match block {
                    BlockNode::Paragraph(paragraph) if include_direct => {
                        let paragraph = read_paragraph(paragraph, structural, comment);
                        paragraphs.push(super::DocxBlock {
                            id: paragraph.id,
                            kind: super::DocxBlockKind::Paragraph,
                            role: None,
                            text: paragraph.text,
                            runs: Vec::new(),
                            cells: Vec::new(),
                            locked: paragraph.locked,
                        });
                    }
                    BlockNode::Table(nested) => append_descendant_paragraph_blocks(
                        nested, structural, true, comment, paragraphs,
                    ),
                    _ => {}
                }
            }
        }
    }
}

/// Current cell paragraphs in native story-local identity space.
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
    // Keep every previously returned direct anchor ahead of new descendants.
    for tracked in blocks {
        if current(&tracked.status)
            && let BlockNode::Table(table) = &tracked.block
        {
            append_descendant_anchor_blocks(table, false, &mut anchors);
        }
    }
    anchors
}

fn append_descendant_anchor_blocks(
    table: &stemma::domain::TableNode,
    include_direct: bool,
    anchors: &mut Vec<crate::DocxAnchorBlock>,
) {
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
                match block {
                    BlockNode::Paragraph(paragraph) if include_direct => {
                        anchors.push(crate::DocxAnchorBlock {
                            block_id: paragraph.id.to_string(),
                            para_id: paragraph.para_id.clone(),
                            text: current_text(paragraph),
                        });
                    }
                    BlockNode::Table(nested) => {
                        append_descendant_anchor_blocks(nested, true, anchors);
                    }
                    _ => {}
                }
            }
        }
    }
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
