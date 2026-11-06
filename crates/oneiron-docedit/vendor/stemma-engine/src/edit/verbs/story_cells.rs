//! Story-scoped table-cell text edits (FIX 594): `EditStoryCell`.
//!
//! One op serves all five story families (header/footer/footnote/endnote/
//! comment) because the cell-text core is identical; only the story address
//! differs. Header/footer reuse [`StoryRef`] (part name verbatim) plus the
//! exact expected band; notes carry `(NoteKind, w:id)`; comments carry `w:id`
//! — never the body, never a bare `tbl_n` (story `tbl_n` ids collide with body
//! `tbl_n` and cross-story, so the scope is load-bearing, not decorative).
//!
//! Resolution is strict and family-local: the actual named story (H/F: exact
//! band and authored, never a synthesized render-time blank), then the
//! story-local table block, then the shared in-place core
//! (`apply_set_cell_text_on_table_block`) — the SAME logical-grid,
//! vMerge, effective-status, first-paragraph, opaque, no-op, revision and
//! Direct law the body cell path uses. H/F and note cells land tracked
//! (Direct honors the outer mode, as the body does); comment cells land as
//! Normal annotation text in BOTH outer modes via the core's text-only settle
//! of the target paragraph only, never a whole-table accept.
//!
//! Invariant M holds: this verb resolves and calls the shared core, which
//! builds the materializer's input; no second materializer is added.

use super::super::story_addr::{StoryRef, story_blocks_mut};
use super::super::{CellStep, EditError, MaterializationMode};
use super::footnotes::NoteKind;
use crate::domain::{
    BlockNode, CanonDoc, HeaderFooterKind, NodeId, RevisionInfo, TableNode, TrackedBlock,
    TrackingStatus, VerticalMerge,
};
use crate::semantic_hash::check_block_guard;

/// Which story a story-cell edit targets. Header/footer carry the [`StoryRef`]
/// (part name verbatim) plus the exact expected band; notes carry their kind
/// plus `w:id`; comments carry their `w:id`. There is deliberately no body
/// arm: body cells keep the body `TableStructureOp` path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoryCellAddress {
    /// A header/footer story: the part name plus the exact band it must carry.
    HeaderFooter {
        story: StoryRef,
        band: HeaderFooterKind,
    },
    /// A footnote/endnote story by kind plus `w:id`.
    Note { kind: NoteKind, id: String },
    /// A comment story by `w:id`.
    Comment { id: String },
}

/// `EditStoryCell`: resolve the actual story table and rewrite its selected
/// cell paragraph through the shared in-place core. An absent selector edits
/// the FIRST paragraph. See the module doc for
/// the addressing and landing law.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply(
    doc: &mut CanonDoc,
    story: &StoryCellAddress,
    block_id: &NodeId,
    row_index: usize,
    col_index: usize,
    paragraph: Option<&NodeId>,
    text: &str,
    semantic_hash: Option<&str>,
    revision: &RevisionInfo,
    rev_counter: &mut u32,
    transaction_floor: u32,
    mode: MaterializationMode,
    step_index: usize,
) -> Result<(), EditError> {
    match story {
        StoryCellAddress::HeaderFooter {
            story: story_ref,
            band,
        } => {
            let (part, is_header) = match story_ref {
                StoryRef::Header(part) => (part, true),
                StoryRef::Footer(part) => (part, false),
                // Translate only ever builds Header/Footer; a Body here is a
                // direct-engine caller error, refused as a missing story (the
                // same guard the paragraph verb applies).
                StoryRef::Body => {
                    return Err(EditError::StoryNotFound {
                        story: story_ref.clone(),
                        step_index,
                    });
                }
            };
            // Strict actual-story gate: the named part must exist, carry
            // exactly the requested band, and be authored — never a synthesized
            // render-time blank (the reader skips those; so does the wrapper).
            let resolved = if is_header {
                doc.headers
                    .iter()
                    .find(|s| &s.part_name == part)
                    .is_some_and(|s| &s.kind == band && !s.synthesized)
            } else {
                doc.footers
                    .iter()
                    .find(|s| &s.part_name == part)
                    .is_some_and(|s| &s.kind == band && !s.synthesized)
            };
            if !resolved {
                return Err(EditError::StoryNotFound {
                    story: story_ref.clone(),
                    step_index,
                });
            }
            let blocks = story_blocks_mut(doc, story_ref, step_index)?;
            let path =
                find_table_path(blocks, block_id).ok_or_else(|| EditError::StoryBlockNotFound {
                    story: story_ref.clone(),
                    block_id: block_id.clone(),
                    step_index,
                })?;
            check_guard_and_table(block_at(blocks, &path), block_id, semantic_hash, step_index)?;
            let (block, enclosing_insert) =
                block_at_mut(blocks, &path, block_id, transaction_floor, step_index)?;
            super::super::apply_set_cell_text_on_table_block(
                block,
                block_id,
                row_index,
                col_index,
                paragraph,
                text,
                revision,
                rev_counter,
                transaction_floor,
                mode,
                step_index,
                false,
                enclosing_insert,
            )
            // The H/F paragraph verb recomputes no story hash; the cell path
            // matches that law.
        }
        StoryCellAddress::Note { kind, id } => {
            let mut story = note_story_mut(doc, *kind, id, step_index)?;
            let path = find_table_path(&story.blocks, block_id).ok_or_else(|| {
                EditError::BlockNotFound {
                    block_id: block_id.clone(),
                    step_index,
                }
            })?;
            check_guard_and_table(
                block_at(&story.blocks, &path),
                block_id,
                semantic_hash,
                step_index,
            )?;
            let (block, enclosing_insert) = block_at_mut(
                &mut story.blocks,
                &path,
                block_id,
                transaction_floor,
                step_index,
            )?;
            super::super::apply_set_cell_text_on_table_block(
                block,
                block_id,
                row_index,
                col_index,
                paragraph,
                text,
                revision,
                rev_counter,
                transaction_floor,
                mode,
                step_index,
                false,
                enclosing_insert,
            )?;
            // Recompute the ENTIRE chosen note story's content hash (the runs
            // verbs' law); every other block and the reference runs survive.
            let story_nodes: Vec<BlockNode> =
                story.blocks.iter().map(|tb| tb.block.clone()).collect();
            *story.content_hash = crate::import::compute_story_content_hash(&story_nodes);
            Ok(())
        }
        StoryCellAddress::Comment { id } => {
            let mut story = comment_story_mut(doc, id, step_index)?;
            let path = find_table_path(&story.blocks, block_id).ok_or_else(|| {
                EditError::BlockNotFound {
                    block_id: block_id.clone(),
                    step_index,
                }
            })?;
            check_guard_and_table(
                block_at(&story.blocks, &path),
                block_id,
                semantic_hash,
                step_index,
            )?;
            let (block, enclosing_insert) = block_at_mut(
                &mut story.blocks,
                &path,
                block_id,
                transaction_floor,
                step_index,
            )?;
            super::super::apply_set_cell_text_on_table_block(
                block,
                block_id,
                row_index,
                col_index,
                paragraph,
                text,
                revision,
                rev_counter,
                transaction_floor,
                mode,
                step_index,
                true,
                enclosing_insert,
            )?;
            // Recompute the ENTIRE chosen comment story's content hash (the
            // runs verb's law); author/date, threading/resolve sidecar, all
            // other blocks, and body anchors survive.
            let story_nodes: Vec<BlockNode> =
                story.blocks.iter().map(|tb| tb.block.clone()).collect();
            *story.content_hash = crate::import::compute_story_content_hash(&story_nodes);
            Ok(())
        }
    }
}

/// The transaction-base table block for a story-cell step, if the actual story
/// and block both resolve there. The dispatch arm checks the caller's guard
/// against THIS (not the live table) so same-transaction sibling steps on one
/// story table do not invalidate each other — the same base-guard law the body
/// `TableStructureOp` arm applies. Any miss (unknown story, band/synthesized
/// mismatch, unknown block) returns `None` and the live path fails loud with
/// its own typed error.
pub(crate) fn find_base_table_block<'a>(
    base: &'a CanonDoc,
    story: &StoryCellAddress,
    block_id: &NodeId,
) -> Option<&'a BlockNode> {
    let blocks: &[TrackedBlock] = match story {
        StoryCellAddress::HeaderFooter {
            story: story_ref,
            band,
        } => match story_ref {
            StoryRef::Header(part) => base.headers.iter().find_map(|s| {
                (&s.part_name == part && &s.kind == band && !s.synthesized)
                    .then_some(s.blocks.as_slice())
            })?,
            StoryRef::Footer(part) => base.footers.iter().find_map(|s| {
                (&s.part_name == part && &s.kind == band && !s.synthesized)
                    .then_some(s.blocks.as_slice())
            })?,
            StoryRef::Body => return None,
        },
        StoryCellAddress::Note { kind, id } => match kind {
            NoteKind::Footnote => base
                .footnotes
                .iter()
                .find_map(|s| (&s.id == id).then_some(s.blocks.as_slice()))?,
            NoteKind::Endnote => base
                .endnotes
                .iter()
                .find_map(|s| (&s.id == id).then_some(s.blocks.as_slice()))?,
        },
        StoryCellAddress::Comment { id } => base
            .comments
            .iter()
            .find_map(|s| (&s.id == id).then_some(s.blocks.as_slice()))?,
    };
    let path = find_table_path(blocks, block_id)?;
    Some(block_at(blocks, &path))
}

/// An internal canonical path, never a wire address. Old top-level ids win.
struct TablePath {
    top: usize,
    descent: Vec<CellStep>,
}

fn find_table_path(blocks: &[TrackedBlock], block_id: &NodeId) -> Option<TablePath> {
    if let Some(top) = super::super::find_block_index(blocks, block_id) {
        return Some(TablePath {
            top,
            descent: Vec::new(),
        });
    }
    for (top, tracked) in blocks.iter().enumerate() {
        if let BlockNode::Table(table) = &tracked.block
            && let Some(descent) = find_table_in_table(table, block_id)
        {
            return Some(TablePath { top, descent });
        }
    }
    None
}

fn find_table_in_table(table: &TableNode, block_id: &NodeId) -> Option<Vec<CellStep>> {
    for (row_idx, row) in table.rows.iter().enumerate() {
        for (cell_idx, cell) in row.cells.iter().enumerate() {
            for (block_in_cell_idx, block) in cell.blocks.iter().enumerate() {
                if let BlockNode::Table(nested) = block {
                    let step = CellStep {
                        row_idx,
                        cell_idx,
                        block_in_cell_idx,
                    };
                    if &nested.id == block_id {
                        return Some(vec![step]);
                    }
                    if let Some(mut path) = find_table_in_table(nested, block_id) {
                        path.insert(0, step);
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

fn block_at<'a>(blocks: &'a [TrackedBlock], path: &TablePath) -> &'a BlockNode {
    let mut block = &blocks[path.top].block;
    for step in &path.descent {
        let BlockNode::Table(table) = block else {
            unreachable!("table path")
        };
        block = &table.rows[step.row_idx].cells[step.cell_idx].blocks[step.block_in_cell_idx];
    }
    block
}

fn block_at_mut<'a>(
    blocks: &'a mut [TrackedBlock],
    path: &TablePath,
    block_id: &NodeId,
    transaction_floor: u32,
    step_index: usize,
) -> Result<(&'a mut BlockNode, bool), EditError> {
    let tracked = &mut blocks[path.top];
    let mut enclosing_insert = false;
    if !path.descent.is_empty() {
        enclosing_insert = own_insert(&tracked.status, transaction_floor);
        if !enclosing_insert
            && let Some(status) = super::super::tracking_status_label(&tracked.status)
        {
            return Err(EditError::BlockHasTrackedStatus {
                block_id: block_id.clone(),
                status,
                step_index,
            });
        }
    }
    let mut block = &mut tracked.block;
    for step in &path.descent {
        let BlockNode::Table(table) = block else {
            unreachable!("table path")
        };
        let row = &mut table.rows[step.row_idx];
        let cell = &mut row.cells[step.cell_idx];
        if cell.v_merge == VerticalMerge::Continue {
            return Err(EditError::TableCellNotEditable {
                block_id: block_id.clone(),
                reason: "an enclosing cell is a vertical-merge continuation; edit its anchor cell"
                    .to_string(),
                step_index,
            });
        }
        if let Some(status) = cell
            .tracking_status
            .as_ref()
            .or(row.tracking_status.as_ref())
        {
            if !own_insert(status, transaction_floor) {
                return Err(EditError::TableCellNotEditable {
                    block_id: block_id.clone(),
                    reason: "an enclosing cell or row carries a pre-existing tracked revision"
                        .to_string(),
                    step_index,
                });
            }
            enclosing_insert = true;
        }
        block = &mut cell.blocks[step.block_in_cell_idx];
    }
    Ok((block, enclosing_insert))
}

fn own_insert(status: &TrackingStatus, floor: u32) -> bool {
    matches!(status, TrackingStatus::Inserted(revision) if revision.revision_id >= floor)
}

/// The live-table preconditions shared by all three story families: the
/// optional semantic-hash guard against the ACTUAL story table block (the same
/// story table view guard the reader mints), then the table-kind gate (a story
/// paragraph id refuses `NotATable` — the shared core's `unreachable!` on
/// non-tables is only sound behind this check, as behind the body's).
fn check_guard_and_table(
    block: &BlockNode,
    block_id: &NodeId,
    semantic_hash: Option<&str>,
    step_index: usize,
) -> Result<(), EditError> {
    if let Some(expected) = semantic_hash
        && let Err(actual) = check_block_guard(block, expected)
    {
        return Err(EditError::BlockSemanticHashMismatch {
            block_id: block_id.clone(),
            expected: expected.to_string(),
            actual,
            step_index,
        });
    }
    match block {
        BlockNode::Table(_) => Ok(()),
        BlockNode::Paragraph(_) => Err(EditError::NotATable {
            block_id: block_id.clone(),
            actual_kind: "paragraph",
            step_index,
        }),
        BlockNode::OpaqueBlock(_) => Err(EditError::NotATable {
            block_id: block_id.clone(),
            actual_kind: "opaque_block",
            step_index,
        }),
    }
}

/// Mutable access to one note/comment story's blocks plus its content hash.
struct StoryMut<'a> {
    blocks: &'a mut Vec<TrackedBlock>,
    content_hash: &'a mut String,
}

/// Resolve one note story's blocks plus content hash by actual `w:id` within
/// the addressed collection.
fn note_story_mut<'a>(
    doc: &'a mut CanonDoc,
    kind: NoteKind,
    id: &str,
    step_index: usize,
) -> Result<StoryMut<'a>, EditError> {
    let kind_label = match kind {
        NoteKind::Footnote => "footnote",
        NoteKind::Endnote => "endnote",
    };
    match kind {
        NoteKind::Footnote => doc
            .footnotes
            .iter_mut()
            .find(|story| story.id == id)
            .map(|story| StoryMut {
                blocks: &mut story.blocks,
                content_hash: &mut story.content_hash,
            }),
        NoteKind::Endnote => doc
            .endnotes
            .iter_mut()
            .find(|story| story.id == id)
            .map(|story| StoryMut {
                blocks: &mut story.blocks,
                content_hash: &mut story.content_hash,
            }),
    }
    .ok_or_else(|| EditError::NoteNotFound {
        note_id: id.to_string(),
        note_kind: kind_label,
        step_index,
    })
}

/// Resolve one comment story's blocks plus content hash by actual `w:id`.
fn comment_story_mut<'a>(
    doc: &'a mut CanonDoc,
    id: &str,
    step_index: usize,
) -> Result<StoryMut<'a>, EditError> {
    doc.comments
        .iter_mut()
        .find(|story| story.id == id)
        .map(|story| StoryMut {
            blocks: &mut story.blocks,
            content_hash: &mut story.content_hash,
        })
        .ok_or_else(|| EditError::CommentTargetNotFound {
            comment_id: id.to_string(),
            step_index,
        })
}
