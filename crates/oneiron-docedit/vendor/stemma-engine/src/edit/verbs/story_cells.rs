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

use super::super::story_addr::{StoryRef, find_block_index_in_story, story_blocks_mut};
use super::super::{EditError, MaterializationMode};
use super::footnotes::NoteKind;
use crate::domain::{BlockNode, CanonDoc, HeaderFooterKind, NodeId, RevisionInfo, TrackedBlock};
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

/// `EditStoryCell`: resolve the actual story table and rewrite the cell's
/// FIRST paragraph through the shared in-place core. See the module doc for
/// the addressing and landing law.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply(
    doc: &mut CanonDoc,
    story: &StoryCellAddress,
    block_id: &NodeId,
    row_index: usize,
    col_index: usize,
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
            let idx = find_block_index_in_story(doc, story_ref, block_id, step_index)?;
            let blocks = story_blocks_mut(doc, story_ref, step_index)?;
            check_guard_and_table(blocks, idx, block_id, semantic_hash, step_index)?;
            super::super::apply_set_cell_text_on_table_block(
                &mut blocks[idx].block,
                block_id,
                row_index,
                col_index,
                text,
                revision,
                rev_counter,
                transaction_floor,
                mode,
                step_index,
                false,
            )
            // The H/F paragraph verb recomputes no story hash; the cell path
            // matches that law.
        }
        StoryCellAddress::Note { kind, id } => {
            let mut story = note_story_mut(doc, *kind, id, step_index)?;
            let idx = find_story_block_index(&story.blocks, block_id, step_index)?;
            check_guard_and_table(&story.blocks, idx, block_id, semantic_hash, step_index)?;
            super::super::apply_set_cell_text_on_table_block(
                &mut story.blocks[idx].block,
                block_id,
                row_index,
                col_index,
                text,
                revision,
                rev_counter,
                transaction_floor,
                mode,
                step_index,
                false,
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
            let idx = find_story_block_index(&story.blocks, block_id, step_index)?;
            check_guard_and_table(&story.blocks, idx, block_id, semantic_hash, step_index)?;
            super::super::apply_set_cell_text_on_table_block(
                &mut story.blocks[idx].block,
                block_id,
                row_index,
                col_index,
                text,
                revision,
                rev_counter,
                transaction_floor,
                mode,
                step_index,
                true,
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
    let idx = super::super::find_block_index(blocks, block_id)?;
    Some(&blocks[idx].block)
}

/// Story-local id lookup over the ACTUAL note/comment blocks (all three block
/// kinds, so a paragraph id never misresolves and a table id is found). This
/// deliberately does not call the body `find_block_index`: a colliding body id
/// must never resolve here. Missing ids surface as `BlockNotFound`, the runs
/// verbs' law for in-story misses.
fn find_story_block_index(
    blocks: &[TrackedBlock],
    block_id: &NodeId,
    step_index: usize,
) -> Result<usize, EditError> {
    blocks
        .iter()
        .position(|tb| match &tb.block {
            BlockNode::Paragraph(p) => &p.id == block_id,
            BlockNode::Table(t) => &t.id == block_id,
            BlockNode::OpaqueBlock(o) => &o.id == block_id,
        })
        .ok_or_else(|| EditError::BlockNotFound {
            block_id: block_id.clone(),
            step_index,
        })
}

/// The live-table preconditions shared by all three story families: the
/// optional semantic-hash guard against the ACTUAL story table block (the same
/// story table view guard the reader mints), then the table-kind gate (a story
/// paragraph id refuses `NotATable` — the shared core's `unreachable!` on
/// non-tables is only sound behind this check, as behind the body's).
fn check_guard_and_table(
    blocks: &[TrackedBlock],
    idx: usize,
    block_id: &NodeId,
    semantic_hash: Option<&str>,
    step_index: usize,
) -> Result<(), EditError> {
    if let Some(expected) = semantic_hash
        && let Err(actual) = check_block_guard(&blocks[idx].block, expected)
    {
        return Err(EditError::BlockSemanticHashMismatch {
            block_id: block_id.clone(),
            expected: expected.to_string(),
            actual,
            step_index,
        });
    }
    match &blocks[idx].block {
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
