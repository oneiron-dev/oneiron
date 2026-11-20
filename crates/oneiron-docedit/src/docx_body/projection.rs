//! In-memory multi-revision DOCX projection and its shared op builder.

use crate::{DoceditError, Document};
use serde_json::{Value, json};
use stemma::domain::{CanonDoc, TrackedBlock};
use stemma::edit::EditTransaction;

mod session;
mod story_cells;
pub use session::{DocxGroupEvents, DocxProjection};
use stemma::view::{BlockView, DocumentView, build_story_blocks_view};
use story_cells::story_cell_op;

use super::{
    DocxAnchor, DocxChange, DocxHeaderFooterBand, DocxRevision, DocxRun, DocxStoryScope, inherited,
    kept_marks, marked_paragraph, new_paragraph, paragraph, remark, runs_text,
};

/// One group's formatting patches with the operations it builds.
pub(super) type GroupPatchesAndOperations<'v> = (Vec<(&'v BlockView, Vec<(u8, u8)>)>, Vec<Value>);

/// The formatting patches and ops one group's changes build against `view` and
/// `canonical`. Shared by [`project_docx`] and [`DocxProjection`]: one group
/// through the session builds exactly what a lone [`project_docx`] call builds.
/// Body ids resolve over `view` only; story ids resolve over `canonical` only.
///
/// [`project_docx`]: crate::docx_body::project_docx
pub(super) fn group_ops<'v>(
    view: &'v DocumentView,
    canonical: &CanonDoc,
    changes: &[DocxChange],
) -> Result<GroupPatchesAndOperations<'v>, DoceditError> {
    let find = |id: &str| {
        view.blocks
            .iter()
            .find(|block| block.id.to_string() == id)
            .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown block {id}")))
    };
    let anchor = |anchor: &DocxAnchor| {
        let (id, position) = match anchor {
            DocxAnchor::After(id) => (id, "after"),
            DocxAnchor::Before(id) => (id, "before"),
        };
        find(id).map(|block| json!({"anchor": block.id.to_string(), "position": position}))
    };
    let mut patches = Vec::new();
    let mut ops: Vec<Value> = Vec::with_capacity(changes.len());
    for change in changes {
        match change {
            DocxChange::SetText { block, text } => {
                let block = find(block)?;
                ops.push(json!({
                    "op": "replace",
                    "target": block.id.to_string(),
                    "guard": block.guard,
                    "content": paragraph(block.role_token.as_deref(), text),
                }));
            }
            DocxChange::SetRuns { block, runs } => {
                let block = find(block)?;
                // Formatting goes first, as a pass of its own: the guard pins
                // text, not marks, so the replace after it still reads the
                // block it was read against.
                if let Some(patch) = kept_marks(block, runs)? {
                    patches.push((block, patch));
                }
                if runs_text(runs) != block.text {
                    ops.push(json!({
                        "op": "replace",
                        "target": block.id.to_string(),
                        "guard": block.guard,
                        "content": marked_paragraph(block.role_token.as_deref(), runs),
                    }));
                }
            }
            DocxChange::SetCell {
                block,
                row,
                col,
                text,
            } => ops.push(json!({
                "op": "table_op",
                "target": find(block)?.id.to_string(),
                "table_op": {"kind": "set_cell_text", "row_index": row, "col_index": col, "text": text},
            })),
            DocxChange::Move { block, anchor: to } => ops.push(json!({
                "op": "move",
                "target": find(block)?.id.to_string(),
                "destination": anchor(to)?,
            })),
            DocxChange::Insert {
                anchor: at,
                paragraphs,
            } => {
                let content = paragraphs
                    .iter()
                    .map(new_paragraph)
                    .collect::<Result<Vec<_>, _>>()?;
                ops.push(json!({"op": "insert", "target": anchor(at)?, "content": content}));
            }
            DocxChange::Delete { block } => {
                let block = find(block)?;
                ops.push(json!({
                    "op": "delete",
                    "target": block.id.to_string(),
                    "guard": block.guard,
                    "expect": block.text,
                }));
            }
            DocxChange::SetStoryText { scope, block, text } => {
                ops.push(story_text_op(canonical, scope, block, text)?);
            }
            DocxChange::SetStoryRuns { scope, block, runs } => {
                ops.push(story_runs_op(canonical, scope, block, runs)?);
            }
            DocxChange::SetStoryCell {
                scope,
                block,
                row,
                col,
                paragraph,
                text,
            } => {
                ops.push(story_cell_op(
                    canonical, scope, block, *row, *col, paragraph.as_deref(), text,
                )?);
            }
        }
    }
    Ok((patches, ops))
}

/// One story text change as its native op: `edit_header`/`edit_footer` for an
/// authored header/footer paragraph, `edit_note` for a footnote/endnote body,
/// `edit_comment_runs` for one paragraph within a comment story. Header/footer
/// scopes match the actual part name and band and skip synthesized blanks
/// exactly as the reader does. A note routes only when the requested block is
/// its first paragraph; any other block never lands on it. A comment routes by
/// story-local paragraph id, any paragraph of the story.
fn story_text_op(
    canonical: &CanonDoc,
    scope: &DocxStoryScope,
    block: &str,
    text: &str,
) -> Result<Value, DoceditError> {
    match scope {
        DocxStoryScope::Header { part_name, band } => {
            let story = canonical
                .headers
                .iter()
                .find(|story| {
                    &story.part_name == part_name
                        && DocxHeaderFooterBand::from(&story.kind) == *band
                        && !story.synthesized
                })
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown header story {part_name}"))
                })?;
            let story_view = build_story_blocks_view(&story.blocks);
            let target = story_view
                .blocks
                .iter()
                .find(|block_view| block_view.id.to_string() == block)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown block {block}"))
                })?;
            Ok(json!({
                "op": "edit_header",
                "header_part": story.part_name,
                "target": target.id.to_string(),
                "expect": target.text,
                "content": story_text_content(text),
                "semantic_hash": target.guard,
            }))
        }
        DocxStoryScope::Footer { part_name, band } => {
            let story = canonical
                .footers
                .iter()
                .find(|story| {
                    &story.part_name == part_name
                        && DocxHeaderFooterBand::from(&story.kind) == *band
                        && !story.synthesized
                })
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown footer story {part_name}"))
                })?;
            let story_view = build_story_blocks_view(&story.blocks);
            let target = story_view
                .blocks
                .iter()
                .find(|block_view| block_view.id.to_string() == block)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown block {block}"))
                })?;
            Ok(json!({
                "op": "edit_footer",
                "footer_part": story.part_name,
                "target": target.id.to_string(),
                "expect": target.text,
                "content": story_text_content(text),
                "semantic_hash": target.guard,
            }))
        }
        DocxStoryScope::Footnote { id } => {
            let story = canonical
                .footnotes
                .iter()
                .find(|story| &story.id == id)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown footnote story {id}"))
                })?;
            let story_view = build_story_blocks_view(&story.blocks);
            let first = story_view.blocks.first().ok_or_else(|| {
                DoceditError::InvalidTransaction(format!("unknown block {block}"))
            })?;
            if first.id.to_string() != block {
                return Err(DoceditError::InvalidTransaction(format!(
                    "unknown block {block}"
                )));
            }
            Ok(json!({
                "op": "edit_note",
                "note_id": story.id,
                "note_kind": "footnote",
                "body": text,
            }))
        }
        DocxStoryScope::Endnote { id } => {
            let story = canonical
                .endnotes
                .iter()
                .find(|story| &story.id == id)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown endnote story {id}"))
                })?;
            let story_view = build_story_blocks_view(&story.blocks);
            let first = story_view.blocks.first().ok_or_else(|| {
                DoceditError::InvalidTransaction(format!("unknown block {block}"))
            })?;
            if first.id.to_string() != block {
                return Err(DoceditError::InvalidTransaction(format!(
                    "unknown block {block}"
                )));
            }
            Ok(json!({
                "op": "edit_note",
                "note_id": story.id,
                "note_kind": "endnote",
                "body": text,
            }))
        }
        DocxStoryScope::Comment { id } => {
            let story = canonical
                .comments
                .iter()
                .find(|story| &story.id == id)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown comment story {id}"))
                })?;
            comment_runs_op(&story.blocks, &story.id, block, story_text_content(text))
        }
    }
}

/// One story runs change as its native op: an authored header/footer paragraph
/// or one paragraph within a footnote/endnote story, as styled inlines for one
/// whole-paragraph tracked redline; or one paragraph within a comment story as
/// styled inlines for one Normal annotation edit. Comment runs land with exactly
/// the requested six text marks, never as a tracked redline.
fn story_runs_op(
    canonical: &CanonDoc,
    scope: &DocxStoryScope,
    block: &str,
    runs: &[DocxRun],
) -> Result<Value, DoceditError> {
    match scope {
        DocxStoryScope::Header { part_name, band } => {
            let story = canonical
                .headers
                .iter()
                .find(|story| {
                    &story.part_name == part_name
                        && DocxHeaderFooterBand::from(&story.kind) == *band
                        && !story.synthesized
                })
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown header story {part_name}"))
                })?;
            let story_view = build_story_blocks_view(&story.blocks);
            let target = story_view
                .blocks
                .iter()
                .find(|block_view| block_view.id.to_string() == block)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown block {block}"))
                })?;
            Ok(json!({
                "op": "edit_header",
                "header_part": story.part_name,
                "target": target.id.to_string(),
                "expect": target.text,
                "content": story_runs_content(runs),
                "exact_marks": true,
                "semantic_hash": target.guard,
            }))
        }
        DocxStoryScope::Footer { part_name, band } => {
            let story = canonical
                .footers
                .iter()
                .find(|story| {
                    &story.part_name == part_name
                        && DocxHeaderFooterBand::from(&story.kind) == *band
                        && !story.synthesized
                })
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown footer story {part_name}"))
                })?;
            let story_view = build_story_blocks_view(&story.blocks);
            let target = story_view
                .blocks
                .iter()
                .find(|block_view| block_view.id.to_string() == block)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown block {block}"))
                })?;
            Ok(json!({
                "op": "edit_footer",
                "footer_part": story.part_name,
                "target": target.id.to_string(),
                "expect": target.text,
                "content": story_runs_content(runs),
                "exact_marks": true,
                "semantic_hash": target.guard,
            }))
        }
        DocxStoryScope::Footnote { id } => {
            let story = canonical
                .footnotes
                .iter()
                .find(|story| &story.id == id)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown footnote story {id}"))
                })?;
            note_runs_op(&story.blocks, &story.id, "footnote", block, runs)
        }
        DocxStoryScope::Endnote { id } => {
            let story = canonical
                .endnotes
                .iter()
                .find(|story| &story.id == id)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown endnote story {id}"))
                })?;
            note_runs_op(&story.blocks, &story.id, "endnote", block, runs)
        }
        DocxStoryScope::Comment { id } => {
            let story = canonical
                .comments
                .iter()
                .find(|story| &story.id == id)
                .ok_or_else(|| {
                    DoceditError::InvalidTransaction(format!("unknown comment story {id}"))
                })?;
            comment_runs_op(&story.blocks, &story.id, block, story_runs_content(runs))
        }
    }
}

/// One footnote/endnote runs change as its native `edit_note_runs` op. The
/// block resolves by ordered story-local lookup over the ACTUAL note story,
/// so any paragraph of the note (not just its first) is addressable; the
/// guard it carries is that paragraph's own.
fn note_runs_op(
    blocks: &[TrackedBlock],
    note_id: &str,
    note_kind: &'static str,
    block: &str,
    runs: &[DocxRun],
) -> Result<Value, DoceditError> {
    let story_view = build_story_blocks_view(blocks);
    let target = story_view
        .blocks
        .iter()
        .find(|block_view| block_view.id.to_string() == block)
        .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown block {block}")))?;
    Ok(json!({
        "op": "edit_note_runs",
        "note_id": note_id,
        "note_kind": note_kind,
        "target": target.id.to_string(),
        "expect": target.text,
        "content": story_runs_content(runs),
        "semantic_hash": target.guard,
    }))
}

/// One comment runs change as its native `edit_comment_runs` op. The block
/// resolves by ordered story-local lookup over the ACTUAL comment story, so any
/// paragraph of the comment (not just its first) is addressable; the guard it
/// carries is that paragraph's own. `content` is the v4 inline list for the new
/// paragraph text, plain or marked — one op serves both story text and runs.
fn comment_runs_op(
    blocks: &[TrackedBlock],
    comment_id: &str,
    block: &str,
    content: Vec<Value>,
) -> Result<Value, DoceditError> {
    let story_view = build_story_blocks_view(blocks);
    let target = story_view
        .blocks
        .iter()
        .find(|block_view| block_view.id.to_string() == block)
        .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown block {block}")))?;
    Ok(json!({
        "op": "edit_comment_runs",
        "comment_id": comment_id,
        "target": target.id.to_string(),
        "expect": target.text,
        "content": content,
        "semantic_hash": target.guard,
    }))
}

/// The v4 inline list for a story text change, through the same builder the
/// body replace uses: an empty paragraph authors no inlines.
fn story_text_content(text: &str) -> Vec<Value> {
    match paragraph(None, text)
        .get("content")
        .and_then(Value::as_array)
    {
        Some(content) => content.clone(),
        None => Vec::new(),
    }
}

/// The v4 inline list for a story runs change, through the same builder the
/// body marked replace uses: empty runs skipped, marks as inline types.
fn story_runs_content(runs: &[DocxRun]) -> Vec<Value> {
    match marked_paragraph(None, runs)
        .get("content")
        .and_then(Value::as_array)
    {
        Some(content) => content.clone(),
        None => Vec::new(),
    }
}

/// Apply one group's built patches and ops as a single tracked transaction
/// under `revision`, with the inherited-marks correction. Shared by
/// [`project_docx`] and [`DocxProjection`]: one group through the session
/// runs exactly what a lone [`project_docx`] call runs. Callers only pass
/// non-empty builds.
///
/// [`project_docx`]: crate::docx_body::project_docx
pub(super) fn apply_built(
    document: &Document,
    patches: Vec<(&BlockView, Vec<(u8, u8)>)>,
    ops: Vec<Value>,
    changes: &[DocxChange],
    revision: &DocxRevision,
) -> Result<Document, DoceditError> {
    let after_patches = if patches.is_empty() {
        None
    } else {
        Some(remark(document, &patches, revision).ok_or_else(|| {
            DoceditError::InvalidTransaction(
                "a mark change on text its paragraph cannot address".to_owned(),
            )
        })?)
    };
    let after_ops = if ops.is_empty() {
        after_patches
    } else {
        let base = after_patches.as_ref().unwrap_or(document);
        Some(base.apply(&native(ops, revision)?)?)
    };
    let mut edited =
        after_ops.ok_or_else(|| DoceditError::InvalidTransaction("empty projection".to_owned()))?;
    if let Some(remarked) = inherited(&edited, changes, revision) {
        edited = remarked;
    }
    Ok(edited)
}

/// `ops` as one tracked transaction under the projection's revision.
pub(super) fn native(
    ops: Vec<Value>,
    revision: &DocxRevision,
) -> Result<EditTransaction, DoceditError> {
    let transaction = json!({
        "ops": ops,
        "revision": {"author": revision.author, "date": revision.date, "apply_op_id": revision.group},
    });
    crate::parse_native_revision(&transaction.to_string())
}
