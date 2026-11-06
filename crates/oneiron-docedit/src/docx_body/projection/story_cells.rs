//! Scoped native table-cell projection.

use crate::{
    DoceditError,
    docx_body::{DocxHeaderFooterBand, DocxStoryScope},
};
use serde_json::{Value, json};
use stemma::domain::{CanonDoc, TrackedBlock};
use stemma::view::build_story_blocks_view;

/// One story cell change as its native `edit_story_cell` op. The table
/// resolves by story-local id over the ACTUAL canonical story only — never the
/// body (story `tbl_n` ids collide with body `tbl_n` and cross-story) — and
/// carries that story table block's own view guard. Header/footer scopes match
/// the actual part name and band and skip synthesized blanks exactly as the
/// reader does; the scope forwards verbatim (the wire scope is the same object
/// shape). A story paragraph id refuses `NotATable` natively, the same
/// authority as the body cell path.
pub(super) fn story_cell_op(
    canonical: &CanonDoc,
    scope: &DocxStoryScope,
    block: &str,
    row: usize,
    col: usize,
    paragraph: Option<&str>,
    text: &str,
) -> Result<Value, DoceditError> {
    let blocks = story_cell_blocks(canonical, scope)?;
    let story_view = build_story_blocks_view(blocks);
    let target = story_view
        .blocks
        .into_iter()
        .find(|block_view| block_view.id.to_string() == block)
        .or_else(|| {
            super::super::cells::descendant_table(blocks, block).map(|table| {
                stemma::view::build_story_block_view(table, &stemma::domain::TrackingStatus::Normal)
            })
        })
        .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown block {block}")))?;
    Ok(json!({
        "op": "edit_story_cell",
        "scope": scope,
        "target": target.id.to_string(),
        "row_index": row,
        "col_index": col,
        "paragraph": paragraph,
        "text": text,
        "semantic_hash": target.guard,
    }))
}

/// The canonical blocks of the story a cell change addresses: the actual named
/// header/footer part plus exact band (synthesized blanks skipped, as the
/// reader does), or the named note kind/id or comment id story.
fn story_cell_blocks<'c>(
    canonical: &'c CanonDoc,
    scope: &DocxStoryScope,
) -> Result<&'c [TrackedBlock], DoceditError> {
    match scope {
        DocxStoryScope::Header { part_name, band } => canonical
            .headers
            .iter()
            .find(|story| {
                &story.part_name == part_name
                    && DocxHeaderFooterBand::from(&story.kind) == *band
                    && !story.synthesized
            })
            .map(|story| story.blocks.as_slice())
            .ok_or_else(|| {
                DoceditError::InvalidTransaction(format!("unknown header story {part_name}"))
            }),
        DocxStoryScope::Footer { part_name, band } => canonical
            .footers
            .iter()
            .find(|story| {
                &story.part_name == part_name
                    && DocxHeaderFooterBand::from(&story.kind) == *band
                    && !story.synthesized
            })
            .map(|story| story.blocks.as_slice())
            .ok_or_else(|| {
                DoceditError::InvalidTransaction(format!("unknown footer story {part_name}"))
            }),
        DocxStoryScope::Footnote { id } => canonical
            .footnotes
            .iter()
            .find(|story| &story.id == id)
            .map(|story| story.blocks.as_slice())
            .ok_or_else(|| {
                DoceditError::InvalidTransaction(format!("unknown footnote story {id}"))
            }),
        DocxStoryScope::Endnote { id } => canonical
            .endnotes
            .iter()
            .find(|story| &story.id == id)
            .map(|story| story.blocks.as_slice())
            .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown endnote story {id}"))),
        DocxStoryScope::Comment { id } => canonical
            .comments
            .iter()
            .find(|story| &story.id == id)
            .map(|story| story.blocks.as_slice())
            .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown comment story {id}"))),
    }
}
