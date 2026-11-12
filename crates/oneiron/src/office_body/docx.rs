//! The DOCX body inside its Loro document, schema 2.
//!
//! Root `office` holds the kind and schema. Root `order`, a movable list, holds
//! block ids in document order, so concurrent moves converge. Root `blocks` maps
//! each id to its block: kind, heading level, role token, whether it was
//! imported, its lock, and either one `text` per paragraph or one text per
//! table cell under `cells` (`row:col`). A paragraph's inline marks are Loro
//! text marks on its `text`, keyed by [`DocxMark::key`] with the value `true`.
//! A deleted block leaves `order` and keeps its entry, so a three-way read can
//! still name it. Imported blocks keep the package's block ids; a new paragraph
//! gets a minted one. Beside the body, root `story_order` lists the imported
//! stories in reader order and root `stories` maps each scope key to its
//! paragraphs and per-paragraph table cells ([`stories`], [`story_tables`]).

mod stories;
mod story_tables;
pub use story_tables::{StoryCell, StoryCellParagraph, StoryTable};

use super::invalid;
use crate::entity_id::EntityId;
use crate::error::Result;
use loro::{
    Container, ExpandType, LoroDoc, LoroMap, LoroMovableList, LoroText, LoroValue, StyleConfig,
    TextDelta, UpdateOptions, ValueOrContainer,
};
use oneiron_docedit::docx_body::{
    DocxAnchor, DocxBlock, DocxBlockKind, DocxChange, DocxLock, DocxMark, DocxParagraph, DocxRun,
    DocxStory, canonical_runs,
};
use std::collections::{BTreeMap, HashMap, HashSet};
pub use stories::{DocxStoryBody, StoryParagraph};

const OFFICE: &str = "office";
const ORDER: &str = "order";
const BLOCKS: &str = "blocks";
const KIND: &str = "kind";
const LEVEL: &str = "level";
const ROLE: &str = "role";
const IMPORTED: &str = "imported";
const LOCK: &str = "lock";
const TEXT: &str = "text";
const CELLS: &str = "cells";
pub(super) const SCHEMA: u32 = 2;
/// One paragraph's or cell's text ceiling.
const MAX_TEXT_BYTES: usize = 1 << 20;

/// A typed read of the body at one frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocxBody {
    pub blocks: Vec<BodyBlock>,
    /// The imported stories in reader order, each with its paragraphs.
    pub stories: Vec<DocxStoryBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyBlock {
    pub id: String,
    pub kind: BodyBlockKind,
    pub role: Option<String>,
    /// Read from the imported package rather than written in the body.
    pub imported: bool,
    /// Read-only: its content would not survive a whole-paragraph replace.
    pub locked: bool,
    pub text: String,
    /// The paragraph's text as runs of one mark set each, joining to `text`;
    /// empty for other blocks.
    pub runs: Vec<DocxRun>,
    /// `(row, col)` to text, for a table.
    pub cells: BTreeMap<(usize, usize), String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyBlockKind {
    Paragraph,
    Heading(u8),
    Table,
    Opaque,
}

#[doc(hidden)]
pub use oneiron_verb_wire::office_body::docx::DocxBodyOp;

/// Write the imported blocks and stories into a fresh document.
pub(super) fn import(doc: &LoroDoc, blocks: &[DocxBlock], stories: &[DocxStory]) -> Result<()> {
    mark_styles(doc);
    let office = doc.get_map(OFFICE);
    office.insert(KIND, "docx").map_err(loro)?;
    office.insert("schema", i64::from(SCHEMA)).map_err(loro)?;
    let order = doc.get_movable_list(ORDER);
    let map = doc.get_map(BLOCKS);
    let mut seen = HashSet::new();
    for (index, block) in blocks.iter().enumerate() {
        if !seen.insert(block.id.as_str()) {
            return Err(invalid("duplicate imported block id"));
        }
        order.insert(index, block.id.as_str()).map_err(loro)?;
        let entry = map
            .insert_container(&block.id, LoroMap::new())
            .map_err(loro)?;
        let (kind, level) = match block.kind {
            DocxBlockKind::Paragraph => ("paragraph", None),
            DocxBlockKind::Heading(level) => ("heading", Some(level)),
            DocxBlockKind::Table => ("table", None),
            DocxBlockKind::Opaque => ("opaque", None),
        };
        entry.insert(KIND, kind).map_err(loro)?;
        if let Some(level) = level {
            entry.insert(LEVEL, i64::from(level)).map_err(loro)?;
        }
        if let Some(role) = &block.role {
            entry.insert(ROLE, role.as_str()).map_err(loro)?;
        }
        entry.insert(IMPORTED, true).map_err(loro)?;
        if let Some(lock) = block.locked {
            entry.insert(LOCK, lock_token(lock)).map_err(loro)?;
        }
        match block.kind {
            DocxBlockKind::Paragraph | DocxBlockKind::Heading(_) => {
                bounded(&block.text)?;
                let text = entry
                    .insert_container(TEXT, LoroText::new())
                    .map_err(loro)?;
                text.insert(0, &block.text).map_err(loro)?;
                let mut at = 0;
                for run in &block.runs {
                    let end = at + run.text.chars().count();
                    for mark in &run.marks {
                        text.mark(at..end, mark.key(), true).map_err(loro)?;
                    }
                    at = end;
                }
            }
            DocxBlockKind::Table => {
                let cells = entry
                    .insert_container(CELLS, LoroMap::new())
                    .map_err(loro)?;
                for cell in &block.cells {
                    bounded(&cell.text)?;
                    cells
                        .insert_container(&cell_key(cell.row, cell.col), LoroText::new())
                        .map_err(loro)?
                        .insert(0, &cell.text)
                        .map_err(loro)?;
                }
            }
            DocxBlockKind::Opaque => {}
        }
    }
    self::stories::import(doc, stories)?;
    Ok(())
}

/// The body's typed state; a malformed document fails closed.
pub(super) fn read(doc: &LoroDoc) -> Result<DocxBody> {
    let office = doc.get_map(OFFICE);
    if string(&office, KIND).as_deref() != Some("docx")
        || int(&office, "schema") != Some(i64::from(SCHEMA))
    {
        return Err(invalid("not a schema-2 DOCX body"));
    }
    let map = doc.get_map(BLOCKS);
    let ids = ids(&doc.get_movable_list(ORDER))?;
    let mut seen = HashSet::new();
    let mut blocks = Vec::with_capacity(ids.len());
    for id in ids {
        if !seen.insert(id.clone()) {
            return Err(invalid("a block appears twice in the body order"));
        }
        let entry = block_map(&map, &id)?;
        let kind = match string(&entry, KIND).as_deref() {
            Some("paragraph") => BodyBlockKind::Paragraph,
            Some("heading") => BodyBlockKind::Heading(
                int(&entry, LEVEL)
                    .and_then(|level| u8::try_from(level).ok())
                    .ok_or_else(|| invalid("heading level"))?,
            ),
            Some("table") => BodyBlockKind::Table,
            Some("opaque") => BodyBlockKind::Opaque,
            _ => return Err(invalid("block kind")),
        };
        let (text, runs) = match kind {
            BodyBlockKind::Paragraph | BodyBlockKind::Heading(_) => {
                let body = loro_text(&entry, TEXT).ok_or_else(|| invalid("paragraph text"))?;
                (body.to_string(), runs(&body)?)
            }
            _ => (String::new(), Vec::new()),
        };
        let mut cells = BTreeMap::new();
        if kind == BodyBlockKind::Table {
            let grid = child_map(&entry, CELLS).ok_or_else(|| invalid("table cells"))?;
            for key in grid.keys() {
                let position = parse_cell_key(&key).ok_or_else(|| invalid("cell key"))?;
                let cell = loro_text(&grid, &key).ok_or_else(|| invalid("cell text"))?;
                cells.insert(position, cell.to_string());
            }
        }
        blocks.push(BodyBlock {
            id,
            kind,
            role: string(&entry, ROLE),
            imported: matches!(
                entry.get(IMPORTED),
                Some(ValueOrContainer::Value(LoroValue::Bool(true)))
            ),
            locked: string(&entry, LOCK).is_some(),
            text,
            runs,
            cells,
        });
    }
    Ok(DocxBody {
        blocks,
        stories: stories::read(doc)?,
    })
}

/// Apply one operation; a minted paragraph id is pushed to `minted`.
pub(super) fn apply(doc: &LoroDoc, op: &DocxBodyOp, minted: &mut Vec<String>) -> Result<()> {
    let order = doc.get_movable_list(ORDER);
    let map = doc.get_map(BLOCKS);
    let ids = ids(&order)?;
    let position = |id: &str| {
        ids.iter()
            .position(|other| other == id)
            .ok_or_else(|| invalid("no such block in the body"))
    };
    let editable = |id: &str| -> Result<LoroMap> {
        position(id)?;
        let entry = block_map(&map, id)?;
        if string(&entry, LOCK).is_some() {
            return Err(invalid("the block is read-only in the body"));
        }
        Ok(entry)
    };
    match op {
        DocxBodyOp::SetText { block, text: new } => {
            line(new)?;
            let body =
                loro_text(&editable(block)?, TEXT).ok_or_else(|| invalid("not a paragraph"))?;
            body.update(new, UpdateOptions::default())
                .map_err(|_| invalid("paragraph update"))?;
        }
        DocxBodyOp::Splice {
            block,
            at,
            delete,
            insert,
        } => {
            line(insert)?;
            let body =
                loro_text(&editable(block)?, TEXT).ok_or_else(|| invalid("not a paragraph"))?;
            let end = at
                .checked_add(*delete)
                .ok_or_else(|| invalid("splice range"))?;
            if end > body.len_unicode() {
                return Err(invalid("splice range"));
            }
            body.delete(*at, *delete).map_err(loro)?;
            body.insert(*at, insert).map_err(loro)?;
            bounded(&body.to_string())?;
        }
        DocxBodyOp::SetCell {
            block,
            row,
            col,
            text: new,
        } => {
            bounded(new)?;
            let grid = child_map(&editable(block)?, CELLS).ok_or_else(|| invalid("not a table"))?;
            loro_text(&grid, &cell_key(*row, *col))
                .ok_or_else(|| invalid("no such cell"))?
                .update(new, UpdateOptions::default())
                .map_err(|_| invalid("cell update"))?;
        }
        DocxBodyOp::InsertParagraph {
            after,
            role,
            text: new,
        } => {
            line(new)?;
            if role
                .as_ref()
                .is_some_and(|role| role.is_empty() || role.len() > 256)
            {
                return Err(invalid("paragraph role"));
            }
            let at = match after {
                Some(after) => position(after)? + 1,
                None => 0,
            };
            let id = format!("n{}", EntityId::now().to_hex());
            order.insert(at, id.as_str()).map_err(loro)?;
            let entry = map.insert_container(&id, LoroMap::new()).map_err(loro)?;
            entry.insert(KIND, "paragraph").map_err(loro)?;
            if let Some(role) = role {
                entry.insert(ROLE, role.as_str()).map_err(loro)?;
            }
            entry.insert(IMPORTED, false).map_err(loro)?;
            entry
                .insert_container(TEXT, LoroText::new())
                .map_err(loro)?
                .insert(0, new)
                .map_err(loro)?;
            minted.push(id);
        }
        DocxBodyOp::Delete { block } => {
            editable(block)?;
            order.delete(position(block)?, 1).map_err(loro)?;
        }
        DocxBodyOp::Move { block, after } => {
            editable(block)?;
            let from = position(block)?;
            let to = match after {
                None => 0,
                Some(after) if after == block => {
                    return Err(invalid("a block cannot follow itself"));
                }
                // Positions after the moved block shift left once it leaves.
                Some(after) => {
                    let anchor = position(after)?;
                    if anchor > from { anchor } else { anchor + 1 }
                }
            };
            if from != to {
                order.mov(from, to).map_err(loro)?;
            }
        }
        DocxBodyOp::Mark {
            block,
            at,
            len,
            mark,
            on,
        } => {
            let body =
                loro_text(&editable(block)?, TEXT).ok_or_else(|| invalid("not a paragraph"))?;
            let end = at
                .checked_add(*len)
                .filter(|end| *len > 0 && *end <= body.len_unicode())
                .ok_or_else(|| invalid("mark range"))?;
            mark_styles(doc);
            if *on {
                body.mark(*at..end, mark.key(), true).map_err(loro)?;
                if let Some(other) = mark.baseline_pair() {
                    body.unmark(*at..end, other.key()).map_err(loro)?;
                }
            } else {
                body.unmark(*at..end, mark.key()).map_err(loro)?;
            }
        }
        DocxBodyOp::SetStoryCellParagraph {
            scope,
            block,
            row,
            col,
            paragraph,
            text,
        } => {
            story_tables::set_text(doc, scope, block, *row, *col, paragraph, text)?;
        }
        DocxBodyOp::SpliceStoryCellParagraph {
            scope,
            block,
            row,
            col,
            paragraph,
            at,
            delete,
            insert,
        } => {
            story_tables::splice(
                doc, scope, block, *row, *col, paragraph, *at, *delete, insert,
            )?;
        }
        DocxBodyOp::SetStoryText { scope, block, text } => {
            stories::set_text(doc, scope, block, text)?;
        }
        DocxBodyOp::SpliceStory {
            scope,
            block,
            at,
            delete,
            insert,
        } => {
            stories::splice(doc, scope, block, *at, *delete, insert)?;
        }
        DocxBodyOp::MarkStory {
            scope,
            block,
            at,
            len,
            mark,
            on,
        } => {
            stories::set_mark(doc, scope, block, *at, *len, *mark, *on)?;
        }
    }
    Ok(())
}

/// Loro configures bold, italic and underline only; every mark of the body
/// grows over text typed at its end, as Word's run formatting does.
fn mark_styles(doc: &LoroDoc) {
    doc.config_default_text_style(Some(StyleConfig {
        expand: ExpandType::After,
    }));
}

/// A paragraph's text as canonical runs; a mark the body does not know fails
/// closed.
fn runs(text: &LoroText) -> Result<Vec<DocxRun>> {
    let mut runs = Vec::new();
    for delta in text.to_delta() {
        let TextDelta::Insert { insert, attributes } = delta else {
            return Err(invalid("paragraph text delta"));
        };
        let mut marks = Vec::new();
        for (key, value) in attributes.into_iter().flatten() {
            if value == LoroValue::Bool(true) {
                marks.push(DocxMark::from_key(&key).ok_or_else(|| invalid("text mark"))?);
            }
        }
        runs.push(DocxRun {
            text: insert,
            marks,
        });
    }
    Ok(canonical_runs(runs))
}

/// Whether any run carries a mark.
fn marked(runs: &[DocxRun]) -> bool {
    runs.iter().any(|run| !run.marks.is_empty())
}

/// The changes that turn the imported `base` into `current`, in the order the
/// native writer applies them: text and cells, moves, inserts, deletes, then
/// story runs.
/// Moves first put the imported blocks in body order, so a new paragraph lands
/// beside the block it follows in the body.
pub(super) fn changes(base: &DocxBody, current: &DocxBody) -> Result<Vec<DocxChange>> {
    let base_index: HashMap<&str, usize> = base
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.id.as_str(), index))
        .collect();
    let kept: Vec<&BodyBlock> = current
        .blocks
        .iter()
        .filter(|block| block.imported)
        .collect();
    let mut changes = Vec::new();
    for block in &kept {
        let before = &base.blocks[*base_index
            .get(block.id.as_str())
            .ok_or_else(|| invalid("an imported block the import never had"))?];
        if block.locked
            && (block.text != before.text
                || block.runs != before.runs
                || block.cells != before.cells)
        {
            return Err(invalid("a read-only block changed"));
        }
        if marked(&block.runs) || marked(&before.runs) {
            if block.runs != before.runs {
                changes.push(DocxChange::SetRuns {
                    block: block.id.clone(),
                    runs: block.runs.clone(),
                });
            }
        } else if block.text != before.text {
            changes.push(DocxChange::SetText {
                block: block.id.clone(),
                text: block.text.clone(),
            });
        }
        for (&(row, col), text) in &block.cells {
            if before.cells.get(&(row, col)) != Some(text) {
                changes.push(DocxChange::SetCell {
                    block: block.id.clone(),
                    row,
                    col,
                    text: text.clone(),
                });
            }
        }
    }
    let staying = increasing(
        &kept
            .iter()
            .map(|block| base_index[block.id.as_str()])
            .collect::<Vec<_>>(),
    );
    for (index, block) in kept.iter().enumerate() {
        if !staying.contains(&index) {
            changes.push(DocxChange::Move {
                block: block.id.clone(),
                anchor: match index.checked_sub(1) {
                    Some(previous) => DocxAnchor::After(kept[previous].id.clone()),
                    None => DocxAnchor::Before(
                        kept.get(1)
                            .ok_or_else(|| invalid("a lone block cannot move"))?
                            .id
                            .clone(),
                    ),
                },
            });
        }
    }
    let mut previous: Option<&str> = None;
    let mut run: Vec<DocxParagraph> = Vec::new();
    let mut inserts = Vec::new();
    for block in &current.blocks {
        if block.imported {
            if !run.is_empty() {
                inserts.push((previous, std::mem::take(&mut run)));
            }
            previous = Some(block.id.as_str());
        } else {
            run.push(DocxParagraph {
                role: block.role.clone(),
                text: block.text.clone(),
                runs: if marked(&block.runs) {
                    block.runs.clone()
                } else {
                    Vec::new()
                },
            });
        }
    }
    if !run.is_empty() {
        inserts.push((previous, run));
    }
    for (previous, paragraphs) in inserts {
        let anchor = match (previous, kept.first(), base.blocks.last()) {
            (Some(previous), _, _) => DocxAnchor::After(previous.to_owned()),
            (None, Some(first), _) => DocxAnchor::Before(first.id.clone()),
            // Every imported block was deleted: a tracked delete keeps it in place.
            (None, None, Some(last)) => DocxAnchor::After(last.id.clone()),
            (None, None, None) => return Err(invalid("an empty import has no anchor")),
        };
        changes.push(DocxChange::Insert { anchor, paragraphs });
    }
    let present: HashSet<&str> = kept.iter().map(|block| block.id.as_str()).collect();
    for block in &base.blocks {
        if !present.contains(block.id.as_str()) {
            if block.locked {
                return Err(invalid("a read-only block was deleted"));
            }
            changes.push(DocxChange::Delete {
                block: block.id.clone(),
            });
        }
    }
    changes.extend(stories::changes(&base.stories, &current.stories)?);
    Ok(changes)
}

/// Indices of one longest strictly increasing subsequence of `values`: the
/// blocks that keep their relative order, so only the rest move.
pub(super) fn increasing(values: &[usize]) -> HashSet<usize> {
    let mut tails: Vec<usize> = Vec::new();
    let mut parent = vec![None; values.len()];
    for (index, value) in values.iter().enumerate() {
        let slot = tails.partition_point(|&tail| values[tail] < *value);
        parent[index] = slot.checked_sub(1).map(|previous| tails[previous]);
        if slot == tails.len() {
            tails.push(index);
        } else {
            tails[slot] = index;
        }
    }
    let mut kept = HashSet::new();
    let mut cursor = tails.last().copied();
    while let Some(index) = cursor {
        kept.insert(index);
        cursor = parent[index];
    }
    kept
}

fn lock_token(lock: DocxLock) -> &'static str {
    match lock {
        DocxLock::Tracked => "tracked",
        DocxLock::Anchors => "anchors",
        DocxLock::LiteralPrefix => "literal_prefix",
        DocxLock::Opaque => "opaque",
    }
}

fn cell_key(row: usize, col: usize) -> String {
    format!("{row}:{col}")
}

fn parse_cell_key(key: &str) -> Option<(usize, usize)> {
    let (row, col) = key.split_once(':')?;
    Some((row.parse().ok()?, col.parse().ok()?))
}

fn ids(order: &LoroMovableList) -> Result<Vec<String>> {
    (0..order.len())
        .map(|index| match order.get(index) {
            Some(ValueOrContainer::Value(LoroValue::String(id))) => Ok(id.to_string()),
            _ => Err(invalid("body order entry")),
        })
        .collect()
}

fn block_map(map: &LoroMap, id: &str) -> Result<LoroMap> {
    child_map(map, id).ok_or_else(|| invalid("body block entry"))
}

fn child_map(map: &LoroMap, key: &str) -> Option<LoroMap> {
    match map.get(key)? {
        ValueOrContainer::Container(Container::Map(child)) => Some(child),
        _ => None,
    }
}

fn loro_text(map: &LoroMap, key: &str) -> Option<LoroText> {
    match map.get(key)? {
        ValueOrContainer::Container(Container::Text(text)) => Some(text),
        _ => None,
    }
}

fn string(map: &LoroMap, key: &str) -> Option<String> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::String(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn int(map: &LoroMap, key: &str) -> Option<i64> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::I64(value)) => Some(value),
        _ => None,
    }
}

/// A paragraph holds one line: a break would be a second paragraph.
fn line(text: &str) -> Result<()> {
    if text.contains(['\n', '\r']) {
        return Err(invalid("a paragraph's text holds no line breaks"));
    }
    bounded(text)
}

fn bounded(text: &str) -> Result<()> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(invalid("text exceeds the body's per-block ceiling"));
    }
    Ok(())
}

fn loro(_: loro::LoroError) -> crate::error::Error {
    invalid("office body document operation")
}
