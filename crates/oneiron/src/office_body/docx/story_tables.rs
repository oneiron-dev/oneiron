//! Plain per-paragraph story-table text. Unmodeled cell siblings stay in the package.

use super::super::invalid;
use super::stories::{child_list, order_ids};
use super::{LOCK, TEXT, cell_key, child_map, lock_token, loro, loro_text, parse_cell_key, string};
use crate::error::Result;
use loro::{LoroDoc, LoroList, LoroMap, LoroText, UpdateOptions};
use oneiron_docedit::docx_body::{DocxBlockKind, DocxChange, DocxStory, DocxStoryScope};
use std::collections::HashSet;

const ORDER: &str = "table_order";
const TABLES: &str = "tables";
const CELLS: &str = "cells";
const PARAGRAPHS: &str = "paragraphs";
const PARA_ORDER: &str = "order";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoryCellParagraph {
    pub id: String,
    pub locked: bool,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoryCell {
    pub row: usize,
    pub col: usize,
    pub paragraphs: Vec<StoryCellParagraph>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoryTable {
    pub id: String,
    pub cells: Vec<StoryCell>,
}

pub(super) fn import(entry: &LoroMap, story: &DocxStory) -> Result<()> {
    let order = entry
        .insert_container(ORDER, LoroList::new())
        .map_err(loro)?;
    let tables = entry
        .insert_container(TABLES, LoroMap::new())
        .map_err(loro)?;
    let mut ids = HashSet::new();
    for (at, table) in story
        .blocks
        .iter()
        .filter(|block| block.kind == DocxBlockKind::Table)
        .enumerate()
    {
        if !ids.insert(table.id.as_str()) {
            return Err(invalid("duplicate imported story table id"));
        }
        order.insert(at, table.id.as_str()).map_err(loro)?;
        let target = tables
            .insert_container(&table.id, LoroMap::new())
            .map_err(loro)?;
        let cells = target
            .insert_container(CELLS, LoroMap::new())
            .map_err(loro)?;
        let mut positions = HashSet::new();
        for cell in &table.cells {
            let key = cell_key(cell.row, cell.col);
            if !positions.insert(key.clone()) {
                return Err(invalid("duplicate imported story cell"));
            }
            let target = cells.insert_container(&key, LoroMap::new()).map_err(loro)?;
            let order = target
                .insert_container(PARA_ORDER, LoroList::new())
                .map_err(loro)?;
            let paragraphs = target
                .insert_container(PARAGRAPHS, LoroMap::new())
                .map_err(loro)?;
            let mut ids = HashSet::new();
            for (at, paragraph) in cell.paragraphs.iter().enumerate() {
                if !ids.insert(paragraph.id.as_str()) {
                    return Err(invalid("duplicate imported story cell paragraph"));
                }
                order.insert(at, paragraph.id.as_str()).map_err(loro)?;
                let target = paragraphs
                    .insert_container(&paragraph.id, LoroMap::new())
                    .map_err(loro)?;
                if let Some(lock) = paragraph.locked {
                    target.insert(LOCK, lock_token(lock)).map_err(loro)?;
                }
                target
                    .insert_container(TEXT, LoroText::new())
                    .map_err(loro)?
                    .insert(0, &paragraph.text)
                    .map_err(loro)?;
            }
        }
    }
    Ok(())
}

pub(super) fn read(entry: &LoroMap) -> Result<Vec<StoryTable>> {
    let order = child_list(entry, ORDER).ok_or_else(|| invalid("story table order"))?;
    let tables = child_map(entry, TABLES).ok_or_else(|| invalid("story tables"))?;
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for id in order_ids(&order)? {
        if !seen.insert(id.clone()) {
            return Err(invalid("a story table appears twice in its order"));
        }
        let table = child_map(&tables, &id).ok_or_else(|| invalid("story table"))?;
        let cells = child_map(&table, CELLS).ok_or_else(|| invalid("story table cells"))?;
        let mut positions = cells
            .keys()
            .map(|key| {
                parse_cell_key(&key)
                    .map(|position| (position, key))
                    .ok_or_else(|| invalid("story cell key"))
            })
            .collect::<Result<Vec<_>>>()?;
        positions.sort_by_key(|(position, _)| *position);
        let mut body_cells = Vec::with_capacity(positions.len());
        for ((row, col), key) in positions {
            // Reject aliases such as 00:1: one logical cell has one native key.
            if cell_key(row, col) != key.as_str() {
                return Err(invalid("story cell key"));
            }
            let cell = child_map(&cells, &key).ok_or_else(|| invalid("story cell"))?;
            let order = child_list(&cell, PARA_ORDER).ok_or_else(|| invalid("story cell order"))?;
            let paragraphs =
                child_map(&cell, PARAGRAPHS).ok_or_else(|| invalid("story cell paragraphs"))?;
            let mut ids = HashSet::new();
            let mut body_paragraphs = Vec::new();
            for id in order_ids(&order)? {
                if !ids.insert(id.clone()) {
                    return Err(invalid("a story cell paragraph appears twice in its order"));
                }
                let paragraph =
                    child_map(&paragraphs, &id).ok_or_else(|| invalid("story cell paragraph"))?;
                let text = loro_text(&paragraph, TEXT)
                    .ok_or_else(|| invalid("story cell paragraph text"))?;
                body_paragraphs.push(StoryCellParagraph {
                    id,
                    locked: string(&paragraph, LOCK).is_some(),
                    text: text.to_string(),
                });
            }
            body_cells.push(StoryCell {
                row,
                col,
                paragraphs: body_paragraphs,
            });
        }
        result.push(StoryTable {
            id,
            cells: body_cells,
        });
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn set_text(
    doc: &LoroDoc,
    scope: &DocxStoryScope,
    table: &str,
    row: usize,
    col: usize,
    paragraph: &str,
    text: &str,
) -> Result<()> {
    editable(doc, scope, table, row, col, paragraph)?
        .update(text, UpdateOptions::default())
        .map_err(|_| invalid("story cell paragraph update"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn splice(
    doc: &LoroDoc,
    scope: &DocxStoryScope,
    table: &str,
    row: usize,
    col: usize,
    paragraph: &str,
    at: usize,
    delete: usize,
    insert: &str,
) -> Result<()> {
    let text = editable(doc, scope, table, row, col, paragraph)?;
    let end = at
        .checked_add(delete)
        .ok_or_else(|| invalid("story cell splice range"))?;
    if end > text.len_unicode() {
        return Err(invalid("story cell splice range"));
    }
    text.delete(at, delete).map_err(loro)?;
    text.insert(at, insert).map_err(loro)?;
    Ok(())
}

pub(super) fn changes(
    scope: &DocxStoryScope,
    before: &[StoryTable],
    after: &[StoryTable],
) -> Result<Vec<DocxChange>> {
    if before.len() != after.len() || before.iter().zip(after).any(|(was, now)| was.id != now.id) {
        return Err(invalid("a story's tables changed shape"));
    }
    let mut changes = Vec::new();
    for (was, now) in before.iter().zip(after) {
        if was.cells.len() != now.cells.len()
            || was
                .cells
                .iter()
                .zip(&now.cells)
                .any(|(was, now)| (was.row, was.col) != (now.row, now.col))
        {
            return Err(invalid("a story table's cells changed shape"));
        }
        for (was_cell, now_cell) in was.cells.iter().zip(&now.cells) {
            if was_cell.paragraphs.len() != now_cell.paragraphs.len()
                || was_cell
                    .paragraphs
                    .iter()
                    .zip(&now_cell.paragraphs)
                    .any(|(was, now)| was.id != now.id)
            {
                return Err(invalid("a story cell's paragraphs changed shape"));
            }
            for (was, paragraph) in was_cell.paragraphs.iter().zip(&now_cell.paragraphs) {
                if was.locked != paragraph.locked {
                    return Err(invalid("a story cell paragraph's lock changed"));
                }
                if was.text == paragraph.text {
                    continue;
                }
                if paragraph.locked {
                    return Err(invalid("a read-only story cell paragraph changed"));
                }
                changes.push(DocxChange::SetStoryCell {
                    scope: scope.clone(),
                    block: now.id.clone(),
                    row: now_cell.row,
                    col: now_cell.col,
                    paragraph: Some(paragraph.id.clone()),
                    text: paragraph.text.clone(),
                });
            }
        }
    }
    Ok(changes)
}

fn editable(
    doc: &LoroDoc,
    scope: &DocxStoryScope,
    table: &str,
    row: usize,
    col: usize,
    paragraph: &str,
) -> Result<LoroText> {
    let entry = super::stories::story_entry(doc, scope)?;
    let order = child_list(&entry, ORDER).ok_or_else(|| invalid("story table order"))?;
    if !order_ids(&order)?.iter().any(|id| id == table) {
        return Err(invalid("no such story table in the body"));
    }
    let tables = child_map(&entry, TABLES).ok_or_else(|| invalid("story tables"))?;
    let table = child_map(&tables, table).ok_or_else(|| invalid("story table"))?;
    let cells = child_map(&table, CELLS).ok_or_else(|| invalid("story table cells"))?;
    let cell = child_map(&cells, &cell_key(row, col))
        .ok_or_else(|| invalid("no such story cell in the body"))?;
    let order = child_list(&cell, PARA_ORDER).ok_or_else(|| invalid("story cell order"))?;
    if !order_ids(&order)?.iter().any(|id| id == paragraph) {
        return Err(invalid("no such paragraph in the story cell"));
    }
    let paragraphs =
        child_map(&cell, PARAGRAPHS).ok_or_else(|| invalid("story cell paragraphs"))?;
    let paragraph =
        child_map(&paragraphs, paragraph).ok_or_else(|| invalid("story cell paragraph"))?;
    if string(&paragraph, LOCK).is_some() {
        return Err(invalid("the story cell paragraph is read-only in the body"));
    }
    loro_text(&paragraph, TEXT).ok_or_else(|| invalid("story cell paragraph text"))
}
