//! The DOCX stories beside the body inside its Loro document, schema 2.
//!
//! Root `story_order`, a list, holds story keys in reader order, and root
//! `stories` maps each key to its story: the scope it serializes as, an
//! `order` list of paragraph ids in reader order, and a `blocks` map of each
//! id to its paragraph: its lock and one `text` with Loro text marks. A story
//! key is its scope's canonical JSON, so no two scopes share one. Story tables
//! model their direct cell paragraphs separately in [`super::story_tables`].
//! Unmodeled opaque and nested blocks stay in the same source package.

use super::super::invalid;
use super::{LOCK, TEXT, child_map, lock_token, loro, loro_text, mark_styles, runs, string};
use crate::error::Result;
use loro::{
    Container, LoroDoc, LoroList, LoroMap, LoroText, LoroValue, UpdateOptions, ValueOrContainer,
};
use oneiron_docedit::docx_body::{
    DocxBlockKind, DocxChange, DocxMark, DocxRun, DocxStory, DocxStoryScope,
};
use std::collections::HashSet;

const STORIES: &str = "stories";
const STORY_ORDER: &str = "story_order";
const SCOPE: &str = "scope";
const ORDER: &str = "order";
const BLOCKS: &str = "blocks";

/// One imported story paragraph: its story-local id, lock and text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoryParagraph {
    pub id: String,
    /// Read-only: its content would not survive a whole-paragraph replace.
    pub locked: bool,
    pub text: String,
    /// The paragraph's text as runs of one mark set each, joining to `text`.
    pub runs: Vec<DocxRun>,
}

/// One imported story: its native scope and paragraphs in reader order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocxStoryBody {
    pub scope: DocxStoryScope,
    pub paragraphs: Vec<StoryParagraph>,
    pub tables: Vec<super::StoryTable>,
}

/// A story's key: its scope's canonical JSON.
pub(super) fn scope_key(scope: &DocxStoryScope) -> Result<String> {
    serde_json::to_string(scope).map_err(|_| invalid("story scope"))
}

/// Write the imported stories into a fresh document beside its body.
pub(super) fn import(doc: &LoroDoc, stories: &[DocxStory]) -> Result<()> {
    let order = doc.get_list(STORY_ORDER);
    let map = doc.get_map(STORIES);
    let mut seen = HashSet::new();
    for (index, story) in stories.iter().enumerate() {
        let key = scope_key(&story.scope)?;
        if !seen.insert(key.clone()) {
            return Err(invalid("duplicate imported story scope"));
        }
        order.insert(index, key.as_str()).map_err(loro)?;
        let entry = map.insert_container(&key, LoroMap::new()).map_err(loro)?;
        entry.insert(SCOPE, key.as_str()).map_err(loro)?;
        let story_order = entry
            .insert_container(ORDER, LoroList::new())
            .map_err(loro)?;
        let blocks = entry
            .insert_container(BLOCKS, LoroMap::new())
            .map_err(loro)?;
        super::story_tables::import(&entry, story)?;
        let mut ids = HashSet::new();
        let mut at = 0;
        for block in &story.blocks {
            // Tables have their own per-paragraph model; opaque blocks stay
            // in the source package.
            if !matches!(
                block.kind,
                DocxBlockKind::Paragraph | DocxBlockKind::Heading(_)
            ) {
                continue;
            }
            if !ids.insert(block.id.as_str()) {
                return Err(invalid("duplicate imported story paragraph id"));
            }
            story_order.insert(at, block.id.as_str()).map_err(loro)?;
            at += 1;
            let paragraph = blocks
                .insert_container(&block.id, LoroMap::new())
                .map_err(loro)?;
            if let Some(lock) = block.locked {
                paragraph.insert(LOCK, lock_token(lock)).map_err(loro)?;
            }
            let text = paragraph
                .insert_container(TEXT, LoroText::new())
                .map_err(loro)?;
            text.insert(0, &block.text).map_err(loro)?;
            let mut pos = 0;
            for run in &block.runs {
                let end = pos + run.text.chars().count();
                for mark in &run.marks {
                    text.mark(pos..end, mark.key(), true).map_err(loro)?;
                }
                pos = end;
            }
        }
    }
    Ok(())
}

/// The stories' typed state; a malformed document fails closed.
pub(super) fn read(doc: &LoroDoc) -> Result<Vec<DocxStoryBody>> {
    let map = doc.get_map(STORIES);
    let keys = order_ids(&doc.get_list(STORY_ORDER))?;
    let mut seen = HashSet::new();
    let mut stories = Vec::with_capacity(keys.len());
    for key in keys {
        if !seen.insert(key.clone()) {
            return Err(invalid("a story appears twice in the story order"));
        }
        let entry = child_map(&map, &key).ok_or_else(|| invalid("story entry"))?;
        let scope: DocxStoryScope = match string(&entry, SCOPE) {
            Some(stored) if stored == key => {
                serde_json::from_str(&stored).map_err(|_| invalid("story scope"))?
            }
            _ => return Err(invalid("story scope")),
        };
        let blocks = child_map(&entry, BLOCKS).ok_or_else(|| invalid("story blocks"))?;
        let list = child_list(&entry, ORDER).ok_or_else(|| invalid("story order"))?;
        let ids = order_ids(&list)?;
        let mut names = HashSet::new();
        let mut paragraphs = Vec::with_capacity(ids.len());
        for id in ids {
            if !names.insert(id.clone()) {
                return Err(invalid("a story paragraph appears twice in its order"));
            }
            let paragraph = child_map(&blocks, &id).ok_or_else(|| invalid("story paragraph"))?;
            let body =
                loro_text(&paragraph, TEXT).ok_or_else(|| invalid("story paragraph text"))?;
            paragraphs.push(StoryParagraph {
                id,
                locked: string(&paragraph, LOCK).is_some(),
                text: body.to_string(),
                runs: runs(&body)?,
            });
        }
        stories.push(DocxStoryBody {
            scope,
            paragraphs,
            tables: super::story_tables::read(&entry)?,
        });
    }
    Ok(stories)
}

/// Replace one story paragraph's text by its shortest edit.
pub(super) fn set_text(
    doc: &LoroDoc,
    scope: &DocxStoryScope,
    block: &str,
    text: &str,
) -> Result<()> {
    story_line(text)?;
    editable(doc, scope, block)?
        .update(text, UpdateOptions::default())
        .map_err(|_| invalid("story paragraph update"))?;
    Ok(())
}

/// Splice one story paragraph's text; offsets and lengths count Unicode
/// scalar values.
pub(super) fn splice(
    doc: &LoroDoc,
    scope: &DocxStoryScope,
    block: &str,
    at: usize,
    delete: usize,
    insert: &str,
) -> Result<()> {
    story_line(insert)?;
    let body = editable(doc, scope, block)?;
    let end = at
        .checked_add(delete)
        .ok_or_else(|| invalid("story splice range"))?;
    if end > body.len_unicode() {
        return Err(invalid("story splice range"));
    }
    body.delete(at, delete).map_err(loro)?;
    body.insert(at, insert).map_err(loro)?;
    Ok(())
}

/// Turn one inline mark on or off over `len` characters of one story
/// paragraph from `at`, with the body's baseline law.
pub(super) fn set_mark(
    doc: &LoroDoc,
    scope: &DocxStoryScope,
    block: &str,
    at: usize,
    len: usize,
    mark: DocxMark,
    on: bool,
) -> Result<()> {
    let body = editable(doc, scope, block)?;
    let end = at
        .checked_add(len)
        .filter(|end| len > 0 && *end <= body.len_unicode())
        .ok_or_else(|| invalid("story mark range"))?;
    mark_styles(doc);
    if on {
        body.mark(at..end, mark.key(), true).map_err(loro)?;
        if let Some(other) = mark.baseline_pair() {
            body.unmark(at..end, other.key()).map_err(loro)?;
        }
    } else {
        body.unmark(at..end, mark.key()).map_err(loro)?;
    }
    Ok(())
}

/// The story changes that turn the imported `base` into `current`: every
/// changed paragraph as its full current runs. Scope, order, membership or
/// lock drift outside what the story operations express fails closed.
pub(super) fn changes(
    base: &[DocxStoryBody],
    current: &[DocxStoryBody],
) -> Result<Vec<DocxChange>> {
    if base.len() != current.len()
        || base
            .iter()
            .zip(current.iter())
            .any(|(before, after)| before.scope != after.scope)
    {
        return Err(invalid("the body's stories changed shape"));
    }
    let mut changes = Vec::new();
    for (before, after) in base.iter().zip(current.iter()) {
        if before.paragraphs.len() != after.paragraphs.len()
            || before
                .paragraphs
                .iter()
                .zip(after.paragraphs.iter())
                .any(|(was, now)| was.id != now.id)
        {
            return Err(invalid("a story's paragraphs changed shape"));
        }
        for (was, now) in before.paragraphs.iter().zip(after.paragraphs.iter()) {
            if was.locked != now.locked {
                return Err(invalid("a story paragraph's lock changed"));
            }
            if now.locked && (now.text != was.text || now.runs != was.runs) {
                return Err(invalid("a read-only story paragraph changed"));
            }
            // Every changed paragraph exports as its full current runs, even
            // plaintext or empty: the native plain note writer refuses
            // multi-paragraph and empty bodies, and the comment writer
            // settles runs to Normal annotation text.
            if now.runs != was.runs {
                changes.push(DocxChange::SetStoryRuns {
                    scope: after.scope.clone(),
                    block: now.id.clone(),
                    runs: now.runs.clone(),
                });
            }
        }
        changes.extend(super::story_tables::changes(
            &after.scope,
            &before.tables,
            &after.tables,
        )?);
    }
    Ok(changes)
}

/// One editable story paragraph's text.
pub(super) fn story_entry(doc: &LoroDoc, scope: &DocxStoryScope) -> Result<LoroMap> {
    let map = doc.get_map(STORIES);
    let key = scope_key(scope)?;
    let entry = child_map(&map, &key).ok_or_else(|| invalid("no such story in the body"))?;
    if string(&entry, SCOPE).as_deref() != Some(key.as_str()) {
        return Err(invalid("no such story in the body"));
    }
    let order = order_ids(&doc.get_list(STORY_ORDER))?;
    if !order.iter().any(|id| id == &key) {
        return Err(invalid("no such story in the body"));
    }
    Ok(entry)
}

fn editable(doc: &LoroDoc, scope: &DocxStoryScope, block: &str) -> Result<LoroText> {
    let entry = story_entry(doc, scope)?;
    let list = child_list(&entry, ORDER).ok_or_else(|| invalid("story order"))?;
    if !order_ids(&list)?.iter().any(|id| id == block) {
        return Err(invalid("no such story paragraph in the body"));
    }
    let blocks = child_map(&entry, BLOCKS).ok_or_else(|| invalid("story blocks"))?;
    let paragraph = child_map(&blocks, block).ok_or_else(|| invalid("story paragraph"))?;
    if string(&paragraph, LOCK).is_some() {
        return Err(invalid("the story paragraph is read-only in the body"));
    }
    loro_text(&paragraph, TEXT).ok_or_else(|| invalid("story paragraph text"))
}

/// A story paragraph holds one line: a break would be a second paragraph.
/// There is no byte ceiling; the body's per-block ceiling does not extend
/// here.
fn story_line(text: &str) -> Result<()> {
    if text.contains(['\n', '\r']) {
        return Err(invalid("a story paragraph's text holds no line breaks"));
    }
    Ok(())
}

pub(super) fn child_list(map: &LoroMap, key: &str) -> Option<LoroList> {
    match map.get(key)? {
        ValueOrContainer::Container(Container::List(list)) => Some(list),
        _ => None,
    }
}

pub(super) fn order_ids(list: &LoroList) -> Result<Vec<String>> {
    (0..list.len())
        .map(|index| match list.get(index) {
            Some(ValueOrContainer::Value(LoroValue::String(id))) => Ok(id.to_string()),
            _ => Err(invalid("story order entry")),
        })
        .collect()
}
