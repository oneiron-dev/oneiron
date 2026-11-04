//! What an anchor says: the text under a locator in one version's bytes, the
//! exact places those words occur in another version, and how a Word span
//! moves across an edit (OF-368, owner ruling 2026-10-17).
//!
//! An edit inside the commented spot keeps the anchor; only deleting the spot
//! detaches it, and a partial delete shrinks the anchor to what remains. A
//! detached comment keeps a snapshot of its text, so a person can be offered
//! the exact words when they return; nothing here reattaches on a guess.

use std::collections::{BTreeMap, BTreeSet};

use dom_query::{Document, NodeRef};
use similar::{Algorithm, DiffTag, capture_diff_slices};

use oneiron_docedit::retained_opc::{Limits, Package};
use oneiron_docedit::xlsx_body::read_xlsx_cells;
use oneiron_xlsx_formula::cell_display_text;

use super::model::{ANNOTATION_LOCATOR_TEXT_MAX_BYTES, Locator};
use crate::edit_roundtrip::{CellRef, OfficeFormat};

mod xlsx;

use xlsx::{find_in_sheets, xlsx_range_text};

/// Paragraphs joined in a shape's text.
const PARAGRAPH_SEPARATOR: char = '\n';
/// The most places one reattach offer lists.
pub(super) const MAX_OFFERS: usize = 16;

/// The format readers' ceilings, resolved once per sweep from live policy.
#[derive(Clone)]
pub(super) struct TextLimits {
    pub(super) package: Limits,
    pub(super) docx: oneiron_docedit::ArchiveLimits,
}

/// Artifact text formats, with HTML beside the OOXML edit formats (FIX 7905).
#[derive(Clone, Copy)]
pub(super) enum UnitFormat {
    Xlsx,
    Docx,
    Pptx,
    Html,
}

impl UnitFormat {
    pub(super) fn from_media_type(media_type: &str) -> Option<Self> {
        if media_type
            .split(';')
            .next()
            .is_some_and(|base| base.trim().eq_ignore_ascii_case("text/html"))
        {
            return Some(Self::Html);
        }
        match OfficeFormat::from_media_type(media_type).ok()? {
            OfficeFormat::Xlsx => Some(Self::Xlsx),
            OfficeFormat::Docx => Some(Self::Docx),
            OfficeFormat::Pptx => Some(Self::Pptx),
        }
    }
}

/// Whole admitted version bytes, with no second HTML-specific cap (CALLS).
const HTML_READ_WHOLE: bool = true;
const HTML_BLOCK_TAGS: &[&str] = &[
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "blockquote",
    "pre",
    "td",
    "th",
    "figcaption",
    "dt",
    "dd",
];
const HTML_LEAF_CONTAINERS: &[&str] = &[
    "div", "section", "article", "header", "footer", "main", "aside", "figure", "body", "html",
];
const HTML_IGNORED_SUBTREES: &[&str] = &["script", "style", "template", "noscript"];

/// The text under `locator` in `bytes`, or `Ok(None)` when the spot cannot
/// be read. A resource refusal is the engine's error (FIX 10587).
pub(super) fn anchor_text(
    bytes: &[u8],
    locator: &Locator,
    limits: &TextLimits,
) -> crate::Result<Option<String>> {
    match locator {
        Locator::Xlsx { sheet, range } => xlsx_range_text(bytes, sheet, *range, limits),
        Locator::Docx {
            para_path,
            char_start,
            char_end,
        } => {
            let Some(blocks) = docx_blocks(bytes, limits)? else {
                return Ok(None);
            };
            let Some((_, text)) = blocks.iter().find(|(id, _)| id == para_path) else {
                return Ok(None);
            };
            Ok(char_slice(text, *char_start, *char_end))
        }
        Locator::Pptx { slide, shape_id } => {
            let Some(deck) = deck_view(bytes, limits)? else {
                return Ok(None);
            };
            let Ok(number) = usize::try_from(*slide) else {
                return Ok(None);
            };
            let Some(index) = number.checked_sub(1) else {
                return Ok(None);
            };
            let Some(slide) = deck.slides.get(index) else {
                return Ok(None);
            };
            if shape_id == "slide" {
                let texts: Vec<String> = slide.shapes.iter().filter_map(shape_text).collect();
                return Ok(
                    (!texts.is_empty()).then(|| texts.join(&PARAGRAPH_SEPARATOR.to_string()))
                );
            }
            let wanted = guid_key(shape_id);
            let mut matches = slide.shapes.iter().filter(|shape| {
                shape
                    .creation_id
                    .as_deref()
                    .is_some_and(|guid| guid_key(guid) == wanted)
                    || shape.id.is_some_and(|id| id.to_string() == *shape_id)
            });
            let Some(shape) = matches.next() else {
                return Ok(None);
            };
            if matches.next().is_some() {
                return Ok(None);
            }
            Ok(shape_text(shape))
        }
        Locator::Html {
            part_id,
            char_start,
            char_end,
        } => {
            let Some(blocks) = html_blocks(bytes)? else {
                return Ok(None);
            };
            let mut matches = blocks.iter().filter(|block| &block.part_id == part_id);
            let Some(block) = matches.next() else {
                return Ok(None);
            };
            if matches.next().is_some() {
                return Ok(None);
            }
            Ok(char_slice(&block.text, *char_start, *char_end))
        }
        _ => Ok(None),
    }
}

/// Every place in `bytes` that holds exactly `text`, in document order. A
/// sheet offers same-shaped ranges, a Word document every exact run of the
/// words, a deck every shape whose whole text is the words. A resource
/// refusal is the engine's error (FIX 10587).
pub(super) fn find_text(
    bytes: &[u8],
    format: UnitFormat,
    text: &str,
    limits: &TextLimits,
) -> crate::Result<Vec<Locator>> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut found = match format {
        UnitFormat::Xlsx => find_in_sheets(bytes, text, limits)?,
        UnitFormat::Docx => docx_blocks(bytes, limits)?
            .map(|blocks| {
                blocks
                    .iter()
                    .flat_map(|(id, block)| {
                        char_occurrences(block, text)
                            .into_iter()
                            .filter_map(|(start, end)| Locator::docx(id.clone(), start, end).ok())
                    })
                    .collect()
            })
            .unwrap_or_default(),
        UnitFormat::Pptx => deck_view(bytes, limits)?
            .map(|deck| {
                deck.slides
                    .iter()
                    .enumerate()
                    .flat_map(|(index, slide)| {
                        slide.shapes.iter().filter_map(move |shape| {
                            let identity = shape
                                .creation_id
                                .clone()
                                .or_else(|| shape.id.map(|id| id.to_string()))?;
                            (shape_text(shape).as_deref() == Some(text)).then(|| {
                                Locator::pptx(u64::try_from(index).ok()? + 1, identity).ok()
                            })?
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        UnitFormat::Html => html_blocks(bytes)?
            .map(|blocks| {
                let mut counts = BTreeMap::new();
                for block in &blocks {
                    *counts.entry(block.part_id.as_str()).or_insert(0) += 1;
                }
                blocks
                    .iter()
                    .filter(|block| counts.get(block.part_id.as_str()).copied().unwrap_or(0) == 1)
                    .flat_map(|block| {
                        char_occurrences(&block.text, text).into_iter().filter_map(
                            |(start, end)| Locator::html(block.part_id.clone(), start, end).ok(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    found.truncate(MAX_OFFERS);
    Ok(found)
}

/// Moves a Word or HTML span across disjoint character edits. Boundaries
/// inside one changed run move to its edges. A span detaches only when none
/// of its original characters survives; partial deletes shrink it and edits
/// inside a surviving span stay inside its boundaries.
pub(super) fn remap_span(before: &str, after: &str, start: u64, end: u64) -> Option<(u64, u64)> {
    let before: Vec<char> = before.chars().collect();
    let after: Vec<char> = after.chars().collect();
    let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
    if start >= end || end > before.len() {
        return None;
    }
    let edits = capture_diff_slices(Algorithm::Myers, &before, &after);
    let survives = edits.iter().any(|edit| {
        let (tag, old, _) = edit.as_tag_tuple();
        tag == DiffTag::Equal && old.start < end && start < old.end
    });
    if !survives {
        return None;
    }
    let map = |at: usize, trailing: bool| {
        for edit in &edits {
            let (tag, old, new) = edit.as_tag_tuple();
            if at <= old.start {
                return new.start;
            }
            if at < old.end {
                return if tag == DiffTag::Equal {
                    new.start + at - old.start
                } else if trailing {
                    new.end
                } else {
                    new.start
                };
            }
        }
        after.len()
    };
    let (new_start, new_end) = (map(start, false), map(end, true));
    (new_start < new_end).then(|| (new_start as u64, new_end as u64))
}

/// The body paragraphs of a Word document: block id and visible text. Both
/// DOCX reads run in the host's memory (FIX 10651), and a resource refusal is
/// the engine's error (FIX 10587), never `None`.
pub(super) fn docx_blocks(
    bytes: &[u8],
    limits: &TextLimits,
) -> crate::Result<Option<Vec<(String, String)>>> {
    let resources = crate::office_body::document_resources();
    let parsed = resources.docx(|| {
        oneiron_docedit::preflight_with_limits(bytes, limits.docx)?;
        oneiron_docedit::Document::parse(bytes)
    });
    let document = match parsed {
        Ok(document) => document,
        Err(error) => {
            if let Some(refusal) = oneiron_docedit::docx_resource(&error) {
                return Err(crate::office_body::document_refused(refusal));
            }
            return Ok(None);
        }
    };
    Ok(Some(
        document
            .read()
            .blocks
            .into_iter()
            .map(|block| (block.id.to_string(), block.text))
            .collect(),
    ))
}

/// Visible text blocks in an HTML document: stable part id and exact decoded
/// text. Stored bytes never change; structural ids derive from the parse tree.
pub(super) struct HtmlBlock {
    pub(super) part_id: String,
    pub(super) text: String,
    /// A producer's explicit data-part-id, not a derived structural position.
    pub(super) explicit: bool,
}

pub(super) fn html_blocks(bytes: &[u8]) -> crate::Result<Option<Vec<HtmlBlock>>> {
    if !HTML_READ_WHOLE {
        return Ok(None);
    }
    let Ok(html) = std::str::from_utf8(bytes) else {
        return Ok(None);
    };
    let document = Document::from(html);
    let root = document.root();
    let body = {
        let mut pending = vec![root];
        let mut found = None;
        while let Some(node) = pending.pop() {
            if node.node_name().as_deref() == Some("body") {
                found = Some(node);
                break;
            }
            pending.extend(node.element_children());
        }
        found.unwrap_or(root)
    };
    let mut pending = vec![(body, vec![0])];
    let mut candidates = Vec::new();
    while let Some((node, path)) = pending.pop() {
        if html_ignored(&node) {
            continue;
        }
        if html_block_candidate(&node) {
            candidates.push((node, path));
            continue;
        }
        let children = node
            .element_children()
            .into_iter()
            .enumerate()
            .map(|(index, child)| {
                let mut path = path.clone();
                path.push(index);
                (child, path)
            })
            .collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    // Every admitted producer id is reserved before any structural id is
    // allocated, so a structural block never takes a producer's id and the
    // producer's own id stays pinnable.
    let admitted = |node: &NodeRef<'_>| {
        node.attr("data-part-id")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && value.len() <= ANNOTATION_LOCATOR_TEXT_MAX_BYTES)
    };
    let mut used_ids = BTreeSet::new();
    for (node, _) in &candidates {
        if let Some(id) = admitted(node) {
            used_ids.insert(id);
        }
    }
    let mut blocks = Vec::new();
    for (node, path) in candidates {
        let (part_id, explicit) = match admitted(&node) {
            Some(id) => {
                used_ids.insert(id.clone());
                (id, true)
            }
            _ => {
                let ordinals = path
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(".");
                let tag = node.node_name().unwrap_or_else(|| "block".into());
                let base = format!("{tag}/{ordinals}");
                let mut structural = base.clone();
                let mut collision = 0;
                while !used_ids.insert(structural.clone()) {
                    collision += 1;
                    structural = format!("{base}#{collision}");
                }
                (structural, false)
            }
        };
        blocks.push(HtmlBlock {
            part_id,
            text: html_text(node),
            explicit,
        });
    }
    if blocks.is_empty() {
        return Ok(None);
    }
    Ok(Some(blocks))
}

fn html_ignored(node: &NodeRef<'_>) -> bool {
    node.node_name()
        .is_some_and(|name| HTML_IGNORED_SUBTREES.contains(&name.as_ref()))
}

fn html_block_candidate(node: &NodeRef<'_>) -> bool {
    let Some(name) = node.node_name() else {
        return false;
    };
    if HTML_BLOCK_TAGS.contains(&name.as_ref()) {
        return true;
    }
    if !HTML_LEAF_CONTAINERS.contains(&name.as_ref()) {
        return false;
    }
    let mut pending = node.element_children();
    while let Some(child) = pending.pop() {
        if html_ignored(&child) {
            continue;
        }
        if child.node_name().is_some_and(|name| {
            HTML_BLOCK_TAGS.contains(&name.as_ref())
                || HTML_LEAF_CONTAINERS.contains(&name.as_ref())
        }) {
            return false;
        }
        pending.extend(child.element_children());
    }
    true
}

fn html_text(node: NodeRef<'_>) -> String {
    let mut out = String::new();
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        if html_ignored(&node) {
            continue;
        }
        if node.is_text() {
            out.push_str(&node.text());
            continue;
        }
        let children = node.children_it(false).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    out
}

/// The deck's typed view. A resource refusal is the engine's error
/// (FIX 10587), never `None`.
fn deck_view(
    bytes: &[u8],
    limits: &TextLimits,
) -> crate::Result<Option<oneiron_docedit::deck::DeckView>> {
    let package = match Package::open(
        bytes,
        limits.package,
        &crate::office_body::document_resources(),
    ) {
        Ok(package) => package,
        Err(error) => {
            if let Some(refusal) = error.resource() {
                return Err(crate::office_body::document_refused(refusal));
            }
            return Ok(None);
        }
    };
    match oneiron_docedit::deck::DeckView::read(&package) {
        Ok(view) => Ok(Some(view)),
        Err(error) => {
            if let Some(refusal) = error.resource() {
                return Err(crate::office_body::document_refused(refusal));
            }
            Ok(None)
        }
    }
}

fn shape_text(shape: &oneiron_docedit::deck::ShapeView) -> Option<String> {
    let text = shape.text.as_ref()?;
    let paragraphs: Vec<String> = text
        .paragraphs
        .iter()
        .map(|paragraph| paragraph.runs.iter().map(|run| run.text.as_str()).collect())
        .collect();
    let joined = paragraphs.join(&PARAGRAPH_SEPARATOR.to_string());
    (!joined.trim().is_empty()).then_some(joined)
}

fn guid_key(text: &str) -> String {
    text.trim_matches(|c| c == '{' || c == '}')
        .to_ascii_uppercase()
}

fn char_slice(text: &str, start: u64, end: u64) -> Option<String> {
    let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
    let chars: Vec<char> = text.chars().collect();
    (start < end && end <= chars.len()).then(|| chars[start..end].iter().collect())
}

/// Every non-overlapping exact occurrence of `needle`, in characters.
fn char_occurrences(haystack: &str, needle: &str) -> Vec<(u64, u64)> {
    let len = needle.chars().count() as u64;
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(found) = haystack[from..].find(needle) {
        let byte = from + found;
        let start = haystack[..byte].chars().count() as u64;
        out.push((start, start + len));
        from = byte + needle.len().max(1);
        if out.len() >= MAX_OFFERS {
            break;
        }
    }
    out
}

/// The units the existing office readers can address, in document order.
/// This reads the same blocks, displayed cells and slide-scoped shape identities
/// as anchor_text; unsupported artifact kinds have no implied adapter here.
/// A resource refusal is the engine's error (FIX 10587), never `None`.
pub(super) fn unit_texts(
    bytes: &[u8],
    format: UnitFormat,
    limits: &TextLimits,
) -> crate::Result<Option<Vec<(Locator, Option<String>)>>> {
    match format {
        UnitFormat::Docx => {
            let Some(blocks) = docx_blocks(bytes, limits)? else {
                return Ok(None);
            };
            Ok(blocks
                .into_iter()
                .map(|(path, text)| {
                    let end = text.chars().count() as u64;
                    let locator = Locator::docx(path, 0, end).ok()?;
                    Some((locator, (end > 0).then_some(text)))
                })
                .collect())
        }
        UnitFormat::Xlsx => {
            let book = match read_xlsx_cells(
                bytes,
                limits.package,
                &crate::office_body::document_resources(),
            ) {
                Ok(book) => book,
                Err(error) => {
                    if let Some(refusal) = error.resource() {
                        return Err(crate::office_body::document_refused(refusal));
                    }
                    return Ok(None);
                }
            };
            let mut units = Vec::new();
            for sheet in &book.sheets {
                for cell in &sheet.cells {
                    let address = CellRef {
                        col: cell.col,
                        row: cell.row,
                    }
                    .to_a1();
                    let Ok(locator) = Locator::xlsx(sheet.name.clone(), &address) else {
                        return Ok(None);
                    };
                    let text = cell_display_text(&book, cell);
                    units.push((locator, (!text.trim().is_empty()).then_some(text)));
                }
            }
            Ok(Some(units))
        }
        UnitFormat::Pptx => {
            let Some(deck) = deck_view(bytes, limits)? else {
                return Ok(None);
            };
            let mut units = Vec::new();
            for (index, slide) in deck.slides.iter().enumerate() {
                for shape in &slide.shapes {
                    let Some(identity) = shape
                        .creation_id
                        .clone()
                        .or_else(|| shape.id.map(|id| id.to_string()))
                    else {
                        continue;
                    };
                    let wanted = guid_key(&identity);
                    let matches = slide
                        .shapes
                        .iter()
                        .filter(|candidate| {
                            candidate
                                .creation_id
                                .as_deref()
                                .is_some_and(|guid| guid_key(guid) == wanted)
                                || candidate.id.is_some_and(|id| id.to_string() == identity)
                        })
                        .count();
                    let Ok(locator) = Locator::pptx(index as u64 + 1, identity) else {
                        return Ok(None);
                    };
                    let quote = (matches == 1).then(|| shape_text(shape)).flatten();
                    units.push((locator, quote));
                }
            }
            Ok(Some(units))
        }
        UnitFormat::Html => {
            let Some(blocks) = html_blocks(bytes)? else {
                return Ok(None);
            };
            let mut counts = BTreeMap::new();
            for block in &blocks {
                *counts.entry(block.part_id.clone()).or_insert(0) += 1;
            }
            Ok(blocks
                .into_iter()
                .map(|block| {
                    let matches = counts.get(block.part_id.as_str()).copied().unwrap_or(0);
                    let end = block.text.chars().count() as u64;
                    let locator = Locator::html(block.part_id.clone(), 0, end).ok()?;
                    let quote = (matches == 1 && end > 0).then_some(block.text);
                    Some((locator, quote))
                })
                .collect())
        }
    }
}
