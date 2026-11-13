//! What an anchor says: the text under a locator in one version's bytes, the
//! exact places those words occur in another version, and how a Word span
//! moves across an edit (OF-368, owner ruling 2026-10-17).
//!
//! An edit inside the commented spot keeps the anchor; only deleting the spot
//! detaches it, and a partial delete shrinks the anchor to what remains.
//! Rewriting the spot's words deletes it: a rewritten sentence detaches. A
//! detached comment keeps a snapshot of its text, so a person can be offered
//! the exact words when they return; nothing here reattaches on a guess.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use dom_query::{Document, NodeRef};
use similar::{Algorithm, DiffTag, capture_diff_slices};

use oneiron_docedit::retained_opc::{Limits, Package};
use oneiron_docedit::xlsx_body::read_xlsx_cells;
use oneiron_xlsx_formula::cell_display_text;

use super::model::{ANNOTATION_LOCATOR_TEXT_MAX_BYTES, Locator};
use crate::edit_roundtrip::{CellRef, OfficeFormat};
use crate::file_secret_marks::FILLER;

pub(super) mod stories;
mod text;
mod xlsx;

pub(super) use text::{TextReanchor, decoded, remap_text_span, text_span, text_units};
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

/// Artifact text formats, with HTML and plain text beside the OOXML edit
/// formats (FIX 7905).
#[derive(Clone, Copy)]
pub(super) enum UnitFormat {
    Xlsx,
    Docx,
    Pptx,
    Html,
    Text,
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
        match OfficeFormat::from_media_type(media_type).ok() {
            Some(OfficeFormat::Xlsx) => Some(Self::Xlsx),
            Some(OfficeFormat::Docx) => Some(Self::Docx),
            Some(OfficeFormat::Pptx) => Some(Self::Pptx),
            None => text::is_text_media_type(media_type).then_some(Self::Text),
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
/// be read. A code locator's `bytes` are the file it names. A resource
/// refusal is the engine's error (FIX 10587).
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
        Locator::DocxStory {
            scope,
            para_path,
            char_start,
            char_end,
        } => {
            let Some(stories) = stories::units(bytes, limits)? else {
                return Ok(None);
            };
            let units = crate::office_body::DocxUnits {
                blocks: Vec::new(),
                stories,
            };
            let Some(paragraphs) = units.story(scope) else {
                return Ok(None);
            };
            let Some((_, text)) = paragraphs.iter().find(|(id, _)| id == para_path) else {
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
        Locator::Text {
            char_start,
            char_end,
        }
        | Locator::Code {
            char_start,
            char_end,
            ..
        } => Ok(text::text_span(bytes, *char_start, *char_end)),
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
        UnitFormat::Docx => {
            let mut found: Vec<Locator> =
                docx_blocks(bytes, limits)?
                    .map(|blocks| {
                        blocks
                            .iter()
                            .flat_map(|(id, block)| {
                                char_occurrences(block, text).into_iter().filter_map(
                                    |(start, end)| Locator::docx(id.clone(), start, end).ok(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
            if let Some(read) = stories::units(bytes, limits)? {
                for story in &read {
                    if read
                        .iter()
                        .filter(|other| other.scope == story.scope)
                        .count()
                        != 1
                    {
                        continue;
                    }
                    for (id, paragraph) in &story.paragraphs {
                        found.extend(char_occurrences(paragraph, text).into_iter().filter_map(
                            |(start, end)| {
                                Locator::docx_story(story.scope.clone(), id.clone(), start, end)
                                    .ok()
                            },
                        ));
                    }
                }
            }
            found
        }
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
        UnitFormat::Text => text::find_in_text(bytes, text),
    };
    found.truncate(MAX_OFFERS);
    Ok(found)
}

/// Moves a Word or HTML span across an edit, by a character diff of the two
/// texts; [`span_after_edits`] holds the rule.
pub(super) fn remap_span(before: &str, after: &str, start: u64, end: u64) -> Option<(u64, u64)> {
    let before: Vec<char> = before.chars().collect();
    let after: Vec<char> = after.chars().collect();
    let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
    if start >= end || end > before.len() {
        return None;
    }
    let edits: Vec<CharEdit> = capture_diff_slices(Algorithm::Myers, &before, &after)
        .iter()
        .map(|edit| edit.as_tag_tuple())
        .collect();
    span_after_edits(&before, &after, &edits, start, end)
}

/// One step of a character diff: its kind, its old range and its new range.
type CharEdit = (DiffTag, Range<usize>, Range<usize>);

/// Moves the span `start..end` of `before` onto `after` across `edits`, a
/// character diff of the two texts in order. Boundaries inside one changed
/// run move to its edges. Text inserted right at a boundary stays outside
/// the span, and text inserted inside it joins it. The span keeps its
/// anchor while its words survive ([`words_survive`]): a partial delete
/// shrinks it and a small edit keeps it, but a span whose words were
/// rewritten detaches, however many letters the new words share with the
/// old ones (OF-368; ARCH-0075: no selection is invented).
fn span_after_edits(
    before: &[char],
    after: &[char],
    edits: &[CharEdit],
    start: usize,
    end: usize,
) -> Option<(u64, u64)> {
    let map = |at: usize, trailing: bool| {
        for (tag, old, new) in edits {
            if !trailing && *tag == DiffTag::Insert && old.start == at {
                continue;
            }
            if at <= old.start {
                return new.start;
            }
            if at < old.end {
                return if *tag == DiffTag::Equal {
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
    if new_start >= new_end {
        return None;
    }
    let survives = words_survive(
        before,
        after,
        word_extent(before, start..end),
        word_extent(after, new_start..new_end),
    )
    .unwrap_or_else(|| {
        edits
            .iter()
            .any(|(tag, old, _)| *tag == DiffTag::Equal && old.start < end && start < old.end)
    });
    survives.then_some((new_start as u64, new_end as u64))
}

/// Whether a span's words survive an edit. `old` and `new` are the span
/// before and after it, each widened to whole words. Words are diffed as
/// wholes, so a letter matched inside another word never keeps a span. A
/// word counts as kept when it is unchanged, or when it is replaced one for
/// one by a word that keeps more than half of its letters (a typo fix); a
/// word deleted outright counts neither way. The span survives while its
/// kept words are at least as many as its replaced ones. `None` when the
/// span holds no word: its characters decide.
fn words_survive(
    before: &[char],
    after: &[char],
    old: Range<usize>,
    new: Range<usize>,
) -> Option<bool> {
    let old_words: Vec<&[char]> = words(before, old).into_iter().map(|w| &before[w]).collect();
    if old_words.is_empty() {
        return None;
    }
    let new_words: Vec<&[char]> = words(after, new).into_iter().map(|w| &after[w]).collect();
    let (mut kept, mut replaced) = (0_usize, 0_usize);
    for edit in capture_diff_slices(Algorithm::Myers, &old_words, &new_words) {
        let (tag, was, now) = edit.as_tag_tuple();
        match tag {
            DiffTag::Equal => kept += was.len(),
            DiffTag::Delete | DiffTag::Insert => {}
            DiffTag::Replace => {
                for (at, word) in old_words[was].iter().enumerate() {
                    if at < now.len() && keeps_most_letters(word, new_words[now.start + at]) {
                        kept += 1;
                    } else {
                        replaced += 1;
                    }
                }
            }
        }
    }
    Some(kept > 0 && kept >= replaced)
}

/// Whether `new` keeps more than half of `old`'s letters, counted against
/// the longer of the two words.
fn keeps_most_letters(old: &[char], new: &[char]) -> bool {
    let shared: usize = capture_diff_slices(Algorithm::Myers, old, new)
        .iter()
        .filter(|edit| edit.tag() == DiffTag::Equal)
        .map(|edit| edit.old_range().len())
        .sum();
    2 * shared > old.len().max(new.len())
}

/// The words in `text[range]`, as ranges: runs of letters and digits, with
/// each CJK character a word of its own.
fn words(text: &[char], range: Range<usize>) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut at = range.start;
    while at < range.end {
        if joins_word(text[at]) {
            let from = at;
            while at < range.end && joins_word(text[at]) {
                at += 1;
            }
            out.push(from..at);
        } else {
            if text[at].is_alphanumeric() {
                out.push(at..at + 1);
            }
            at += 1;
        }
    }
    out
}

/// `range` widened to whole words of `text`.
fn word_extent(text: &[char], range: Range<usize>) -> Range<usize> {
    let (mut start, mut end) = (range.start, range.end);
    while inside_word(text, start) {
        start -= 1;
    }
    while inside_word(text, end) {
        end += 1;
    }
    start..end
}

/// Whether offset `at` falls between two letters of one word.
fn inside_word(text: &[char], at: usize) -> bool {
    at > 0 && at < text.len() && joins_word(text[at - 1]) && joins_word(text[at])
}

/// A letter or digit that runs on into its neighbours. Kana and CJK
/// ideographs stand alone: those scripts put no space between words.
fn joins_word(c: char) -> bool {
    c.is_alphanumeric()
        && !matches!(
            u32::from(c),
            0x3040..=0x30FF | 0x31F0..=0x31FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF
                | 0xF900..=0xFAFF | 0x2_0000..=0x3_134F
        )
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

/// Raw and caller-sighted plain text when both decode and the sighted copy
/// preserves the raw character layout. Raw coordinates always name the
/// immutable version; only the quote is projected to the caller's sight.
fn text_layout_for_sight<'a>(
    raw_bytes: &'a [u8],
    sighted_bytes: &'a [u8],
) -> Option<(&'a str, &'a str)> {
    let raw = text::decoded(raw_bytes)?;
    let sighted = text::decoded(sighted_bytes)?;
    if raw_bytes != sighted_bytes
        && (sighted.len() != raw.len()
            || sighted
                .bytes()
                .zip(raw.bytes())
                .any(|(masked, raw)| masked != raw && masked != FILLER))
    {
        // A rebuilt container has no raw coordinate map. Do not serve nearby
        // text as though it were the requested immutable span.
        return None;
    }
    Some((raw, sighted))
}

/// The exact byte range of a non-empty character span in decoded text.
fn text_span_byte_range(
    raw: &str,
    char_start: u64,
    char_end: u64,
) -> Option<std::ops::Range<usize>> {
    let (start, end) = (
        usize::try_from(char_start).ok()?,
        usize::try_from(char_end).ok()?,
    );
    if start >= end {
        return None;
    }
    let len = raw.chars().count();
    if end > len {
        return None;
    }
    let byte_start = raw.char_indices().nth(start).map(|(at, _)| at)?;
    let byte_end = if end == len {
        raw.len()
    } else {
        raw.char_indices().nth(end).map(|(at, _)| at)?
    };
    Some(byte_start..byte_end)
}

/// The raw byte range of a text locator, including any BOM excluded from the
/// locator's character coordinates. Secret marks use these stored byte offsets.
pub(super) fn text_raw_span_byte_range(
    raw_bytes: &[u8],
    char_start: u64,
    char_end: u64,
) -> Option<std::ops::Range<usize>> {
    let raw = text::decoded(raw_bytes)?;
    let bom_len = if raw_bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        '\u{feff}'.len_utf8()
    } else {
        0
    };
    let span = text_span_byte_range(raw, char_start, char_end)?;
    Some(span.start + bom_len..span.end + bom_len)
}

/// The quote at a raw text-locator span as the caller's sighted copy renders
/// it. The owner and granted sights pass the stored bytes back; a masked
/// reader gets only the exact sighted span, never raw secret bytes.
pub(super) fn text_quote_for_sight(
    raw_bytes: &[u8],
    sighted_bytes: &[u8],
    char_start: u64,
    char_end: u64,
) -> Option<String> {
    let (raw, sighted) = text_layout_for_sight(raw_bytes, sighted_bytes)?;
    let span = text_span_byte_range(raw, char_start, char_end)?;
    Some(sighted[span].to_owned())
}

/// Main's one-unit-per-line text projection, with every quote read through
/// the caller's sight while every locator keeps its raw coordinates.
pub(super) fn text_units_for_sight(
    raw_bytes: &[u8],
    sighted_bytes: &[u8],
) -> Option<Vec<(Locator, Option<String>)>> {
    Some(
        text::text_units(raw_bytes)?
            .into_iter()
            .map(|(locator, _)| {
                let quote = match &locator {
                    Locator::Text {
                        char_start,
                        char_end,
                    } => text_quote_for_sight(raw_bytes, sighted_bytes, *char_start, *char_end),
                    _ => None,
                };
                (locator, quote)
            })
            .collect(),
    )
}

/// Exact matches in the projected head, named in raw text coordinates. Both
/// the detached snapshot and head are read as this caller sees them; a masked
/// match that is not on raw character boundaries is skipped.
pub(super) fn text_find_text_for_sight(
    raw_bytes: &[u8],
    sighted_bytes: &[u8],
    words: &str,
) -> Vec<Locator> {
    if words.trim().is_empty() {
        return Vec::new();
    }
    let Some((raw, sighted)) = text_layout_for_sight(raw_bytes, sighted_bytes) else {
        return Vec::new();
    };
    if raw_bytes == sighted_bytes {
        return text::find_in_text(raw_bytes, words)
            .into_iter()
            .take(MAX_OFFERS)
            .collect();
    }
    let mut out = Vec::new();
    for (byte_start, matched) in sighted.match_indices(words) {
        let byte_end = byte_start + matched.len();
        if !raw.is_char_boundary(byte_start) || !raw.is_char_boundary(byte_end) {
            continue;
        }
        let start = raw[..byte_start].chars().count() as u64;
        let end = raw[..byte_end].chars().count() as u64;
        if start >= end {
            continue;
        }
        if let Ok(locator) = Locator::text(start, end) {
            out.push(locator);
            if out.len() >= MAX_OFFERS {
                break;
            }
        }
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
            let Some(mut units): Option<Vec<_>> = blocks
                .into_iter()
                .map(|(path, text)| {
                    let end = text.chars().count() as u64;
                    let locator = Locator::docx(path, 0, end).ok()?;
                    Some((locator, (end > 0).then_some(text)))
                })
                .collect()
            else {
                return Ok(None);
            };
            if let Some(read) = stories::units(bytes, limits)? {
                for story in &read {
                    let unique = read
                        .iter()
                        .filter(|other| other.scope == story.scope)
                        .count()
                        == 1;
                    for (id, paragraph) in &story.paragraphs {
                        let end = paragraph.chars().count() as u64;
                        let locator = Locator::docx_story(story.scope.clone(), id.clone(), 0, end)?;
                        units.push((locator, (unique && end > 0).then(|| paragraph.clone())));
                    }
                }
            }
            Ok(Some(units))
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
        UnitFormat::Text => Ok(text::text_units(bytes)),
    }
}
