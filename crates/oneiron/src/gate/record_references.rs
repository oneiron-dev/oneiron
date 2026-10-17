//! OF-063: one check that every record a write names resolves for its writer.
//!
//! The owner's ruling (2026-10-17): check that the records an AI says it
//! created, or cites, really exist; refuse invented ones and log the refusal.
//!
//! A verb-table row declares its typed ref slots as JSON pointers (`refs` in
//! `scripts/sdk/agent-verbs.json`, where `*` takes every item of an array).
//! The row's generated engine fn calls [`admit_row_references`] before the
//! engine call, so every door that reaches the row (the HTTP facade, the MCP
//! dispatch, code mode and the SDK) meets this check once, and no door
//! carries a second, hand-written one.
//!
//! Every named ref must resolve under the WRITER's own scoped read. An
//! invented ref, a missing record and a record the writer may not read are
//! one refusal, so the writer learns nothing it could not read. The refusal
//! names the field pointer, never the ref, and it is receipted on its own
//! write ([`crate::receipt::ReceiptKind::ReferenceRefusal`]) before the
//! caller hears it. The refused write never runs. Inside an anonymous
//! off-record session the refusal stands but no receipt is written (Engine
//! ruling 10-17, matching OF-538).
//!
//! Only typed slots carry authority. Prose links (OF-063 prose links:
//! Engine ruling 10-17) are the one exception this file reads in text, and
//! only for display: [`parse_record_links`] finds Markdown links
//! `[label](oneiron://<ref>)`, reference-style links `[label][id]` with an
//! `[id]: oneiron://<ref>` definition, and autolinks `<oneiron://<ref>>`
//! (Engine ruling 10-18), outside code spans, fences, indented code and raw
//! HTML, bounded in count and length. A reader's link resolves under the
//! reader's own read (`vault.refs.links`, through the `vault.refs.resolve`
//! door); an AI-written link that does not resolve for its writer never
//! refuses or rewrites the text, it leaves the same reference-refusal receipt
//! with the outcome `unlinked` ([`unlinked_prose_links`]). The receipt
//! means landed speech only (Engine ruling 10-18): the links are read before
//! the engine call, and the receipt is written only once that call has
//! landed the text ([`receipt_landed_prose`]), so an attempt that never
//! lands leaves none. The witness program reads every AI-written message it
//! lands this way, whatever door it came through ([`witness_prose_unlinked`]),
//! and a streamed continuation its appended text ([`prose_text_unlinked`]).
//! No grant, scope or authority path reads a prose link.

mod blocks;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde_json::Value;

use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVENTED_REFERENCE, MEMORY_CODE_NOT_FOUND, Memory,
    MemoryError, MemoryResult,
};
use crate::receipt::{ReferenceOutcome, ReferenceRefusalFacts, receipt_reference_refusals};

/// One ref a write names, at the concrete pointer of its slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedRecordRef {
    /// The slot's concrete JSON pointer (`/edges/2/target_ref`).
    pub(crate) pointer: String,
    /// The ref as the caller wrote it.
    pub(crate) reference: String,
}

/// Why a write's named refs were not admitted.
#[derive(Debug)]
pub(crate) enum ReferenceRefusal {
    /// The ref at `pointer` names no record the writer may read: invented,
    /// missing and unreadable are this one refusal.
    Unresolved { pointer: String },
    /// The writer's read itself failed, so no ref was judged.
    Read(MemoryError),
}

/// Checks that every ref in `refs` resolves under `read`, the writer's own
/// scoped read. The first ref that does not is the refusal; a ref named twice
/// is read once.
pub(crate) fn validate_record_references(
    read: &Memory<'_>,
    refs: &[NamedRecordRef],
) -> Result<(), ReferenceRefusal> {
    let mut judged = BTreeSet::new();
    for named in refs {
        if !judged.insert(named.reference.as_str()) {
            continue;
        }
        let resolves = match read.get_entity(&named.reference) {
            Ok(result) => result.value.is_some(),
            Err(error)
                if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
            {
                false
            }
            Err(error) => return Err(ReferenceRefusal::Read(error)),
        };
        if !resolves {
            return Err(ReferenceRefusal::Unresolved {
                pointer: named.pointer.clone(),
            });
        }
    }
    Ok(())
}

/// The string refs `input` holds at `pointers`, in pointer order. A slot that
/// is absent, null or not a string names no ref; `*` takes every item of an
/// array, and its concrete index goes into the slot's pointer.
pub(crate) fn record_references_at(input: &Value, pointers: &[&str]) -> Vec<NamedRecordRef> {
    let mut refs = Vec::new();
    for pointer in pointers {
        let segments: Vec<&str> = pointer.split('/').skip(1).collect();
        collect_at(input, &segments, String::new(), &mut refs);
    }
    refs
}

fn collect_at(value: &Value, segments: &[&str], at: String, refs: &mut Vec<NamedRecordRef>) {
    let Some((head, rest)) = segments.split_first() else {
        if let Value::String(reference) = value {
            refs.push(NamedRecordRef {
                pointer: at,
                reference: reference.clone(),
            });
        }
        return;
    };
    if *head == "*" {
        if let Value::Array(items) = value {
            for (index, item) in items.iter().enumerate() {
                collect_at(item, rest, format!("{at}/{index}"), refs);
            }
        }
        return;
    }
    if let Some(child) = value.as_object().and_then(|members| members.get(*head)) {
        collect_at(child, rest, format!("{at}/{head}"), refs);
    }
}

/// The generated check one verb-table row with `refs` runs before its engine
/// call: every ref `input` names at `pointers` must resolve for `memory`'s
/// writer. A refusal is receipted on its own write, naming the actor, `row`,
/// the field pointer and the time, and only then returned as
/// [`MEMORY_CODE_INVENTED_REFERENCE`]; if the receipt cannot be written the
/// store's error is returned instead, never a refusal claiming it was logged.
/// Inside an anonymous off-record session the refusal is returned with no
/// receipt, and says so.
pub(crate) fn admit_row_references<T: serde::Serialize>(
    memory: &Memory<'_>,
    row: &'static str,
    input: &T,
    pointers: &[&str],
) -> MemoryResult<()> {
    let value = serde_json::to_value(input).map_err(|_| {
        MemoryError::bad_request("the verb input could not be read for the records it names")
    })?;
    let refs = record_references_at(&value, pointers);
    match validate_record_references(memory, &refs) {
        Ok(()) => Ok(()),
        Err(ReferenceRefusal::Read(error)) => Err(error),
        Err(ReferenceRefusal::Unresolved { pointer }) => {
            let recorded = receipt_reference_refusals(
                memory,
                &[ReferenceRefusalFacts {
                    actor: memory.actor(),
                    actor_class: memory.actor_class(),
                    row,
                    field: pointer.clone(),
                    outcome: ReferenceOutcome::Refused,
                }],
            )?;
            Err(invented_reference(&pointer, recorded))
        }
    }
}

/// The refusal a write naming an unresolved record ref gets: the field
/// pointer, never the ref. `recorded` says whether the refusal was
/// receipted; inside an anonymous off-record session it never is.
pub(crate) fn invented_reference(pointer: &str, recorded: bool) -> MemoryError {
    let kept = if recorded {
        "the refusal receipted"
    } else {
        "no record kept, as this anonymous session keeps none"
    };
    MemoryError::new(
        MEMORY_CODE_INVENTED_REFERENCE,
        format!(
            "the record named at `{pointer}` does not resolve for this writer; the write was refused and {kept}"
        ),
        &[
            "Name only records this writer can read, by the ref the engine issued (a short id or a 32-hex id).",
            "A missing record and one this writer may not read give this same refusal.",
        ],
    )
}

/// The scheme a prose record link names its ref with.
pub(crate) const PROSE_LINK_SCHEME: &str = "oneiron://";
/// The most links one text is read for; any past them stay plain text.
pub(crate) const MAX_PROSE_LINKS: usize = 64;
/// The most bytes of one text read for links; links past them stay plain text.
pub(crate) const MAX_PROSE_SCAN_BYTES: usize = 128 * 1024;
/// The longest link label read, in bytes.
pub(crate) const MAX_PROSE_LINK_LABEL_BYTES: usize = 512;
/// The most text slots one write is read for links.
const MAX_PROSE_SLOTS: usize = 256;
/// How deep an opaque value is walked for its text.
const MAX_PROSE_DEPTH: usize = 32;

/// One Markdown record link in a text: `[label](oneiron://<ref>)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProseLink {
    /// Byte offset of the link's `[`.
    pub(crate) start: usize,
    /// Byte offset just past the link's `)`.
    pub(crate) end: usize,
    /// The label as written, between the brackets.
    pub(crate) label: String,
    /// The ref after `oneiron://`, as written.
    pub(crate) reference: String,
}

/// The `oneiron://` Markdown links in `text`, in order: at most
/// [`MAX_PROSE_LINKS`], read from its first [`MAX_PROSE_SCAN_BYTES`] bytes.
///
/// Fenced code blocks (```` ``` ```` or `~~~`, indented at most three
/// spaces), indented code blocks (four columns in, where no paragraph
/// continues), raw HTML blocks and inline raw HTML (a tag, comment,
/// processing instruction, declaration or CDATA section) and inline code
/// spans are skipped, as are an escaped `[` and an image (`![...](...)`).
/// Every indentation is measured from the content column of the list item a
/// line sits in, so a line indented under a list item is that item's text
/// and only one four columns past its content is code. A code span closes
/// within its paragraph: it never crosses a blank line or a line that opens
/// another block, and an unclosed backtick run is plain text.
/// Reference-style links are links too (Engine ruling 10-18): a full
/// `[label][id]`, a collapsed `[id][]` and a shortcut `[id]` (not followed by
/// `(`), each naming a definition `[id]: oneiron://<ref>` (or
/// `[id]: <oneiron://<ref>>`, with an optional title) on one line at the
/// start of a paragraph or after another definition. Ids match as CommonMark
/// matches them (trimmed, inner blanks collapsed, case folded); the first
/// definition of an id wins, and an id with no `oneiron://` definition links
/// nothing. So is an autolink `<oneiron://<ref>>`, whose label is its URI as
/// written. A label holds no bracket or line break; a ref is 1 to 256
/// printable ASCII bytes with no parenthesis, angle bracket, bracket, quote
/// or backslash. The parse is display data only: nothing it finds is ever
/// authority.
pub(crate) fn parse_record_links(text: &str) -> Vec<ProseLink> {
    parse_prose_links(text).links
}

/// One text's record links and its `oneiron://` link reference definitions.
pub(crate) struct ProseLinks {
    /// The links, as [`parse_record_links`] gives them.
    pub(crate) links: Vec<ProseLink>,
    /// Each definition's byte range, from its `[` to its line's end, in
    /// order. A definition is shown to no reader: it is never text.
    pub(crate) definitions: Vec<Range<usize>>,
}

/// [`parse_record_links`], with the definitions the text holds.
pub(crate) fn parse_prose_links(text: &str) -> ProseLinks {
    let bytes = text.as_bytes();
    let scan_end = bytes.len().min(MAX_PROSE_SCAN_BYTES);
    let defined = definitions(text, scan_end);
    let mut links = Vec::new();
    let mut blocks = blocks::Blocks::default();
    // Where the current paragraph ends, found at its first backtick run, and
    // the run lengths with no closing run before it after a point already
    // tried.
    let mut paragraph_end: Option<usize> = None;
    let mut unclosed = BTreeSet::new();
    let mut line_start = true;
    let mut at = 0;
    while at < scan_end && links.len() < MAX_PROSE_LINKS {
        if line_start {
            line_start = false;
            let line_end = line_end_at(bytes, at, scan_end);
            match blocks.line(&bytes[at..line_end]) {
                blocks::Line::Skip => {
                    at = line_end;
                    continue;
                }
                blocks::Line::Inline {
                    from,
                    starts_paragraph,
                    heading,
                } => {
                    if starts_paragraph {
                        paragraph_end = heading.then_some(line_end);
                        unclosed.clear();
                    }
                    if defined.lines.contains_key(&at) {
                        at = line_end;
                        continue;
                    }
                    at += from;
                    continue;
                }
            }
        }
        match bytes[at] {
            b'\n' => {
                line_start = true;
                at += 1;
            }
            b'\\' => {
                at += if bytes.get(at + 1) == Some(&b'\n') {
                    1
                } else {
                    2
                }
            }
            b'`' => {
                let run = bytes[at..scan_end]
                    .iter()
                    .take_while(|&&byte| byte == b'`')
                    .count();
                let open_end = at + run;
                let end = match paragraph_end {
                    Some(end) if end > at => end,
                    _ => {
                        unclosed.clear();
                        let end = blocks
                            .paragraph_end(&bytes[..scan_end], line_end_at(bytes, at, scan_end));
                        paragraph_end = Some(end);
                        end
                    }
                };
                at = if unclosed.contains(&run) {
                    open_end
                } else if let Some(close_end) = closing_backticks(&bytes[..end], open_end, run) {
                    close_end
                } else {
                    unclosed.insert(run);
                    open_end
                };
            }
            b'!' if bytes.get(at + 1) == Some(&b'[') => {
                // A reference image's id is no shortcut link either.
                at = match label_close(&bytes[..scan_end], at + 1) {
                    Some(close) if bytes.get(close + 1) == Some(&b'[') => {
                        label_close(&bytes[..scan_end], close + 1).map_or(close + 1, |end| end + 1)
                    }
                    _ => at + 2,
                };
            }
            b'<' => match autolink_at(text, at, scan_end) {
                Some(link) => {
                    at = link.end;
                    links.push(link);
                }
                None => {
                    at += inline_html(&bytes[at..line_end_at(bytes, at, scan_end)]).unwrap_or(1);
                }
            },
            b'[' => match link_at(text, at, scan_end)
                .or_else(|| reference_link_at(text, at, scan_end, &defined.labels))
            {
                Some(link) => {
                    at = link.end;
                    links.push(link);
                }
                None => at += 1,
            },
            _ => at += 1,
        }
    }
    ProseLinks {
        links,
        definitions: defined.lines.into_values().collect(),
    }
}

/// A text's `oneiron://` link reference definitions.
#[derive(Default)]
struct Definitions {
    /// Each matched id's ref; the first definition of an id wins.
    labels: BTreeMap<String, String>,
    /// Each definition's range, keyed by the byte its line starts at.
    lines: BTreeMap<usize, Range<usize>>,
}

/// The definitions in `text`'s first `scan_end` bytes, read line by line
/// through the same block structure the link scan reads: a definition sits
/// on one inline line that opens a paragraph, or follows another
/// definition, since a definition never interrupts a paragraph.
fn definitions(text: &str, scan_end: usize) -> Definitions {
    let bytes = text.as_bytes();
    let mut found = Definitions::default();
    let mut blocks = blocks::Blocks::default();
    let mut after_definition = false;
    let mut at = 0;
    while at < scan_end {
        let line_end = line_end_at(bytes, at, scan_end);
        let mut definition = false;
        if let blocks::Line::Inline {
            from,
            starts_paragraph,
            heading,
        } = blocks.line(&bytes[at..line_end])
            && (starts_paragraph || after_definition)
            && !heading
            && let Some((label, reference)) = definition_at(&text[at + from..line_end])
        {
            definition = true;
            found.labels.entry(label).or_insert(reference);
            found.lines.insert(at, at + from..line_end);
        }
        after_definition = definition;
        at = line_end + 1;
    }
    found
}

/// The definition `line` (from its first content byte) is, when it names an
/// `oneiron://` ref: its matched id and its ref.
fn definition_at(line: &str) -> Option<(String, String)> {
    let bytes = line.as_bytes();
    if bytes.first() != Some(&b'[') {
        return None;
    }
    let close = label_close(bytes, 0)?;
    let label = matched_label(&line[1..close])?;
    let after = bytes.get(close + 1..)?.strip_prefix(b":")?;
    let after = &after[after
        .iter()
        .take_while(|&&byte| byte == b' ' || byte == b'\t')
        .count()..];
    let (reference, rest) = match after.strip_prefix(b"<") {
        Some(inner) => {
            let inner = inner.strip_prefix(PROSE_LINK_SCHEME.as_bytes())?;
            let length = inner.iter().position(|&byte| byte == b'>')?;
            (&inner[..length], &inner[length + 1..])
        }
        None => {
            let inner = after.strip_prefix(PROSE_LINK_SCHEME.as_bytes())?;
            let length = inner
                .iter()
                .position(u8::is_ascii_whitespace)
                .unwrap_or(inner.len());
            (&inner[..length], &inner[length..])
        }
    };
    if !record_ref_ok(reference) {
        return None;
    }
    let title = rest.trim_ascii();
    if !title.is_empty() && (!rest[0].is_ascii_whitespace() || !link_title(title)) {
        return None;
    }
    Some((label, std::str::from_utf8(reference).ok()?.to_owned()))
}

/// Whether `title` is one link title: `"…"`, `'…'` or `(…)`, its closing
/// mark escaped wherever it appears before its end.
fn link_title(title: &[u8]) -> bool {
    let close = match title.first() {
        Some(b'"') => b'"',
        Some(b'\'') => b'\'',
        Some(b'(') => b')',
        _ => return false,
    };
    if title.len() < 2 || title[title.len() - 1] != close {
        return false;
    }
    let mut at = 1;
    while at < title.len() - 1 {
        match title[at] {
            b'\\' => at += 2,
            byte if byte == close => return false,
            _ => at += 1,
        }
    }
    at == title.len() - 1
}

/// An id as CommonMark matches it: trimmed, each run of blanks one space,
/// case folded; `None` when nothing is left.
fn matched_label(label: &str) -> Option<String> {
    let matched = label.split_whitespace().collect::<Vec<_>>().join(" ");
    (!matched.is_empty()).then(|| matched.to_lowercase())
}

/// Whether `reference` is a ref a link may name: 1 to
/// [`crate::lens::RECORD_REF_MAX_BYTES`] printable ASCII bytes with no
/// parenthesis, angle bracket, bracket, quote or backslash.
fn record_ref_ok(reference: &[u8]) -> bool {
    !reference.is_empty()
        && reference.len() <= crate::lens::RECORD_REF_MAX_BYTES
        && reference.iter().all(|&byte| {
            byte.is_ascii_graphic()
                && !matches!(byte, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'"' | b'\\')
        })
}

/// The `]` that closes the label opening at the `[` at `start`: a label
/// holds no other bracket or line break and is at most
/// [`MAX_PROSE_LINK_LABEL_BYTES`] long.
fn label_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut close = start + 1;
    while close < bytes.len() {
        match bytes[close] {
            b'\\' => close += 2,
            b']' => return Some(close),
            b'[' | b'\n' => return None,
            _ => close += 1,
        }
        if close - start > MAX_PROSE_LINK_LABEL_BYTES + 1 {
            return None;
        }
    }
    None
}

/// The reference-style record link that opens at the `[` at `start`, if one
/// does: `[label][id]`, `[id][]` or `[id]`, its id defined as an
/// `oneiron://` ref. A label followed by `(` is an inline link's, never a
/// shortcut, and one followed by an id that is not defined links nothing.
fn reference_link_at(
    text: &str,
    start: usize,
    scan_end: usize,
    labels: &BTreeMap<String, String>,
) -> Option<ProseLink> {
    if labels.is_empty() {
        return None;
    }
    let bytes = &text.as_bytes()[..scan_end];
    let close = label_close(bytes, start)?;
    let label = &text[start + 1..close];
    let (id, end) = match bytes.get(close + 1) {
        Some(b'[') => {
            let id_close = label_close(bytes, close + 1)?;
            let id = &text[close + 2..id_close];
            (if id.is_empty() { label } else { id }, id_close + 1)
        }
        Some(b'(') => return None,
        _ => (label, close + 1),
    };
    let reference = labels.get(&matched_label(id)?)?;
    Some(ProseLink {
        start,
        end,
        label: label.to_owned(),
        reference: reference.clone(),
    })
}

/// The record autolink `<oneiron://<ref>>` that opens at the `<` at `start`,
/// if one does; its label is its URI as written.
fn autolink_at(text: &str, start: usize, scan_end: usize) -> Option<ProseLink> {
    let bytes = &text.as_bytes()[..scan_end];
    let target = bytes
        .get(start + 1..)?
        .strip_prefix(PROSE_LINK_SCHEME.as_bytes())?;
    let length = target
        .iter()
        .take(crate::lens::RECORD_REF_MAX_BYTES + 1)
        .position(|&byte| byte == b'>')?;
    if !record_ref_ok(&target[..length]) {
        return None;
    }
    let reference_start = start + 1 + PROSE_LINK_SCHEME.len();
    let end = reference_start + length + 1;
    Some(ProseLink {
        start,
        end,
        label: text[start + 1..end - 1].to_owned(),
        reference: text[reference_start..end - 1].to_owned(),
    })
}

/// The end of the line `at` sits in: its `\n`, or `scan_end`.
fn line_end_at(bytes: &[u8], at: usize, scan_end: usize) -> usize {
    bytes[at..scan_end]
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(scan_end, |offset| at + offset)
}

/// What ends an open raw HTML block (CommonMark's seven kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtmlBlockEnd {
    /// `<script`, `<pre`, `<style` or `<textarea`: the line holding the
    /// closing tag of any of them.
    RawTag,
    /// A line holding this marker: `-->`, `?>`, `>` or `]]>`.
    Marker(&'static [u8]),
    /// A block-level tag, or a lone complete tag: a blank line.
    BlankLine,
}

impl HtmlBlockEnd {
    /// Whether `line` is the block's last.
    fn ends_at(self, line: &[u8]) -> bool {
        match self {
            Self::RawTag => ["</script>", "</pre>", "</style>", "</textarea>"]
                .iter()
                .any(|tag| contains_ignore_case(line, tag.as_bytes())),
            Self::Marker(marker) => line.windows(marker.len()).any(|window| window == marker),
            Self::BlankLine => line.iter().all(u8::is_ascii_whitespace),
        }
    }
}

fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// The block-level tag names that open a raw HTML block (CommonMark kind 6),
/// space-separated.
const HTML_BLOCK_TAGS: &str = "address article aside base basefont blockquote body caption \
    center col colgroup dd details dialog dir div dl dt fieldset figcaption figure footer form \
    frame frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li link main menu \
    menuitem nav noframes ol optgroup option p param search section summary table tbody td \
    tfoot th thead title tr track ul";

/// What ends the raw HTML block `rest` (a line from its first non-space
/// byte) opens, when it opens one. A lone complete tag opens one only after
/// a blank line: it cannot interrupt a paragraph.
fn html_block_start(rest: &[u8], follows_blank: bool) -> Option<HtmlBlockEnd> {
    let after = rest.strip_prefix(b"<")?;
    let name_len = after
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric())
        .count();
    let name_ends = after
        .get(name_len)
        .is_none_or(|&byte| byte.is_ascii_whitespace() || byte == b'>');
    if name_ends
        && ["script", "pre", "style", "textarea"]
            .iter()
            .any(|tag| after[..name_len].eq_ignore_ascii_case(tag.as_bytes()))
    {
        return Some(HtmlBlockEnd::RawTag);
    }
    if after.starts_with(b"!--") {
        return Some(HtmlBlockEnd::Marker(b"-->"));
    }
    if after.starts_with(b"?") {
        return Some(HtmlBlockEnd::Marker(b"?>"));
    }
    if after.starts_with(b"![CDATA[") {
        return Some(HtmlBlockEnd::Marker(b"]]>"));
    }
    if after.first() == Some(&b'!') && after.get(1).is_some_and(u8::is_ascii_alphabetic) {
        return Some(HtmlBlockEnd::Marker(b">"));
    }
    let closing = after.first() == Some(&b'/');
    let tag = if closing { &after[1..] } else { after };
    let tag_len = tag
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric())
        .count();
    let tag_ends = tag.get(tag_len).is_none_or(|&byte| {
        byte.is_ascii_whitespace() || byte == b'>' || tag[tag_len..].starts_with(b"/>")
    });
    if tag_len > 0
        && tag_ends
        && HTML_BLOCK_TAGS
            .split_ascii_whitespace()
            .any(|name| tag[..tag_len].eq_ignore_ascii_case(name.as_bytes()))
    {
        return Some(HtmlBlockEnd::BlankLine);
    }
    let lone_tag = inline_html(rest)
        .is_some_and(|length| rest[length..].iter().all(u8::is_ascii_whitespace))
        && !rest.starts_with(b"<!")
        && !rest.starts_with(b"<?");
    (follows_blank && lone_tag).then_some(HtmlBlockEnd::BlankLine)
}

/// The length of the inline raw HTML `line` opens at its `<`: an open or
/// closing tag, a comment, a processing instruction, a declaration or a
/// CDATA section, ending on this line. `None` when it opens none (an
/// autolink such as `<oneiron://...>` is none), so the `<` is plain text.
fn inline_html(line: &[u8]) -> Option<usize> {
    let after = line.strip_prefix(b"<")?;
    let through = |marker: &[u8], from: usize| {
        line.get(from..)?
            .windows(marker.len())
            .position(|window| window == marker)
            .map(|offset| from + offset + marker.len())
    };
    if after.starts_with(b"!--") {
        return through(b"-->".as_slice(), 4);
    }
    if after.starts_with(b"?") {
        return through(b"?>".as_slice(), 2);
    }
    if after.starts_with(b"![CDATA[") {
        return through(b"]]>".as_slice(), 9);
    }
    if after.first() == Some(&b'!') && after.get(1).is_some_and(u8::is_ascii_alphabetic) {
        return through(b">".as_slice(), 2);
    }
    let closing = after.first() == Some(&b'/');
    let name_at = 1 + usize::from(closing);
    let name = line.get(name_at..)?;
    if !name.first().is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    let mut at = name_at
        + name
            .iter()
            .take_while(|&&byte| byte.is_ascii_alphanumeric() || byte == b'-')
            .count();
    // After the name: whitespace, `/>` or `>`; then attributes up to the
    // tag's `>`, a quoted value holding any `>` it likes.
    if !line
        .get(at)
        .is_some_and(|&byte| byte.is_ascii_whitespace() || byte == b'>' || byte == b'/')
    {
        return None;
    }
    let mut quote = None;
    while let Some(&byte) = line.get(at) {
        match (quote, byte) {
            (Some(open), _) if byte == open => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') if !closing => quote = Some(byte),
            (None, b'>') => return Some(at + 1),
            (None, b'<') => return None,
            (None, _) => {}
        }
        at += 1;
    }
    None
}

/// What a line at a fence boundary does to the open fence: `Some(next)` when
/// it opens or closes one (or sits inside one as a fence-shaped line).
fn fence_line(
    fence: Option<(u8, usize)>,
    indent: usize,
    rest: &[u8],
) -> Option<Option<(u8, usize)>> {
    let &mark = rest.first()?;
    if indent > 3 || (mark != b'`' && mark != b'~') {
        return None;
    }
    let run = rest.iter().take_while(|&&byte| byte == mark).count();
    if run < 3 {
        return None;
    }
    match fence {
        None => Some(Some((mark, run))),
        Some((open, length))
            if open == mark && run >= length && rest[run..].iter().all(u8::is_ascii_whitespace) =>
        {
            Some(None)
        }
        Some(open) => Some(Some(open)),
    }
}

/// The end of the first run of exactly `run` backticks at or after `from`.
fn closing_backticks(bytes: &[u8], from: usize, run: usize) -> Option<usize> {
    let mut at = from;
    while at < bytes.len() {
        if bytes[at] == b'`' {
            let length = bytes[at..].iter().take_while(|&&byte| byte == b'`').count();
            if length == run {
                return Some(at + length);
            }
            at += length;
        } else {
            at += 1;
        }
    }
    None
}

/// The record link that opens at the `[` at `start`, if one does.
fn link_at(text: &str, start: usize, scan_end: usize) -> Option<ProseLink> {
    let bytes = &text.as_bytes()[..scan_end];
    let close = label_close(bytes, start)?;
    let target = bytes[close + 1..]
        .strip_prefix(b"(")?
        .strip_prefix(PROSE_LINK_SCHEME.as_bytes())?;
    let length = target
        .iter()
        .take(crate::lens::RECORD_REF_MAX_BYTES + 1)
        .position(|&byte| byte == b')')?;
    if !record_ref_ok(&target[..length]) {
        return None;
    }
    let reference_start = close + 2 + PROSE_LINK_SCHEME.len();
    Some(ProseLink {
        start,
        end: reference_start + length + 1,
        label: text[start + 1..close].to_owned(),
        reference: text[reference_start..reference_start + length].to_owned(),
    })
}

/// One text slot a write's prose links are read from.
struct ProseSlot<'v> {
    /// The slot's concrete pointer: the declared one, with array indices.
    pointer: String,
    text: &'v str,
    /// The slot sits behind a `*[key=value]` filter, so its item declares
    /// it AI-written whoever wrote it.
    declared: bool,
}

/// The text `input` holds at `pointers`. A pointer may name a string, or a
/// value whose every string is read (under the declared pointer, never a
/// key the caller chose); `*` takes every array item, and `*[key=value]`
/// only those whose `key` is the string `value`.
fn prose_slots_at<'v>(input: &'v Value, pointers: &[&str]) -> Vec<ProseSlot<'v>> {
    let mut slots = Vec::new();
    for pointer in pointers {
        let segments: Vec<&str> = pointer.split('/').skip(1).collect();
        prose_at(input, &segments, String::new(), false, &mut slots);
    }
    slots
}

fn prose_at<'v>(
    value: &'v Value,
    segments: &[&str],
    at: String,
    declared: bool,
    slots: &mut Vec<ProseSlot<'v>>,
) {
    let Some((head, rest)) = segments.split_first() else {
        texts_in(value, &at, declared, 0, slots);
        return;
    };
    if let Some(filter) = head.strip_prefix('*') {
        let Value::Array(items) = value else {
            return;
        };
        let wanted = filter
            .strip_prefix('[')
            .and_then(|filter| filter.strip_suffix(']'))
            .and_then(|filter| filter.split_once('='));
        for (index, item) in items.iter().enumerate() {
            if let Some((key, expected)) = wanted
                && item.get(key).and_then(Value::as_str) != Some(expected)
            {
                continue;
            }
            prose_at(
                item,
                rest,
                format!("{at}/{index}"),
                declared || wanted.is_some(),
                slots,
            );
        }
        return;
    }
    if let Some(child) = value.as_object().and_then(|members| members.get(*head)) {
        prose_at(child, rest, format!("{at}/{head}"), declared, slots);
    }
}

/// Every string in `value`, each as a slot at `pointer`.
fn texts_in<'v>(
    value: &'v Value,
    pointer: &str,
    declared: bool,
    depth: usize,
    slots: &mut Vec<ProseSlot<'v>>,
) {
    if slots.len() >= MAX_PROSE_SLOTS || depth > MAX_PROSE_DEPTH {
        return;
    }
    match value {
        Value::String(text) => slots.push(ProseSlot {
            pointer: pointer.to_owned(),
            text,
            declared,
        }),
        Value::Array(items) => {
            for item in items {
                texts_in(item, pointer, declared, depth + 1, slots);
            }
        }
        Value::Object(members) => {
            for member in members.values() {
                texts_in(member, pointer, declared, depth + 1, slots);
            }
        }
        _ => {}
    }
}

/// The generated prose-link read a row with `prose_links` runs before its
/// engine call (OF-063 prose links: Engine ruling 10-17).
///
/// Each AI-written text slot (its writer is an agent or a system actor, or
/// its item declares it AI-written through a `*[key=value]` filter) is read
/// for `oneiron://` links, and each link must resolve under the writer's own
/// scoped read. A slot with a link that does not earns one reference
/// refusal with the outcome `unlinked`: the actor, `row`, the slot's pointer
/// and the time, never the ref. The text is neither refused nor rewritten,
/// and the write goes on; a reader sees such a link as its plain label.
/// Nothing is written here: the generated fn hands these facts to
/// [`receipt_landed_prose`] once its engine call has landed the write
/// (Engine ruling 10-18: the receipt means landed speech only), so a write
/// that fails, is refused or never runs leaves none. A read that fails
/// returns its error.
pub(crate) fn unlinked_prose_links<T: serde::Serialize>(
    memory: &Memory<'_>,
    row: &'static str,
    input: &T,
    pointers: &[&str],
) -> MemoryResult<Vec<ReferenceRefusalFacts>> {
    let writer_is_ai = memory.actor_class() != crate::EdgeActorClass::Human;
    if !writer_is_ai && !pointers.iter().any(|pointer| pointer.contains("*[")) {
        return Ok(Vec::new());
    }
    let value = serde_json::to_value(input).map_err(|_| {
        MemoryError::bad_request("the verb input could not be read for the records its text links")
    })?;
    let mut unlinked: Vec<ReferenceRefusalFacts> = Vec::new();
    for slot in prose_slots_at(&value, pointers) {
        if !(writer_is_ai || slot.declared)
            || unlinked.iter().any(|facts| facts.field == slot.pointer)
        {
            continue;
        }
        if let Some(facts) = unlinked_text(memory, row, slot.pointer, slot.text, 0)? {
            unlinked.push(facts);
        }
    }
    Ok(unlinked)
}

/// Receipts the `unlinked` facts of text that has now landed, each on its
/// own grouped write (Engine ruling 10-18: the durable unlinked-prose
/// receipt means landed speech only). Called only after the write that
/// carried the text returned success. Inside an anonymous off-record
/// session nothing is written. Best effort, as every receipt of a landed
/// effect: a receipt that cannot be written is logged and the landed write's
/// answer stands.
pub(crate) fn receipt_landed_prose(memory: &Memory<'_>, unlinked: &[ReferenceRefusalFacts]) {
    if let Err(error) = receipt_reference_refusals(memory, unlinked) {
        tracing::warn!(%error, "landed AI text's unresolved links went unreceipted");
    }
}

/// The `unlinked` facts one AI-written `text` at `pointer` earns for its
/// links that end past byte `from`: `None` when each of them resolves for
/// `memory`'s writer.
fn unlinked_text(
    memory: &Memory<'_>,
    row: &'static str,
    pointer: String,
    text: &str,
    from: usize,
) -> MemoryResult<Option<ReferenceRefusalFacts>> {
    let refs: Vec<NamedRecordRef> = parse_record_links(text)
        .into_iter()
        .filter(|link| link.end > from)
        .map(|link| NamedRecordRef {
            pointer: pointer.clone(),
            reference: link.reference,
        })
        .collect();
    match validate_record_references(memory, &refs) {
        Ok(()) => Ok(None),
        Err(ReferenceRefusal::Unresolved { pointer }) => Ok(Some(ReferenceRefusalFacts {
            actor: memory.actor(),
            actor_class: memory.actor_class(),
            row,
            field: pointer,
            outcome: ReferenceOutcome::Unlinked,
        })),
        Err(ReferenceRefusal::Read(error)) => Err(error),
    }
}

/// The row every witnessed message's prose links are receipted under.
pub(crate) const WITNESS_PROSE_ROW: &str = "vault.witness";
/// The AI-written text of a witnessed turn: each companion message's content.
const WITNESS_PROSE_SLOT: &str = "/messages/*[author=companion]/content";

/// The witness program's prose-link read (OF-063 prose links: Engine
/// ruling 10-17), run once for every turn it lands, at base or in a
/// non-anonymous off-record session's overlay, whatever door the turn came
/// through: the verb table's `vault.witness` and `vault.rooms.speak`,
/// first-party speech, a streamed message's final witness, the AI chat
/// reply. An imported turn is not read. Each companion message is read as
/// [`unlinked_prose_links`] reads a declared slot, before the writer opens;
/// the program hands the facts to [`receipt_landed_prose`] once the turn has
/// landed. It never refuses or rewrites the message, and a read that fails
/// is logged and reads as no link.
pub(crate) fn witness_prose_unlinked(
    memory: &Memory<'_>,
    turn: &crate::memory::WitnessTurn,
) -> Vec<ReferenceRefusalFacts> {
    // Most turns name no link: they are not read at all.
    if !turn.messages.iter().any(|message| {
        message.author == crate::memory::WitnessAuthor::Companion
            && message.content.contains(PROSE_LINK_SCHEME)
    }) {
        return Vec::new();
    }
    unlinked_prose_links(memory, WITNESS_PROSE_ROW, turn, &[WITNESS_PROSE_SLOT]).unwrap_or_else(
        |error| {
            tracing::warn!(%error, "witnessed AI text's links could not be read");
            Vec::new()
        },
    )
}

/// The prose-link read of text appended to an AI-written message (a
/// streamed continuation's finalize), before its writer opens: `text` is
/// the message's whole text, whose first `from` bytes were read when they
/// landed, so only links that end past them are read. The finalize hands
/// the facts to [`receipt_landed_prose`] once it has landed; a read that
/// fails is logged and reads as no link.
pub(crate) fn prose_text_unlinked(
    memory: &Memory<'_>,
    row: &'static str,
    field: &str,
    text: &str,
    from: usize,
) -> Vec<ReferenceRefusalFacts> {
    match unlinked_text(memory, row, field.to_owned(), text, from) {
        Ok(facts) => facts.into_iter().collect(),
        Err(error) => {
            tracing::warn!(%error, "appended AI text's links could not be read");
            Vec::new()
        }
    }
}

/// The prose-link check of AI-written text that has already landed (a DAG
/// append's or a summary reply's TURN prose, read once its writer closed):
/// links that end past byte `from` of `text` are read and receipted under
/// `row` at `field`, receipt-only: a read or receipt that fails is logged
/// and the landed write's answer stands.
pub(crate) fn admit_prose_text(
    memory: &Memory<'_>,
    row: &'static str,
    field: &str,
    text: &str,
    from: usize,
) {
    let receipted = unlinked_text(memory, row, field.to_owned(), text, from).and_then(|facts| {
        receipt_reference_refusals(memory, facts.as_slice()).map_err(MemoryError::from)
    });
    if let Err(error) = receipted {
        tracing::warn!(%error, "appended AI text's unresolved links went unreceipted");
    }
}
