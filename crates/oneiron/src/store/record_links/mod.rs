//! Pure parsing of record links in Markdown text.

mod blocks;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

/// The scheme a prose record link names its ref with.
pub(crate) const PROSE_LINK_SCHEME: &str = "oneiron://";
/// The most links one text is read for; any past them stay plain text.
pub(crate) const MAX_PROSE_LINKS: usize = 64;
/// The most bytes of one text read for links; links past them stay plain text.
pub(crate) const MAX_PROSE_SCAN_BYTES: usize = 128 * 1024;
/// The longest link label read, in bytes.
pub(crate) const MAX_PROSE_LINK_LABEL_BYTES: usize = 512;

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
/// `[id]: <oneiron://<ref>>`, with an optional title) at the start of a
/// paragraph or after another definition; its destination and its title may
/// each start on the paragraph's next line, inside its containers or on a
/// lazy continuation line, and a title may run across lines. Ids match as CommonMark
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
    /// Each definition line's byte range, from its first content byte (a
    /// definition's `[` on its first line) to the line's end, in order: one
    /// per line a definition takes, past the line's container markers, as a
    /// link's span is. A definition is shown to no reader: it is never text.
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
    /// Each definition line's content range, keyed by the byte the line
    /// starts at.
    lines: BTreeMap<usize, Range<usize>>,
}

/// The definitions in `text`'s first `scan_end` bytes, read through the same
/// block structure the link scan reads. A definition opens a paragraph or
/// follows another definition, since a definition never interrupts a
/// paragraph, and it may take more than one of the paragraph's lines (FIX
/// 3285): those inside its containers and the lazy lines that continue it
/// outside them, each read from its first content byte, as the link scan
/// reads them.
fn definitions(text: &str, scan_end: usize) -> Definitions {
    let bytes = text.as_bytes();
    let mut found = Definitions::default();
    let mut blocks = blocks::Blocks::default();
    // The open paragraph's lines: each line's start and its content's range.
    let mut paragraph: Vec<(usize, Range<usize>)> = Vec::new();
    let mut at = 0;
    while at < scan_end {
        let line_end = line_end_at(bytes, at, scan_end);
        match blocks.line(&bytes[at..line_end]) {
            blocks::Line::Inline {
                from,
                starts_paragraph,
                heading,
            } => {
                if starts_paragraph {
                    read_definitions(bytes, &paragraph, &mut found);
                    paragraph.clear();
                }
                // A heading is a line of its own, and never a definition.
                if !heading {
                    paragraph.push((at, at + from..line_end));
                }
            }
            blocks::Line::Skip => {
                read_definitions(bytes, &paragraph, &mut found);
                paragraph.clear();
            }
        }
        at = line_end + 1;
    }
    read_definitions(bytes, &paragraph, &mut found);
    found
}

/// Reads the definitions that open the paragraph whose lines `paragraph`
/// holds (each line's start and its content's range), one after another,
/// until a line opens none: the rest of the paragraph is its text.
fn read_definitions(bytes: &[u8], paragraph: &[(usize, Range<usize>)], found: &mut Definitions) {
    let lines: Vec<&[u8]> = paragraph
        .iter()
        .map(|(_, content)| &bytes[content.clone()])
        .collect();
    let mut next = 0;
    while let Some((label, reference, taken)) = definition_at(&lines[next..]) {
        found.labels.entry(label).or_insert(reference);
        for (start, content) in &paragraph[next..next + taken] {
            found.lines.insert(*start, content.clone());
        }
        next += taken;
    }
}

/// The definition `lines` open (a paragraph's lines from its first, each
/// from its first content byte), when it names an `oneiron://` ref: its
/// matched id, its ref, and how many of the lines it takes. The label sits
/// on the first line; the destination on that line or alone at the start of
/// the next; an optional title after a blank on the destination's line, or
/// at the start of the line after it, and it may run across lines. A title
/// that does not end its line unmakes the definition when it shares the
/// destination's line; one that starts a line of its own then is that line's
/// text, and the definition ends at its destination.
fn definition_at(lines: &[&[u8]]) -> Option<(String, String, usize)> {
    let first = *lines.first()?;
    if first.first() != Some(&b'[') {
        return None;
    }
    let close = label_close(first, 0)?;
    let label = matched_label(std::str::from_utf8(&first[1..close]).ok()?)?;
    let after = skip_spaces(first.get(close + 1..)?.strip_prefix(b":")?);
    let (line, after) = if after.trim_ascii().is_empty() {
        (1, *lines.get(1)?)
    } else {
        (0, after)
    };
    let (reference, rest) = destination(after)?;
    if !record_ref_ok(reference) {
        return None;
    }
    let reference = std::str::from_utf8(reference).ok()?.to_owned();
    if !rest.trim_ascii().is_empty() {
        if !rest[0].is_ascii_whitespace() {
            return None;
        }
        let title = rest.trim_ascii_start();
        let last = title_end(&lines[line..], lines[line].len() - title.len())?;
        return Some((label, reference, line + last + 1));
    }
    let taken = lines
        .get(line + 1)
        .filter(|next| matches!(next.first(), Some(b'"' | b'\'' | b'(')))
        .and_then(|_| title_end(&lines[line + 1..], 0))
        .map_or(line + 1, |last| line + 1 + last + 1);
    Some((label, reference, taken))
}

/// `bytes` past its leading spaces and tabs.
fn skip_spaces(bytes: &[u8]) -> &[u8] {
    &bytes[bytes
        .iter()
        .take_while(|&&byte| byte == b' ' || byte == b'\t')
        .count()..]
}

/// The `oneiron://` destination `rest` opens, bare or in angle brackets: its
/// ref and what follows it on its line.
fn destination(rest: &[u8]) -> Option<(&[u8], &[u8])> {
    match rest.strip_prefix(b"<") {
        Some(inner) => {
            let inner = inner.strip_prefix(PROSE_LINK_SCHEME.as_bytes())?;
            let length = inner.iter().position(|&byte| byte == b'>')?;
            Some((&inner[..length], &inner[length + 1..]))
        }
        None => {
            let inner = rest.strip_prefix(PROSE_LINK_SCHEME.as_bytes())?;
            let length = inner
                .iter()
                .position(u8::is_ascii_whitespace)
                .unwrap_or(inner.len());
            Some((&inner[..length], &inner[length..]))
        }
    }
}

/// The index, among `lines`, of the line where the link title opening at
/// byte `start` of the first ends: `"…"`, `'…'` or `(…)`, its closing mark
/// escaped wherever it appears before its end, and nothing but blanks after
/// it on its line. A title may run across lines; `None` when it never ends
/// so.
fn title_end(lines: &[&[u8]], start: usize) -> Option<usize> {
    let close = match lines.first()?.get(start)? {
        b'"' => b'"',
        b'\'' => b'\'',
        b'(' => b')',
        _ => return None,
    };
    let mut from = start + 1;
    for (index, line) in lines.iter().enumerate() {
        let mut at = from;
        while at < line.len() {
            match line[at] {
                b'\\' => at += 2,
                byte if byte == close => {
                    return line[at + 1..].trim_ascii().is_empty().then_some(index);
                }
                _ => at += 1,
            }
        }
        from = 0;
    }
    None
}

/// An id as CommonMark matches it: trimmed, each run of blanks one space,
/// case folded; `None` when nothing is left.
fn matched_label(label: &str) -> Option<String> {
    let matched = label.split_whitespace().collect::<Vec<_>>().join(" ");
    (!matched.is_empty()).then(|| matched.to_lowercase())
}

/// Whether `reference` is a ref a link may name: 1 to
/// [`crate::request_limits::RECORD_REF_MAX_BYTES`] printable ASCII bytes with no
/// parenthesis, angle bracket, bracket, quote or backslash.
fn record_ref_ok(reference: &[u8]) -> bool {
    !reference.is_empty()
        && reference.len() <= crate::request_limits::RECORD_REF_MAX_BYTES
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
        .take(crate::request_limits::RECORD_REF_MAX_BYTES + 1)
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
        .take(crate::request_limits::RECORD_REF_MAX_BYTES + 1)
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
