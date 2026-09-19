//! Native docx part writer: `w:ins`/`w:del` revision marks.
//!
//! Dependency-free tracked-change emission over `word/document.xml` bytes.
//! The writer splices within one target paragraph per op and leaves every
//! other byte of the part verbatim, so unknown elements, attributes,
//! whitespace, and prefixes outside the edit survive in place. Paragraphs
//! carrying complex content (existing revisions, hyperlinks, drawings,
//! fields, math) are refused as unsupported structure rather than rewritten:
//! a narrow verb that cannot prove its output is Word-shaped must fail
//! closed. Span comments live in [`super::comments`].

use super::ops::{DocxOp, DocxSpan};
use crate::{Error, Result};

/// Who the revision mark is attributed to, plus its timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionMark {
    /// `w:author` value, e.g. `oneiron-docedit-docx/0.1.0`.
    pub author: String,
    /// `w:date` value in `xsd:dateTime` shape, e.g. `2026-09-19T00:00:00Z`.
    pub date: String,
}

impl RevisionMark {
    /// Builds a mark, refusing values that cannot appear in XML attributes.
    pub fn new(author: impl Into<String>, date: impl Into<String>) -> Result<Self> {
        let author = author.into();
        let date = date.into();
        if author.trim().is_empty() || author.len() > 128 {
            return Err(Error::InvalidManifest(
                "docx revision author must be 1..=128 chars",
            ));
        }
        if author
            .chars()
            .any(|c| matches!(c, '"' | '<' | '&') || c.is_control())
        {
            return Err(Error::InvalidManifest(
                "docx revision author carries XML-breaking characters",
            ));
        }
        if !super::revision::valid_date(&date) {
            return Err(Error::InvalidManifest(
                "docx revision date must be a real UTC YYYY-MM-DDTHH:MM:SSZ timestamp",
            ));
        }
        Ok(Self { author, date })
    }
}

/// The writer output for one text op: the new `word/document.xml` bytes plus
/// the revision ids it consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextWrite {
    pub document_xml: Vec<u8>,
    pub revision_ids: Vec<i64>,
}

/// Applies one text op (`InsertText`/`DeleteSpan`/`ReplaceSpan`) to
/// `word/document.xml` bytes. Comment ops use the comments module.
pub fn apply_text_op(
    document_xml: &[u8],
    op: &DocxOp,
    mark: &RevisionMark,
    first_revision_id: i64,
) -> Result<TextWrite> {
    op.validate()?;
    RevisionMark::new(mark.author.clone(), mark.date.clone())?;
    let text = std::str::from_utf8(document_xml)
        .map_err(|_| Error::InvalidPackage("docx document.xml is not UTF-8"))?;
    if let DocxOp::JoinParagraphs { span } = op {
        return super::join::join_paragraphs(text, *span, mark, first_revision_id);
    }
    let paragraphs = find_paragraphs(text)?;
    let span = op.span();
    let para = paragraphs
        .get(span.paragraph as usize - 1)
        .ok_or(Error::InvalidManifest(
            "docx span paragraph is past the last paragraph",
        ))?;
    let body = &text[para.clone()];
    check_plain_paragraph(body)?;
    if !oneiron_stemma::plain_paragraph_shape(document_xml, op.span().paragraph)
        .map_err(|_| Error::InvalidPackage("malformed Word paragraph"))?
    {
        return Err(Error::InvalidManifest(
            "target paragraph contains wrapped runs",
        ));
    }
    let runs = scan_runs(body)?;
    check_span_end(span, &runs)?;
    let (replacement, consumed) = match op {
        DocxOp::InsertText { text: payload, .. } => {
            let rpr = caret_rpr(&runs, span.start);
            let block = ins_block(payload, mark, first_revision_id, rpr)?;
            let splice = splice_insert(body, &runs, span.start, &block)?;
            (splice, vec![first_revision_id])
        }
        DocxOp::DeleteSpan { .. } => {
            let splice = splice_delete(body, &runs, span, mark, first_revision_id)?;
            (splice, vec![first_revision_id])
        }
        DocxOp::ReplaceSpan { text: payload, .. } => {
            let splice = splice_replace(body, &runs, span, payload, mark, first_revision_id)?;
            (splice, vec![first_revision_id, first_revision_id + 1])
        }
        DocxOp::JoinParagraphs { .. } | DocxOp::AddComment { .. } => {
            return Err(Error::InvalidManifest(
                "docx comment ops need the comments writer, not apply_text_op",
            ));
        }
    };
    let mut out = String::with_capacity(text.len() + replacement.len());
    out.push_str(&text[..para.start]);
    out.push_str(&replacement);
    out.push_str(&text[para.end..]);
    Ok(TextWrite {
        document_xml: out.into_bytes(),
        revision_ids: consumed,
    })
}

/// Next free revision id: one past the maximum `w:id` already present.
pub fn next_revision_id(document_xml: &[u8]) -> Result<i64> {
    let text = std::str::from_utf8(document_xml)
        .map_err(|_| Error::InvalidPackage("docx document.xml is not UTF-8"))?;
    let mut max: i64 = 0;
    for tag in ["<w:ins", "<w:del "] {
        let mut rest = text;
        while let Some(pos) = rest.find(tag) {
            let after = &rest[pos + tag.len()..];
            let end = after.find('>').unwrap_or(after.len());
            if let Some(id) = attr_id(&after[..end]) {
                max = max.max(id);
            }
            rest = &after[end..];
        }
    }
    max.checked_add(1)
        .filter(|id| *id <= 2_147_483_647)
        .ok_or(Error::InvalidManifest("docx revision id space exhausted"))
}

pub(super) struct Run {
    /// Byte range of the whole `<w:r>...</w:r>` within the paragraph body.
    pub(super) range: std::ops::Range<usize>,
    /// Verbatim `<w:rPr>...</w:rPr>` bytes when the run carries properties.
    pub(super) rpr: Option<String>,
    /// Decoded text content of the single `w:t` node.
    pub(super) text: String,
    pub(super) opening: String,
    pub(super) text_opening: String,
}

pub(super) fn find_paragraphs(xml: &str) -> Result<Vec<std::ops::Range<usize>>> {
    oneiron_stemma::body_paragraph_ranges(xml.as_bytes())
        .map_err(|_| Error::InvalidPackage("malformed Word body XML"))
}

pub(super) fn tag_boundary(after_tag: &str) -> bool {
    match after_tag.as_bytes().first() {
        None => true,
        Some(b'>' | b'/' | b' ' | b'\t' | b'\n' | b'\r') => true,
        Some(_) => false,
    }
}

const FORBIDDEN_IN_TARGET: [&str; 22] = [
    "<!--",
    "<![CDATA[",
    "<m:",
    "<w:fldSimple",
    "<mc:AlternateContent",
    "<w:ins",
    "<w:del ",
    "<w:del>",
    "<w:move",
    "<w:commentRange",
    "<w:commentReference",
    "<w:hyperlink",
    "<w:bookmark",
    "<w:smartTag",
    "<w:sdt",
    "<w:object",
    "<w:drawing",
    "<w:pict",
    "<w:instrText",
    "<w:delText",
    "<w:fldChar",
    "&#",
];

pub(super) fn check_plain_paragraph(body: &str) -> Result<()> {
    if FORBIDDEN_IN_TARGET.iter().any(|frag| body.contains(*frag)) {
        return Err(Error::InvalidManifest(
            "docx target paragraph carries complex content the narrow writer refuses",
        ));
    }
    Ok(())
}

pub(super) fn scan_runs(body: &str) -> Result<Vec<Run>> {
    let mut runs = Vec::new();
    let mut cursor = 0usize;
    while let Some(start) = body[cursor..].find("<w:r") {
        let abs = cursor + start;
        if !tag_boundary(&body[abs + "<w:r".len()..]) {
            cursor = abs + "<w:r".len();
            continue;
        }
        let after_tag = &body[abs + "<w:r".len()..];
        let open_end = after_tag
            .find('>')
            .ok_or(Error::InvalidPackage("docx run open tag is truncated"))?;
        if after_tag[..open_end].ends_with('/') {
            cursor = abs + "<w:r".len() + open_end + 1;
            continue;
        }
        let content_start = abs + "<w:r".len() + open_end + 1;
        let close = body[content_start..]
            .find("</w:r>")
            .ok_or(Error::InvalidPackage("docx run close tag is missing"))?;
        let run_end = content_start + close + "</w:r>".len();
        let inner = &body[content_start..content_start + close];
        let texts = find_text_nodes(inner)?;
        if texts.len() != 1 {
            return Err(Error::InvalidManifest(
                "docx target run must hold exactly one w:t node",
            ));
        }
        let t = &inner[texts[0].clone()];
        let decoded = decode_text(t)?;
        let rpr_range = find_rpr(inner);
        let rpr = rpr_range.clone().map(|r| inner[r].to_owned());
        let text_start = inner[..texts[0].start]
            .rfind("<w:t")
            .ok_or(Error::InvalidPackage("missing text tag"))?;
        let text_end = texts[0].end + "</w:t>".len();
        let before_text = &inner[..text_start];
        let known_before = match rpr_range {
            Some(range) if range.end <= text_start => {
                format!("{}{}", &inner[..range.start], &inner[range.end..text_start])
            }
            Some(_) => return Err(Error::InvalidManifest("run properties must precede text")),
            None => before_text.to_owned(),
        };
        if !known_before.trim().is_empty() || !inner[text_end..].trim().is_empty() {
            return Err(Error::InvalidManifest(
                "target run contains unmodelled children; refusing lossy split",
            ));
        }
        let text_opening = inner[text_start..texts[0].start].to_owned();
        runs.push(Run {
            range: abs..run_end,
            rpr,
            text: decoded,
            opening: body[abs..content_start].to_owned(),
            text_opening,
        });
        cursor = run_end;
    }
    Ok(runs)
}

fn find_text_nodes(inner: &str) -> Result<Vec<std::ops::Range<usize>>> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(start) = inner[cursor..].find("<w:t") {
        let abs = cursor + start;
        if !tag_boundary(&inner[abs + "<w:t".len()..]) {
            cursor = abs + "<w:t".len();
            continue;
        }
        let after_tag = &inner[abs + "<w:t".len()..];
        let open_end = after_tag
            .find('>')
            .ok_or(Error::InvalidPackage("docx w:t open tag is truncated"))?;
        if after_tag[..open_end].ends_with('/') {
            cursor = abs + "<w:t".len() + open_end + 1;
            continue;
        }
        let content_start = abs + "<w:t".len() + open_end + 1;
        let close = inner[content_start..]
            .find("</w:t>")
            .ok_or(Error::InvalidPackage("docx w:t close tag is missing"))?;
        out.push(content_start..content_start + close);
        cursor = content_start + close + "</w:t>".len();
    }
    Ok(out)
}

fn find_rpr(inner: &str) -> Option<std::ops::Range<usize>> {
    let start = inner.find("<w:rPr")?;
    if !tag_boundary(&inner[start + "<w:rPr".len()..]) {
        return None;
    }
    let after_tag = &inner[start + "<w:rPr".len()..];
    let open_end = after_tag.find('>')?;
    if after_tag[..open_end].ends_with('/') {
        return Some(start..start + "<w:rPr".len() + open_end + 1);
    }
    let content_start = start + "<w:rPr".len() + open_end + 1;
    let close = inner[content_start..].find("</w:rPr>")?;
    Some(start..content_start + close + "</w:rPr>".len())
}

fn decode_text(raw: &str) -> Result<String> {
    if raw.contains("&#") {
        return Err(Error::InvalidManifest(
            "docx w:t carries numeric refs the narrow writer refuses",
        ));
    }
    Ok(raw
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&"))
}

pub(super) fn escape_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

pub(super) fn escape_attr(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

pub(super) fn text_element(raw: &str) -> String {
    if needs_preserve(raw) {
        format!("<w:t xml:space=\"preserve\">{}</w:t>", escape_text(raw))
    } else {
        format!("<w:t>{}</w:t>", escape_text(raw))
    }
}

fn needs_preserve(raw: &str) -> bool {
    raw.starts_with([' ', '\t']) || raw.ends_with([' ', '\t'])
}

pub(super) fn run_xml(rpr: Option<&str>, inner: &str) -> String {
    match rpr {
        Some(props) => format!("<w:r>{props}{inner}</w:r>"),
        None => format!("<w:r>{inner}</w:r>"),
    }
}

fn ins_block(payload: &str, mark: &RevisionMark, id: i64, rpr: Option<&str>) -> Result<String> {
    super::revision::tracked_xml(mark, id, true, &run_xml(rpr, &text_element(payload)))
}

fn check_span_end(span: DocxSpan, runs: &[Run]) -> Result<()> {
    let char_count = runs
        .iter()
        .map(|r| r.text.chars().count() as u32)
        .sum::<u32>();
    if span.end > char_count {
        return Err(Error::InvalidManifest(
            "docx span end is past the paragraph text",
        ));
    }
    Ok(())
}

/// The `w:rPr` to carry onto inserted runs: the properties of the run holding
/// the caret, or the last run's at end-of-paragraph.
fn caret_rpr(runs: &[Run], caret: u32) -> Option<&str> {
    let mut offset = 0u32;
    for run in runs {
        let len = run.text.chars().count() as u32;
        if caret <= offset + len {
            return run.rpr.as_deref();
        }
        offset += len;
    }
    runs.last().and_then(|run| run.rpr.as_deref())
}

fn splice_insert(body: &str, runs: &[Run], caret: u32, block: &str) -> Result<String> {
    let mut offset = 0u32;
    for run in runs {
        let len = run.text.chars().count() as u32;
        if caret < offset || caret > offset + len {
            offset += len;
            continue;
        }
        let cut = (caret - offset) as usize;
        let before: String = run.text.chars().take(cut).collect();
        let after: String = run.text.chars().skip(cut).collect();
        let mut replacement = String::new();
        if !before.is_empty() {
            replacement.push_str(&run.fragment(&before, false));
        }
        replacement.push_str(block);
        if !after.is_empty() {
            replacement.push_str(&run.fragment(&after, false));
        }
        let mut out = String::with_capacity(body.len() + block.len());
        out.push_str(&body[..run.range.start]);
        out.push_str(&replacement);
        out.push_str(&body[run.range.end..]);
        return Ok(out);
    }
    if caret == offset {
        let close = body
            .rfind("</w:p>")
            .ok_or(Error::InvalidPackage("docx paragraph close tag is missing"))?;
        let mut out = String::with_capacity(body.len() + block.len());
        out.push_str(&body[..close]);
        out.push_str(block);
        out.push_str(&body[close..]);
        return Ok(out);
    }
    Err(Error::InvalidManifest(
        "docx insert caret is past the paragraph text",
    ))
}

fn splice_delete(
    body: &str,
    runs: &[Run],
    span: DocxSpan,
    mark: &RevisionMark,
    id: i64,
) -> Result<String> {
    collect_delete(body, runs, span, mark, id, None)
}

fn splice_replace(
    body: &str,
    runs: &[Run],
    span: DocxSpan,
    payload: &str,
    mark: &RevisionMark,
    first_id: i64,
) -> Result<String> {
    let second = first_id
        .checked_add(1)
        .ok_or(Error::InvalidManifest("docx revision id space exhausted"))?;
    let rpr = caret_rpr(runs, span.start);
    let ins = ins_block(payload, mark, second, rpr)?;
    collect_delete(body, runs, span, mark, first_id, Some(ins.as_str()))
}

fn collect_delete(
    body: &str,
    runs: &[Run],
    span: DocxSpan,
    mark: &RevisionMark,
    id: i64,
    trailing_ins: Option<&str>,
) -> Result<String> {
    let (first_idx, last_idx) = overlapping_runs(runs, span)?;
    for pair in runs[first_idx..=last_idx].windows(2) {
        if !body[pair[0].range.end..pair[1].range.start]
            .trim()
            .is_empty()
        {
            return Err(Error::InvalidManifest(
                "delete crosses unmodelled paragraph children",
            ));
        }
    }
    let mut deleted: Vec<String> = Vec::new();
    let mut before = String::new();
    let mut after = String::new();
    let mut cursor = 0u32;
    for (index, run) in runs.iter().enumerate() {
        let len = run.text.chars().count() as u32;
        let run_end = cursor + len;
        if index >= first_idx && index <= last_idx {
            let chars: Vec<char> = run.text.chars().collect();
            let from = span.start.saturating_sub(cursor) as usize;
            let to = span.end.min(run_end).saturating_sub(cursor) as usize;
            let from = from.min(chars.len());
            let to = to.min(chars.len());
            if index == first_idx {
                before = chars[..from].iter().collect();
            }
            if index == last_idx {
                after = chars[to..].iter().collect();
            }
            let cut: String = chars[from..to].iter().collect();
            if !cut.is_empty() {
                deleted.push(run.fragment(&cut, true));
            }
        }
        cursor = run_end;
    }
    if deleted.is_empty() {
        return Err(Error::InvalidManifest(
            "docx delete span covers no paragraph text",
        ));
    }
    let del = super::revision::tracked_xml(mark, id, false, &deleted.concat())?;
    let mut replacement = String::new();
    if !before.is_empty() {
        replacement.push_str(&runs[first_idx].fragment(&before, false));
    }
    replacement.push_str(&del);
    if let Some(ins) = trailing_ins {
        replacement.push_str(ins);
    }
    if !after.is_empty() {
        replacement.push_str(&runs[last_idx].fragment(&after, false));
    }
    let start = runs[first_idx].range.start;
    let end = runs[last_idx].range.end;
    let mut out = String::with_capacity(body.len() + del.len() + 128);
    out.push_str(&body[..start]);
    out.push_str(&replacement);
    out.push_str(&body[end..]);
    Ok(out)
}

fn overlapping_runs(runs: &[Run], span: DocxSpan) -> Result<(usize, usize)> {
    let mut offset = 0u32;
    let mut first: Option<usize> = None;
    let mut last: Option<usize> = None;
    for (index, run) in runs.iter().enumerate() {
        let len = run.text.chars().count() as u32;
        let run_end = offset + len;
        if span.start < run_end && span.end > offset {
            if first.is_none() {
                first = Some(index);
            }
            last = Some(index);
        }
        offset = run_end;
    }
    match (first, last) {
        (Some(first_idx), Some(last_idx)) => Ok((first_idx, last_idx)),
        _ => Err(Error::InvalidManifest(
            "docx delete span covers no paragraph text",
        )),
    }
}

pub(super) fn attr_id(tag_body: &str) -> Option<i64> {
    let needle = "w:id=\"";
    let start = tag_body.find(needle)? + needle.len();
    let end = tag_body[start..].find('"')?;
    tag_body[start..start + end].parse().ok()
}
