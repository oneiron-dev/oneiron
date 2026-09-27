//! One bounded structural account of PDF revisions, definitions and xref roles.
//!
//! A clean renewal requires a complete raw inventory reconciled with the
//! strict semantic parse; a lexical ambiguity never becomes an empty set.

use super::{
    last_startxref,
    lex::{Kind, LexError, PdfLexer, Token, stream_delimiter},
};
use crate::api::SealResourceLimits;
use lopdf::{
    Document, LoadOptions, Object, ObjectId,
    xref::{XrefEntry, XrefType},
};
use std::{collections::BTreeSet, ops::Range};

const MAX_REVISIONS: usize = 32;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevisionAnalysisError {
    Framing,
    Limit,
    UnresolvedStream,
}
impl From<LexError> for RevisionAnalysisError {
    fn from(err: LexError) -> Self {
        match err {
            LexError::WorkLimit => Self::Limit,
            LexError::Malformed => Self::Framing,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ObjectDefinition {
    pub(crate) id: ObjectId,
    pub(crate) byte_span: Range<usize>,
    pub(crate) stream_span: Option<Range<usize>>,
    pub(crate) indexed: bool,
    pub(crate) xref_role: bool,
}
#[derive(Debug, Clone)]
pub(crate) struct RevisionFact {
    pub(crate) byte_end: usize,
    pub(crate) xref_offset: usize,
    pub(crate) prev_xref: Option<usize>,
    pub(crate) xref_style: XrefType,
    pub(crate) trailer: lopdf::Dictionary,
    pub(crate) definitions: Vec<ObjectDefinition>,
}
#[derive(Debug, Clone)]
pub(crate) struct RevisionFacts {
    pub(crate) revisions: Vec<RevisionFact>,
}
impl RevisionFacts {
    pub(crate) fn ends(&self) -> Vec<usize> {
        self.revisions.iter().map(|r| r.byte_end).collect()
    }
    pub(crate) fn has_duplicates(&self) -> bool {
        self.revisions.iter().any(|r| {
            let mut ids = BTreeSet::new();
            r.definitions.iter().any(|d| !ids.insert(d.id))
        })
    }
    /// A renewal must list EVERY raw object once, at the indexed position.
    pub(crate) fn accounts_for(&self, index: usize, changed: &BTreeSet<ObjectId>) -> bool {
        let Some(rev) = self.revisions.get(index) else {
            return false;
        };
        let mut ids = BTreeSet::new();
        for definition in &rev.definitions {
            if !definition.indexed && !definition.xref_role {
                return false;
            }
            if !ids.insert(definition.id) {
                return false;
            }
        }
        for def in &rev.definitions {
            if def.xref_role && !changed.contains(&def.id) {
                ids.remove(&def.id);
            }
        }
        ids == *changed
    }
}

fn strict(bytes: &[u8], limits: &SealResourceLimits) -> Result<Document, RevisionAnalysisError> {
    let options = LoadOptions {
        strict: true,
        max_decompressed_size: Some(limits.max_input_bytes),
        ..LoadOptions::default()
    };
    let doc = Document::load_mem_with_options(bytes, options)
        .map_err(|_| RevisionAnalysisError::Framing)?;
    if doc.objects.len() > limits.max_pdf_objects {
        return Err(RevisionAnalysisError::Limit);
    }
    Ok(doc)
}

fn stream_span(
    bytes: &[u8],
    header: Token<'_>,
    object_start: usize,
    doc: &Document,
    id: ObjectId,
) -> Result<Range<usize>, RevisionAnalysisError> {
    let (_, begin) = stream_delimiter(
        bytes
            .get(object_start..header.span.end + 2)
            .ok_or(RevisionAnalysisError::Framing)?,
    )
    .ok_or(RevisionAnalysisError::Framing)?;
    let begin = object_start + begin;
    if begin > bytes.len() {
        return Err(RevisionAnalysisError::Framing);
    }
    // Indexed streams are checked against the strict parser's raw bytes.
    // For a shadowed stream, a direct /Length is required; an unresolved
    // indirect length cannot be used to claim a complete definition inventory.
    let length = if let Ok(Object::Stream(stream)) = doc.get_object(id) {
        if matches!(doc.reference_table.get(id.0), Some(XrefEntry::Normal{offset,..})
            if *offset as usize == object_start)
        {
            Some(stream.content.len())
        } else {
            None
        }
    } else {
        None
    };
    let length = match length {
        Some(n) => n,
        None => {
            let mut lex = PdfLexer::new(bytes, object_start, 4096);
            let mut n = None;
            while let Some(t) = lex.next()? {
                if t.span.start >= header.span.start {
                    break;
                }
                if t.kind == Kind::Name && t.value == b"/Length" {
                    let v = lex.next()?.ok_or(RevisionAnalysisError::Framing)?;
                    if v.kind != Kind::Word || n.is_some() {
                        return Err(RevisionAnalysisError::UnresolvedStream);
                    }
                    n = std::str::from_utf8(v.value)
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok());
                }
            }
            n.ok_or(RevisionAnalysisError::UnresolvedStream)?
        }
    };
    let end = begin
        .checked_add(length)
        .ok_or(RevisionAnalysisError::Limit)?;
    if bytes.get(begin..end).is_none()
        || !bytes.get(end..).is_some_and(|tail| {
            tail.starts_with(b"\nendstream")
                || tail.starts_with(b"\r\nendstream")
                || tail.starts_with(b"\rendstream")
                || tail.starts_with(b"endstream")
        })
    {
        return Err(RevisionAnalysisError::Framing);
    }
    Ok(begin..end)
}

fn definitions(
    bytes: &[u8],
    start: usize,
    end: usize,
    doc: &Document,
    xref_offset: usize,
    limits: &SealResourceLimits,
) -> Result<Vec<ObjectDefinition>, RevisionAnalysisError> {
    let max_work = limits.max_input_bytes.min(8_000_000);
    let mut lexer = PdfLexer::new(bytes, start, max_work);
    let mut first: Option<Token<'_>> = None;
    let mut second: Option<Token<'_>> = None;
    let mut current: Option<(ObjectId, usize, Option<Range<usize>>)> = None;
    let mut out = Vec::new();
    while let Some(t) = lexer.next()? {
        if t.span.start >= end {
            break;
        }
        if t.kind == Kind::Word && t.value == b"stream" {
            let (id, begin, span) = current
                .as_mut()
                .ok_or(RevisionAnalysisError::UnresolvedStream)?;
            if span.is_some() {
                return Err(RevisionAnalysisError::Framing);
            }
            let content = stream_span(bytes, t, *begin, doc, *id)?;
            lexer.skip_to(content.end)?;
            *span = Some(content);
            first = None;
            second = None;
            continue;
        }
        if t.kind == Kind::Word && t.value == b"endobj" {
            let (id, begin, span) = current.take().ok_or(RevisionAnalysisError::Framing)?;
            let indexed = matches!(doc.reference_table.get(id.0), Some(XrefEntry::Normal{offset,generation})
                if *offset as usize == begin && *generation == id.1);
            out.push(ObjectDefinition {
                id,
                byte_span: begin..t.span.end,
                stream_span: span,
                indexed,
                xref_role: begin == xref_offset,
            });
            if out.len() > limits.max_pdf_objects.min(1_000_000) {
                return Err(RevisionAnalysisError::Limit);
            }
            first = None;
            second = None;
            continue;
        }
        if t.kind == Kind::Word && t.value == b"obj" {
            let num = first
                .as_ref()
                .filter(|v| v.kind == Kind::Word)
                .and_then(|v| std::str::from_utf8(v.value).ok()?.parse::<u32>().ok());
            let generation = second
                .as_ref()
                .filter(|v| v.kind == Kind::Word)
                .and_then(|v| std::str::from_utf8(v.value).ok()?.parse::<u16>().ok());
            if let (Some(num), Some(generation)) = (num, generation) {
                if current.is_some() {
                    return Err(RevisionAnalysisError::Framing);
                }
                current = Some((
                    (num, generation),
                    first
                        .as_ref()
                        .ok_or(RevisionAnalysisError::Framing)?
                        .span
                        .start,
                    None,
                ));
                first = None;
                second = None;
                continue;
            }
        }
        first = second.take();
        second = Some(t);
    }
    if current.is_some() {
        return Err(RevisionAnalysisError::Framing);
    }
    Ok(out)
}

/// Return the actual final EOF marker end, allowing at most four CR/LF bytes.
pub(crate) fn eof_tail(bytes: &[u8]) -> Option<usize> {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\r' | b'\n') {
        end -= 1;
        if bytes.len() - end > 4 {
            return None;
        }
    }
    bytes[..end].ends_with(b"%%EOF").then_some(end)
}

/// Locate the revision footer whose `startxref` points to `at`. A raw
/// `%%EOF` inside a stream is not a revision boundary. Work stays bounded by
/// the validated input size and MAX_REVISIONS in the caller.
fn revision_footer(bytes: &[u8], at: usize, upper: usize) -> Option<(usize, usize)> {
    let section = bytes.get(at..upper)?;
    for (i, window) in section.windows(b"startxref".len()).enumerate().rev() {
        if window != b"startxref" {
            continue;
        }
        let mut cursor = at + i + b"startxref".len();
        while matches!(bytes.get(cursor), Some(b' ' | b'\r' | b'\n')) {
            cursor += 1;
        }
        let first = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if first == cursor
            || bytes
                .get(first..cursor)?
                .iter()
                .try_fold(0usize, |value, b| {
                    value.checked_mul(10)?.checked_add(usize::from(*b - b'0'))
                })
                != Some(at)
        {
            continue;
        }
        while matches!(bytes.get(cursor), Some(b' ' | b'\r' | b'\n')) {
            cursor += 1;
        }
        if bytes.get(cursor..cursor + 5) == Some(b"%%EOF") && cursor + 5 <= upper {
            return Some((at + i, cursor + 5));
        }
    }
    None
}

/// The previous xref is read only from the current xref/trailer header.
/// lopdf's merged trailer deliberately drops /Prev.
fn xref_previous(bytes: &[u8], at: usize, footer_start: usize) -> Option<Option<usize>> {
    let section = bytes.get(at..footer_start)?;
    let header = if section.starts_with(b"xref") {
        section
    } else {
        let (stream_at, _) = stream_delimiter(section)?;
        &section[..stream_at]
    };
    let mut lexer = PdfLexer::new(header, 0, header.len().min(8_000_000));
    let mut prev = None;
    while let Some(token) = lexer.next().ok()? {
        if token.kind == Kind::Name && token.value == b"/Prev" {
            if prev.is_some() {
                return None;
            }
            let n = lexer.next().ok()??;
            if n.kind != Kind::Word {
                return None;
            }
            prev = Some(std::str::from_utf8(n.value).ok()?.parse::<usize>().ok()?);
        }
    }
    Some(prev)
}

/// Follow the validated xref `/Prev` chain and its matching startxref/EOF
/// footers. Never infer revisions from raw `%%EOF` occurrences in streams.
fn revision_boundaries(bytes: &[u8]) -> Vec<usize> {
    let Some(mut upper) = eof_tail(bytes) else {
        return Vec::new();
    };
    let Ok(start) = last_startxref(bytes) else {
        return Vec::new();
    };
    let Ok(mut at) = usize::try_from(start) else {
        return Vec::new();
    };
    let mut ends = Vec::new();
    for _ in 0..=MAX_REVISIONS {
        if at >= upper {
            return Vec::new();
        }
        let Some((footer, end)) = revision_footer(bytes, at, upper) else {
            return Vec::new();
        };
        if ends.is_empty() && end != upper {
            return Vec::new();
        }
        ends.push(end);
        let Some(prev) = xref_previous(bytes, at, footer) else {
            return Vec::new();
        };
        let Some(prev) = prev else {
            ends.reverse();
            return ends;
        };
        if prev >= at {
            return Vec::new();
        }
        upper = at;
        at = prev;
    }
    ends.reverse(); // MAX_REVISIONS + 1 is the fail-closed sentinel.
    ends
}

/// Complete structural account: every raw definition has a byte span and a
/// reference-table role, even if it is shadowed or unindexed.
pub(crate) fn analyze(
    bytes: &[u8],
    limits: &SealResourceLimits,
) -> Result<RevisionFacts, RevisionAnalysisError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(RevisionAnalysisError::Limit);
    }
    let ends = revision_boundaries(bytes);
    if ends.is_empty() {
        return Err(RevisionAnalysisError::Framing);
    }
    if ends.len() > MAX_REVISIONS {
        return Err(RevisionAnalysisError::Limit);
    }
    let mut previous_end = 0;
    let mut revisions: Vec<RevisionFact> = Vec::with_capacity(ends.len());
    for end in ends {
        let doc = strict(&bytes[..end], limits)?;
        let xref_offset = usize::try_from(
            last_startxref(&bytes[..end]).map_err(|_| RevisionAnalysisError::Framing)?,
        )
        .map_err(|_| RevisionAnalysisError::Limit)?;
        let footer = revision_footer(bytes, xref_offset, end)
            .ok_or(RevisionAnalysisError::Framing)?
            .0;
        let prev_xref =
            xref_previous(bytes, xref_offset, footer).ok_or(RevisionAnalysisError::Framing)?;
        match revisions.last() {
            None if prev_xref.is_some() => return Err(RevisionAnalysisError::Framing),
            Some(prior) if prev_xref != Some(prior.xref_offset) => {
                return Err(RevisionAnalysisError::Framing);
            }
            _ => {}
        }
        let definitions = definitions(&bytes[..end], previous_end, end, &doc, xref_offset, limits)?;
        if definitions.iter().any(|d| {
            d.byte_span.start >= d.byte_span.end
                || d.stream_span.as_ref().is_some_and(|s| s.start > s.end)
        }) {
            return Err(RevisionAnalysisError::Framing);
        }
        // Every indexed definition introduced in this revision must have an
        // exact matching raw header. Compressed object members are carried by
        // their indexed container stream, not by fabricated object headers.
        for (&num, entry) in &doc.reference_table.entries {
            if let XrefEntry::Normal { offset, generation } = entry {
                let offset = *offset as usize;
                if (previous_end..end).contains(&offset)
                    && definitions
                        .iter()
                        .filter(|d| {
                            d.id == (num, *generation) && d.byte_span.start == offset && d.indexed
                        })
                        .count()
                        != 1
                {
                    return Err(RevisionAnalysisError::Framing);
                }
            }
        }
        revisions.push(RevisionFact {
            byte_end: end,
            xref_offset,
            prev_xref,
            xref_style: doc.reference_table.cross_reference_type,
            trailer: doc.trailer,
            definitions,
        });
        previous_end = end;
    }
    Ok(RevisionFacts { revisions })
}
