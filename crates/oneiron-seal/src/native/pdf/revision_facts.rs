//! One bounded structural account of PDF revisions, definitions and xref roles.
//!
//! A clean renewal requires a complete raw inventory reconciled with the
//! strict semantic parse; a lexical ambiguity never becomes an empty set.

use super::{
    last_startxref,
    lex::{Kind, LexError, PdfLexer, Token, stream_delimiter},
    revision_ends,
};
use crate::api::SealResourceLimits;
use lopdf::{
    Document, LoadOptions, ObjectId,
    xref::{XrefEntry, XrefType},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

const MAX_REVISIONS: usize = 32;
const MAX_STRUCTURAL_WORK: usize = 8_000_000;
const MAX_PREFIX_WORK: usize = 2 * 1024 * 1024 * 1024;
struct WorkBudget {
    remaining: usize,
}
impl WorkBudget {
    fn new(limits: &SealResourceLimits) -> Self {
        // Caller object caps also bound allowable token work. The default
        // 1M-object cap retains the fixed 8M-token ceiling; a deliberately
        // tight object cap tightens the work budget rather than silently
        // allowing a single enormous object to consume the whole host.
        Self {
            remaining: limits
                .max_input_bytes
                .min(MAX_STRUCTURAL_WORK)
                .min(limits.max_pdf_objects.saturating_mul(128)),
        }
    }
    fn charge(&mut self, count: usize) -> Result<(), RevisionAnalysisError> {
        self.remaining = self
            .remaining
            .checked_sub(count)
            .ok_or(RevisionAnalysisError::Limit)?;
        Ok(())
    }
}

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
        let Some(prior) = index.checked_sub(1).and_then(|i| self.revisions.get(i)) else {
            return false;
        };
        if rev.prev_xref != Some(prior.xref_offset)
            || std::mem::discriminant(&rev.xref_style) != std::mem::discriminant(&prior.xref_style)
            || rev.trailer.get(b"Root").ok() != prior.trailer.get(b"Root").ok()
            || rev.trailer.get(b"ID").ok() != prior.trailer.get(b"ID").ok()
            || rev.trailer.get(b"Info").ok() != prior.trailer.get(b"Info").ok()
        {
            return false;
        }
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
    limits: &SealResourceLimits,
) -> Result<Range<usize>, RevisionAnalysisError> {
    let candidate = bytes
        .get(object_start..header.span.end + 2)
        .ok_or(RevisionAnalysisError::Framing)?;
    let (_, begin) = stream_delimiter(candidate).ok_or(RevisionAnalysisError::Framing)?;
    let begin = object_start + begin;
    if begin > bytes.len() {
        return Err(RevisionAnalysisError::Framing);
    }
    // /Length is the encoded byte count. lopdf may expose DECOMPRESSED
    // `Stream.content` for object streams, so its length cannot frame the
    // original bytes. Direct lengths are bound to this definition's header.
    // An indirect length is resolved only when this stream is xref-selected.
    let mut lex = PdfLexer::new(bytes, object_start, 4096);
    let mut length = None;
    while let Some(t) = lex.next()? {
        if t.span.start >= header.span.start {
            break;
        }
        if t.kind == Kind::Name && t.value == b"/Length" {
            if length.is_some() {
                return Err(RevisionAnalysisError::Framing);
            }
            let v = lex.next()?.ok_or(RevisionAnalysisError::Framing)?;
            if v.kind != Kind::Word {
                return Err(RevisionAnalysisError::UnresolvedStream);
            }
            let n = std::str::from_utf8(v.value)
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or(RevisionAnalysisError::UnresolvedStream)?;
            // A PDF stream may reference a separate /Length object. Bind
            // that value to this strict revision snapshot, never a future
            // document state or an unindexed shadow definition.
            let mut lookahead = PdfLexer::new(bytes, lex.at, 3);
            let second = lookahead.next()?;
            let third = lookahead.next()?;
            let indirect =
                second
                    .as_ref()
                    .zip(third.as_ref())
                    .is_some_and(|(generation_token, r)| {
                        generation_token.kind == Kind::Word
                            && generation_token.value.iter().all(u8::is_ascii_digit)
                            && r.kind == Kind::Word
                            && r.value == b"R"
                    });
            if indirect {
                let indexed = matches!(doc.reference_table.get(id.0),
                    Some(XrefEntry::Normal{offset,generation})
                        if *offset as usize == object_start && *generation == id.1);
                if !indexed {
                    return Err(RevisionAnalysisError::UnresolvedStream);
                }
                let generation = second
                    .and_then(|t| std::str::from_utf8(t.value).ok()?.parse::<u16>().ok())
                    .ok_or(RevisionAnalysisError::UnresolvedStream)?;
                let num = u32::try_from(n).map_err(|_| RevisionAnalysisError::UnresolvedStream)?;
                let value = doc
                    .get_object((num, generation))
                    .ok()
                    .and_then(|o| o.as_i64().ok())
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or(RevisionAnalysisError::UnresolvedStream)?;
                length = Some(value);
            } else {
                length = Some(n);
            }
        }
    }
    let length = length.ok_or(RevisionAnalysisError::UnresolvedStream)?;
    if length > limits.max_input_bytes {
        return Err(RevisionAnalysisError::Limit);
    }
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
    budget: &mut WorkBudget,
) -> Result<Vec<ObjectDefinition>, RevisionAnalysisError> {
    let mut lexer = PdfLexer::new(bytes, start, budget.remaining);
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
            let content = stream_span(bytes, t, *begin, doc, *id, limits)?;
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
    budget.charge(lexer.work())?;
    Ok(out)
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
    let final_doc = strict(bytes, limits)?;
    let ends = revision_ends(bytes, &final_doc, limits).ok_or(RevisionAnalysisError::Framing)?;
    if ends.len() > MAX_REVISIONS {
        return Err(RevisionAnalysisError::Limit);
    }
    let mut previous_end = 0;
    let mut prefix_work = 0usize;
    let mut budget = WorkBudget::new(limits);
    let mut revisions: Vec<RevisionFact> = Vec::with_capacity(ends.len());
    for end in ends {
        prefix_work = prefix_work
            .checked_add(end)
            .ok_or(RevisionAnalysisError::Limit)?;
        if prefix_work > MAX_PREFIX_WORK {
            return Err(RevisionAnalysisError::Limit);
        }
        let doc = strict(&bytes[..end], limits)?;
        let xref_offset = usize::try_from(
            last_startxref(&bytes[..end]).map_err(|_| RevisionAnalysisError::Framing)?,
        )
        .map_err(|_| RevisionAnalysisError::Limit)?;
        // `revision_ends` already proved the actual /Prev chain with strict
        // snapshots. Store the prior proven offset, never reparse it with a
        // competing grammar here.
        let prev_xref = revisions
            .last()
            .map(|prior: &RevisionFact| prior.xref_offset);
        let definitions = definitions(
            &bytes[..end],
            previous_end,
            end,
            &doc,
            xref_offset,
            limits,
            &mut budget,
        )?;
        if definitions.iter().any(|d| {
            d.byte_span.start >= d.byte_span.end
                || d.stream_span.as_ref().is_some_and(|s| s.start > s.end)
        }) {
            return Err(RevisionAnalysisError::Framing);
        }
        // Index exact raw identities and offsets ONCE. Preserve duplicate
        // counts in the facts, then reconcile each normal xref entry in
        // O(log N) rather than walking every definition for every entry.
        let mut raw = BTreeMap::<(ObjectId, usize), usize>::new();
        for definition in &definitions {
            budget.charge(1)?;
            *raw.entry((definition.id, definition.byte_span.start))
                .or_default() += 1;
        }
        for (&num, entry) in &doc.reference_table.entries {
            budget.charge(1)?;
            if let XrefEntry::Normal { offset, generation } = entry {
                let offset = *offset as usize;
                if (previous_end..end).contains(&offset)
                    && raw.get(&((num, *generation), offset)) != Some(&1)
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
