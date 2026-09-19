//! Span-anchored docx comments: ranges in `word/document.xml` plus rows.
//!
//! A comment is three coordinated writes: a `w:commentRangeStart`/`w:commentRangeEnd`
//! pair plus a `w:commentReference` run in the target paragraph, a `w:comment`
//! row in `word/comments.xml`, and — for the first comment — the content-type
//! override and relationship row that link the new part. Markers land between
//! runs only: boundary text nodes are split first so the paragraph's run
//! properties and unknown siblings survive verbatim.

use super::ops::DocxOp;
use super::writer::{
    Run, attr_id, check_plain_paragraph, escape_attr, find_paragraphs, scan_runs, text_element,
};
use crate::{Error, Result};

/// The writer output for one comment op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentWrite {
    pub document_xml: Vec<u8>,
    pub comments_xml: Vec<u8>,
    /// True when `comments.xml` was created (caller must add the content-type
    /// override and relationship row via [`comments_override_row`] and
    /// [`comments_rel_row`]).
    pub comments_created: bool,
    pub comment_id: i64,
}

/// Applies one `AddComment` op. `comments_xml` is `None` when the package has
/// no `word/comments.xml` yet; the writer then returns a skeleton part and
/// sets `comments_created` so the pipeline can link it.
pub fn apply_comment(
    document_xml: &[u8],
    comments_xml: Option<&[u8]>,
    op: &DocxOp,
    mark: &super::writer::RevisionMark,
    comment_id: i64,
) -> Result<CommentWrite> {
    let DocxOp::AddComment { span, body } = op else {
        return Err(Error::InvalidManifest(
            "docx apply_comment needs an AddComment op",
        ));
    };
    op.validate()?;
    super::writer::RevisionMark::new(mark.author.clone(), mark.date.clone())?;
    if !(0..=i64::from(i32::MAX)).contains(&comment_id) {
        return Err(Error::InvalidManifest("invalid comment id"));
    }
    let text = std::str::from_utf8(document_xml)
        .map_err(|_| Error::InvalidPackage("docx document.xml is not UTF-8"))?;
    let paragraphs = find_paragraphs(text)?;
    let para = paragraphs
        .get(span.paragraph as usize - 1)
        .ok_or(Error::InvalidManifest(
            "docx span paragraph is past the last paragraph",
        ))?;
    let body_xml = &text[para.clone()];
    check_plain_paragraph(body_xml)?;
    if !oneiron_stemma::plain_paragraph_shape(document_xml, span.paragraph)
        .map_err(|_| Error::InvalidPackage("malformed Word paragraph"))?
    {
        return Err(Error::InvalidManifest(
            "target paragraph contains wrapped runs",
        ));
    }
    let runs = scan_runs(body_xml)?;
    check_comment_span(span.end, &runs)?;
    let with_markers = splice_comment_markers(body_xml, *span, comment_id)?;
    let mut document = String::with_capacity(text.len() + 256);
    document.push_str(&text[..para.start]);
    document.push_str(&with_markers);
    document.push_str(&text[para.end..]);
    let (comments, created) = upsert_comment(comments_xml, comment_id, mark, body)?;
    Ok(CommentWrite {
        document_xml: document.into_bytes(),
        comments_xml: comments,
        comments_created: created,
        comment_id,
    })
}

/// Next free comment id across document and comments parts.
pub fn next_comment_id(document_xml: &[u8], comments_xml: Option<&[u8]>) -> Result<i64> {
    let mut max: i64 = 0;
    for bytes in [Some(document_xml), comments_xml].into_iter().flatten() {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::InvalidPackage("docx comment part is not UTF-8"))?;
        for tag in ["<w:commentRangeStart", "<w:commentRangeEnd", "<w:comment "] {
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
    }
    max.checked_add(1)
        .filter(|id| *id <= 2_147_483_647)
        .ok_or(Error::InvalidManifest("docx comment id space exhausted"))
}

/// The `<Override>` row the pipeline splices into `[Content_Types].xml` when
/// the first comment creates `word/comments.xml`.
#[must_use]
pub const fn comments_override_row() -> &'static str {
    "<Override PartName=\"/word/comments.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml\"/>"
}

/// The `<Relationship>` row the pipeline splices into
/// `word/_rels/document.xml.rels` when the first comment creates
/// `word/comments.xml`. The caller supplies the next free `rId`.
#[must_use]
pub fn comments_rel_row(rid: &str) -> String {
    format!(
        "<Relationship Id=\"{rid}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments\" Target=\"comments.xml\"/>"
    )
}

fn check_comment_span(end: u32, runs: &[Run]) -> Result<()> {
    let char_count = runs
        .iter()
        .map(|r| r.text.chars().count() as u32)
        .sum::<u32>();
    if end > char_count {
        return Err(Error::InvalidManifest(
            "docx span end is past the paragraph text",
        ));
    }
    Ok(())
}

fn splice_comment_markers(
    body: &str,
    span: super::ops::DocxSpan,
    comment_id: i64,
) -> Result<String> {
    let mut owned = body.to_owned();
    for caret in [span.end, span.start] {
        let current = scan_runs(&owned)?;
        owned = split_at_caret(&owned, &current, caret)?;
    }
    let placed = scan_runs(&owned)?;
    if placed.is_empty() {
        if !span.is_caret() {
            return Err(Error::InvalidManifest(
                "docx comment span covers no paragraph text",
            ));
        }
        let close = owned
            .rfind("</w:p>")
            .ok_or(Error::InvalidPackage("docx paragraph close tag is missing"))?;
        let markers = format!(
            "<w:commentRangeStart w:id=\"{comment_id}\"/><w:commentRangeEnd w:id=\"{comment_id}\"/><w:r><w:commentReference w:id=\"{comment_id}\"/></w:r>"
        );
        owned.insert_str(close, &markers);
        return Ok(owned);
    }
    let start_byte = caret_byte(&placed, span.start)?;
    let start_marker = format!("<w:commentRangeStart w:id=\"{comment_id}\"/>");
    owned.insert_str(start_byte, &start_marker);
    let rescanned = scan_runs(&owned)?;
    let end_byte = caret_byte(&rescanned, span.end)?;
    let end_marker = format!(
        "<w:commentRangeEnd w:id=\"{comment_id}\"/><w:r><w:commentReference w:id=\"{comment_id}\"/></w:r>"
    );
    owned.insert_str(end_byte, &end_marker);
    Ok(owned)
}

fn split_at_caret(body: &str, runs: &[Run], caret: u32) -> Result<String> {
    let mut offset = 0u32;
    for run in runs {
        let len = run.text.chars().count() as u32;
        if caret <= offset || caret >= offset + len {
            offset += len;
            continue;
        }
        let cut = (caret - offset) as usize;
        let before: String = run.text.chars().take(cut).collect();
        let after: String = run.text.chars().skip(cut).collect();
        let replacement = format!(
            "{}{}",
            run.fragment(&before, false),
            run.fragment(&after, false)
        );
        let mut out = String::with_capacity(body.len() + 64);
        out.push_str(&body[..run.range.start]);
        out.push_str(&replacement);
        out.push_str(&body[run.range.end..]);
        return Ok(out);
    }
    Ok(body.to_owned())
}

fn caret_byte(runs: &[Run], caret: u32) -> Result<usize> {
    let mut offset = 0u32;
    for (index, run) in runs.iter().enumerate() {
        if caret == offset {
            return Ok(run.range.start);
        }
        offset += run.text.chars().count() as u32;
        if caret == offset {
            let next = runs.get(index + 1).map_or(run.range.end, |r| r.range.start);
            return Ok(next);
        }
    }
    match runs.last() {
        Some(run) if caret == offset => Ok(run.range.end),
        _ => Err(Error::InvalidManifest(
            "docx comment caret is past the paragraph text",
        )),
    }
}

fn upsert_comment(
    comments_xml: Option<&[u8]>,
    comment_id: i64,
    mark: &super::writer::RevisionMark,
    body: &str,
) -> Result<(Vec<u8>, bool)> {
    let author = escape_attr(&mark.author);
    let date = escape_attr(&mark.date);
    let initials = escape_attr(&initials(&mark.author));
    let row = format!(
        "<w:comment w:id=\"{comment_id}\" w:author=\"{author}\" w:date=\"{date}\" w:initials=\"{initials}\"><w:p><w:r>{}</w:r></w:p></w:comment>",
        text_element(body)
    );
    match comments_xml {
        None => {
            let skeleton = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><w:comments xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">{row}</w:comments>"
            );
            Ok((skeleton.into_bytes(), true))
        }
        Some(bytes) => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| Error::InvalidPackage("docx comments.xml is not UTF-8"))?;
            let close = text.find("</w:comments>").ok_or(Error::InvalidPackage(
                "docx comments.xml has no closing tag",
            ))?;
            let mut out = String::with_capacity(text.len() + row.len());
            out.push_str(&text[..close]);
            out.push_str(&row);
            out.push_str(&text[close..]);
            Ok((out.into_bytes(), false))
        }
    }
}

fn initials(author: &str) -> String {
    let mut out = String::new();
    for word in author.split(|c: char| !c.is_alphanumeric()) {
        if let Some(first) = word.chars().next() {
            out.push(first.to_ascii_uppercase());
        }
        if out.len() >= 3 {
            break;
        }
    }
    if out.is_empty() {
        out.push('O');
    }
    out
}
