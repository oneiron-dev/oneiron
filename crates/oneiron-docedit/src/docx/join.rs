//! Track a paragraph join as a deleted paragraph mark, preserving both bodies.
use super::DocxSpan;
use super::writer::{RevisionMark, TextWrite, check_plain_paragraph, find_paragraphs, scan_runs};
use crate::{Error, Result};

pub(super) fn join_paragraphs(
    document: &str,
    span: DocxSpan,
    mark: &RevisionMark,
    id: i64,
) -> Result<TextWrite> {
    for ordinal in [span.paragraph, span.paragraph + 1] {
        if !oneiron_stemma::plain_paragraph_shape(document.as_bytes(), ordinal)
            .map_err(|_| Error::InvalidPackage("malformed join paragraph"))?
        {
            return Err(Error::InvalidManifest("join target contains wrapped runs"));
        }
    }
    let paragraphs = find_paragraphs(document)?;
    let first = paragraphs
        .get(span.paragraph as usize - 1)
        .ok_or(Error::InvalidManifest("join paragraph missing"))?;
    let next = paragraphs
        .get(span.paragraph as usize)
        .ok_or(Error::InvalidManifest(
            "join needs a following body paragraph",
        ))?;
    // Never join across a table, section marker, or unmodelled block.
    if !document[first.end..next.start].trim().is_empty() {
        return Err(Error::InvalidManifest("join crosses non-paragraph content"));
    }
    let body = &document[first.clone()];
    check_plain_paragraph(body)?;
    check_plain_paragraph(&document[next.clone()])?;
    if body.contains("<w:sectPr") {
        return Err(Error::InvalidManifest("join cannot delete a section break"));
    }
    let len: usize = scan_runs(body)?
        .iter()
        .map(|run| run.text.chars().count())
        .sum();
    if len != span.start as usize || !span.is_caret() {
        return Err(Error::InvalidManifest(
            "join must address the paragraph-end caret",
        ));
    }
    let deletion = super::revision::paragraph_deletion(mark, id)?;
    let mut changed = body.to_owned();
    if let Some(ppr) = body.find("<w:pPr") {
        let open = ppr
            + body[ppr..]
                .find('>')
                .ok_or(Error::InvalidPackage("truncated paragraph properties"))?;
        if body[..open].ends_with('/') {
            changed.replace_range(
                open - 1..open + 1,
                &format!("><w:rPr>{deletion}</w:rPr></w:pPr>"),
            );
        } else {
            let close = body[open..]
                .find("</w:pPr>")
                .map(|offset| open + offset)
                .ok_or(Error::InvalidPackage("missing paragraph properties close"))?;
            let properties = &body[open + 1..close];
            if let Some(rpr) = properties.find("<w:rPr") {
                let start = open + 1 + rpr;
                let end = start
                    + body[start..]
                        .find('>')
                        .ok_or(Error::InvalidPackage("truncated mark properties"))?;
                if body[..end].ends_with('/') {
                    changed.replace_range(end - 1..end + 1, &format!(">{deletion}</w:rPr>"));
                } else {
                    let end = body[start..]
                        .find("</w:rPr>")
                        .map(|offset| start + offset)
                        .ok_or(Error::InvalidPackage("missing mark properties close"))?;
                    changed.insert_str(end, &deletion);
                }
            } else {
                // rPr precedes sectPr/pPrChange in CT_PPr. Section breaks were refused above.
                let at = properties
                    .find("<w:pPrChange")
                    .map_or(close, |offset| open + 1 + offset);
                changed.insert_str(at, &format!("<w:rPr>{deletion}</w:rPr>"));
            }
        }
    } else {
        let open = body
            .find('>')
            .ok_or(Error::InvalidPackage("truncated paragraph"))?;
        changed.insert_str(
            open + 1,
            &format!("<w:pPr><w:rPr>{deletion}</w:rPr></w:pPr>"),
        );
    }
    let mut out = document.to_owned();
    out.replace_range(first.clone(), &changed);
    Ok(TextWrite {
        document_xml: out.into_bytes(),
        revision_ids: vec![id],
    })
}
