//! docx inspect-first: paragraph census plus revision and comment ids.
//!
//! The writer refuses to run blind: this scan reports the paragraph count the
//! spans resolve against, the revision/comment ids already taken (so new ids
//! never collide), and the unknown-part set the passthrough law protects.
//! Pure byte scans over UTF-8 XML; no XML library, no allocation beyond the
//! report itself.

use crate::opc;
use serde::{Deserialize, Serialize};

/// The inspect-first summary for a docx package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxStructure {
    /// Paragraph count in `word/document.xml` body order.
    pub paragraphs: u32,
    /// Revision ids (`w:id`) already present on tracked-change marks.
    pub revision_ids: Vec<i64>,
    /// Comment ids already present in `word/document.xml` ranges.
    pub comment_ids: Vec<i64>,
    /// True when any `w:ins`/`w:del` mark is present.
    pub has_tracked_changes: bool,
    /// Parts classified unknown: the passthrough set.
    pub unknown_parts: Vec<String>,
}

/// Scans an already-opened docx. Missing `word/document.xml` is a refusal:
/// without a spine there is no paragraph census to inspect against.
pub fn inspect_docx(
    document_xml: Option<&[u8]>,
    names: impl Iterator<Item = String>,
) -> crate::Result<DocxStructure> {
    let xml = document_xml.ok_or(crate::Error::InvalidPackage(
        "docx is missing word/document.xml",
    ))?;
    let text = std::str::from_utf8(xml)
        .map_err(|_| crate::Error::InvalidPackage("docx document.xml is not UTF-8"))?;
    let paragraphs = u32::try_from(super::writer::find_paragraphs(text)?.len())
        .map_err(|_| crate::Error::InvalidPackage("too many body paragraphs"))?;
    let revision_ids = scan_revision_ids(text);
    let comment_ids = scan_comment_ids(text);
    let has_tracked_changes = text.contains("<w:ins") || text.contains("<w:del ");
    let unknown_parts = names
        .filter(|name| opc::classify(name) == opc::PartClass::Unknown)
        .collect();
    Ok(DocxStructure {
        paragraphs,
        revision_ids,
        comment_ids,
        has_tracked_changes,
        unknown_parts,
    })
}

fn scan_revision_ids(xml: &str) -> Vec<i64> {
    let mut ids = Vec::new();
    for tag in ["<w:ins", "<w:del "] {
        let mut rest = xml;
        while let Some(pos) = rest.find(tag) {
            let after = &rest[pos + tag.len()..];
            let end = after.find('>').unwrap_or(after.len());
            if let Some(id) = attr_i64(&after[..end], "w:id=\"")
                && !ids.contains(&id)
            {
                ids.push(id);
            }
            rest = &after[end..];
        }
    }
    ids.sort_unstable();
    ids
}

fn scan_comment_ids(xml: &str) -> Vec<i64> {
    let mut ids = Vec::new();
    for tag in ["<w:commentRangeStart", "<w:commentRangeEnd"] {
        let mut rest = xml;
        while let Some(pos) = rest.find(tag) {
            let after = &rest[pos + tag.len()..];
            let end = after.find('>').unwrap_or(after.len());
            if let Some(id) = attr_i64(&after[..end], "w:id=\"")
                && !ids.contains(&id)
            {
                ids.push(id);
            }
            rest = &after[end..];
        }
    }
    ids.sort_unstable();
    ids
}

fn attr_i64(tag_body: &str, needle: &str) -> Option<i64> {
    let start = tag_body.find(needle)? + needle.len();
    let end = tag_body[start..].find('"')?;
    tag_body[start..start + end].parse().ok()
}
