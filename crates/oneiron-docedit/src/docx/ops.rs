//! Native docx edit operations and span locators.
//!
//! Narrow verbs only: insert text, delete a span, replace a span, and anchor
//! a comment to a span. Every op addresses one paragraph by its 1-based body
//! ordinal plus a half-open char span in Unicode scalar values, matching the
//! engine `Locator::Docx { para_path, char_start, char_end }` shape. The
//! canonical `para_path` grammar is `body/pN` with N 1-based; parsing any
//! other shape is a refusal, never a guess.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// A 1-based paragraph ordinal plus a half-open char span `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxSpan {
    /// 1-based paragraph ordinal in document-body order.
    pub paragraph: u32,
    /// Inclusive start offset in Unicode scalar values.
    pub start: u32,
    /// Exclusive end offset in Unicode scalar values.
    pub end: u32,
}

impl DocxSpan {
    /// Builds a span, refusing 0 paragraphs and inverted ranges.
    pub fn new(paragraph: u32, start: u32, end: u32) -> Result<Self> {
        if paragraph == 0 {
            return Err(Error::InvalidManifest(
                "docx span paragraph must be 1-based",
            ));
        }
        if start > end {
            return Err(Error::InvalidManifest(
                "docx span is inverted; start must be at or before end",
            ));
        }
        Ok(Self {
            paragraph,
            start,
            end,
        })
    }

    /// Parses the canonical `body/pN` path plus a char span.
    pub fn parse(para_path: &str, char_start: u64, char_end: u64) -> Result<Self> {
        let ordinal = para_path
            .strip_prefix("body/p")
            .ok_or(Error::InvalidManifest(
                "docx para_path must match body/pN with N 1-based",
            ))?;
        if ordinal.is_empty() || !ordinal.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidManifest(
                "docx para_path must match body/pN with N 1-based",
            ));
        }
        let paragraph: u64 = ordinal
            .parse()
            .map_err(|_| Error::InvalidManifest("docx para_path ordinal overflow"))?;
        if paragraph == 0 || paragraph > u64::from(u32::MAX) {
            return Err(Error::InvalidManifest(
                "docx para_path ordinal must be 1-based and fit u32",
            ));
        }
        let start = u32::try_from(char_start)
            .map_err(|_| Error::InvalidManifest("docx char span overflow"))?;
        let end = u32::try_from(char_end)
            .map_err(|_| Error::InvalidManifest("docx char span overflow"))?;
        Self::new(paragraph as u32, start, end)
    }

    /// Renders the canonical `body/pN` path.
    #[must_use]
    pub fn para_path(self) -> String {
        let paragraph = self.paragraph;
        format!("body/p{paragraph}")
    }

    /// True for a caret (empty span): insert and comment anchors only.
    #[must_use]
    pub fn is_caret(self) -> bool {
        self.start == self.end
    }
}

/// The narrow docx verb vocabulary. Each op carries its span plus the text it
/// needs; paragraph joins use the first paragraph-end caret. Table and style edits
/// are not representable and are refused by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocxOp {
    /// Delete the paragraph mark at this end-of-paragraph caret. The next
    /// body paragraph joins on accept; reject preserves both paragraphs.
    JoinParagraphs { span: DocxSpan },
    /// Insert `text` at the caret. The span must be empty.
    InsertText { span: DocxSpan, text: String },
    /// Delete the covered span as one `w:del` mark. The span must be non-empty.
    DeleteSpan { span: DocxSpan },
    /// Replace the covered span: one `w:del` plus one `w:ins`. The span must
    /// be non-empty.
    ReplaceSpan { span: DocxSpan, text: String },
    /// Anchor a comment to the span (caret or range) with the given body text.
    AddComment { span: DocxSpan, body: String },
}

impl DocxOp {
    /// The span this op addresses.
    #[must_use]
    pub fn span(&self) -> DocxSpan {
        match self {
            Self::JoinParagraphs { span }
            | Self::InsertText { span, .. }
            | Self::DeleteSpan { span }
            | Self::ReplaceSpan { span, .. }
            | Self::AddComment { span, .. } => *span,
        }
    }

    /// Validates op-shape invariants before any byte is touched: caret vs
    /// range requirements, non-empty payloads, and text that cannot appear in
    /// XML (control characters other than tab/LF/CR).
    pub fn validate(&self) -> Result<()> {
        let span = self.span();
        DocxSpan::new(span.paragraph, span.start, span.end)?;
        match self {
            Self::JoinParagraphs { span } => {
                if !span.is_caret() || span.paragraph == u32::MAX {
                    return Err(Error::InvalidManifest(
                        "paragraph join needs an end caret and a following paragraph",
                    ));
                }
            }
            Self::InsertText { span, text } => {
                if !span.is_caret() {
                    return Err(Error::InvalidManifest(
                        "docx insert needs an empty span; use replace for ranges",
                    ));
                }
                check_text(text)?;
            }
            Self::DeleteSpan { span } => {
                if span.is_caret() {
                    return Err(Error::InvalidManifest("docx delete needs a non-empty span"));
                }
            }
            Self::ReplaceSpan { span, text } => {
                if span.is_caret() {
                    return Err(Error::InvalidManifest(
                        "docx replace needs a non-empty span; use insert at a caret",
                    ));
                }
                check_text(text)?;
            }
            Self::AddComment { body, .. } => {
                check_text(body)?;
            }
        }
        Ok(())
    }

    /// A one-line semantic diff rendering of this op.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::JoinParagraphs { span } => {
                format!("join {} to following paragraph", span.para_path())
            }
            Self::InsertText { span, text } => {
                let path = span.para_path();
                let start = span.start;
                format!("insert at {path}:{start} {text:?}")
            }
            Self::DeleteSpan { span } => {
                let path = span.para_path();
                let start = span.start;
                let end = span.end;
                format!("delete {path}:{start}-{end}")
            }
            Self::ReplaceSpan { span, text } => {
                let path = span.para_path();
                let start = span.start;
                let end = span.end;
                format!("replace {path}:{start}-{end} with {text:?}")
            }
            Self::AddComment { span, body } => {
                let path = span.para_path();
                let start = span.start;
                let end = span.end;
                format!("comment on {path}:{start}-{end}: {body:?}")
            }
        }
    }
}

/// The anchor-remapping effect of a docx op for comment re-anchoring.
/// Text shifts and paragraph joins use final-view Unicode scalar offsets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocxAnchorEffect {
    /// Final-view body ordinals after deleting a paragraph mark.
    JoinParagraphs { paragraph: u32, first_len: u32 },
    /// Text shifted within one paragraph: `[at, at+removed)` was replaced by
    /// `inserted` chars.
    ShiftWithinParagraph {
        paragraph: u32,
        at: u32,
        removed: u32,
        inserted: u32,
    },
}

impl DocxOp {
    /// The anchor effect ARTL-2 replays, when this op moves text.
    /// `AddComment` anchors but never shifts, so it yields none.
    #[must_use]
    pub fn anchor_effect(&self) -> Option<DocxAnchorEffect> {
        match self {
            Self::JoinParagraphs { span } => Some(DocxAnchorEffect::JoinParagraphs {
                paragraph: span.paragraph,
                first_len: span.start,
            }),
            Self::InsertText { span, text } => Some(DocxAnchorEffect::ShiftWithinParagraph {
                paragraph: span.paragraph,
                at: span.start,
                removed: 0,
                inserted: text.chars().count() as u32,
            }),
            Self::DeleteSpan { span } => Some(DocxAnchorEffect::ShiftWithinParagraph {
                paragraph: span.paragraph,
                at: span.start,
                removed: span.end - span.start,
                inserted: 0,
            }),
            Self::ReplaceSpan { span, text } => Some(DocxAnchorEffect::ShiftWithinParagraph {
                paragraph: span.paragraph,
                at: span.start,
                removed: span.end - span.start,
                inserted: text.chars().count() as u32,
            }),
            Self::AddComment { .. } => None,
        }
    }
}

fn check_text(text: &str) -> Result<()> {
    if text.is_empty() {
        return Err(Error::InvalidManifest("docx text payload is empty"));
    }
    if text.len() > 1_000_000 {
        return Err(Error::InvalidManifest("docx text payload is too large"));
    }
    if text.chars().any(is_forbidden_xml_char) {
        return Err(Error::InvalidManifest(
            "docx text carries a control character XML cannot hold",
        ));
    }
    Ok(())
}

fn is_forbidden_xml_char(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{0008}' | '\u{000B}' | '\u{000C}' | '\u{000E}'..='\u{001F}' | '\u{007F}')
}
