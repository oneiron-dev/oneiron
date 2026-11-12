//! Moved from `crates/oneiron/src/office_body/docx.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_docedit::docx_body::DocxMark;
use oneiron_docedit::docx_body::DocxStoryScope;

/// One typed operation on a DOCX body. Offsets and lengths count Unicode
/// scalar values.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DocxBodyOp {
    /// Replace a paragraph's text by its shortest edit.
    SetText {
        block: String,
        text: String,
    },
    Splice {
        block: String,
        at: usize,
        delete: usize,
        insert: String,
    },
    SetCell {
        block: String,
        row: usize,
        col: usize,
        text: String,
    },
    /// A new paragraph after `after`, or first; the engine mints its id.
    InsertParagraph {
        after: Option<String>,
        role: Option<String>,
        text: String,
    },
    Delete {
        block: String,
    },
    /// Place a block after `after`, or first.
    Move {
        block: String,
        after: Option<String>,
    },
    /// Turn one inline mark on or off over `len` characters of a paragraph
    /// from `at`. Turning subscript on turns superscript off there, and the
    /// reverse: a run sits at one baseline.
    Mark {
        block: String,
        at: usize,
        len: usize,
        mark: DocxMark,
        on: bool,
    },
    /// Replace the plain text of one exact paragraph within a story table cell.
    SetStoryCellParagraph {
        scope: DocxStoryScope,
        block: String,
        row: usize,
        col: usize,
        paragraph: String,
        text: String,
    },
    SpliceStoryCellParagraph {
        scope: DocxStoryScope,
        block: String,
        row: usize,
        col: usize,
        paragraph: String,
        at: usize,
        delete: usize,
        insert: String,
    },
    /// Replace one story paragraph's text by its shortest edit.
    SetStoryText {
        scope: DocxStoryScope,
        block: String,
        text: String,
    },
    SpliceStory {
        scope: DocxStoryScope,
        block: String,
        at: usize,
        delete: usize,
        insert: String,
    },
    /// Turn one inline mark on or off over `len` characters of one story
    /// paragraph from `at`, with the body's baseline law.
    MarkStory {
        scope: DocxStoryScope,
        block: String,
        at: usize,
        len: usize,
        mark: DocxMark,
        on: bool,
    },
}
