//! Moved from `crates/oneiron/src/office_body/docx.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_docedit::docx_body::DocxRun;
pub use oneiron_verb_wire::office_body::docx::DocxBodyOp;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyBlock {
    pub id: String,
    pub kind: BodyBlockKind,
    pub role: Option<String>,
    /// Read from the imported package rather than written in the body.
    pub imported: bool,
    /// Read-only: its content would not survive a whole-paragraph replace.
    pub locked: bool,
    pub text: String,
    /// The paragraph's text as runs of one mark set each, joining to `text`;
    /// empty for other blocks.
    pub runs: Vec<DocxRun>,
    /// `(row, col)` to text, for a table.
    pub cells: BTreeMap<(usize, usize), String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyBlockKind {
    Paragraph,
    Heading(u8),
    Table,
    Opaque,
}
