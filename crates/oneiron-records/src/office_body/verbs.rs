//! Moved from `crates/oneiron/src/office_body/verbs.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::office_body::docx::BodyBlockKind;
use crate::office_body::pptx::verbs::DeckBodyView;
use crate::office_body::xlsx::BodyCell;
use crate::office_body::xlsx::BodyConditionalFormat;
use crate::office_body::xlsx::BodyFormat;
use crate::office_body::xlsx::BodyName;
use crate::office_body::xlsx::XlsxBody;
use oneiron_docedit::docx_body::DocxRun;
use oneiron_docedit::docx_body::DocxStoryScope;
use oneiron_docedit::xlsx_body::XlsxArea;
use oneiron_docedit::xlsx_body::XlsxLines;
use oneiron_docedit::xlsx_body::XlsxSheetVisibility;
use oneiron_docedit::xlsx_body::XlsxStyle;
use oneiron_docedit::xlsx_body::XlsxTable;
use oneiron_store::write_envelope::provenance::text_commit::TextCommitReceipt;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyArtifactRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyCommitsRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyEditRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyExportVerbRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyForkEditRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyForkMergeRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyForkOpenRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyForkRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyImportRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyOps;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyPreviewRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyProposalRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyProposalSettleRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyReadRequest;
pub use oneiron_verb_wire::office_body::verbs::OfficeBodyReviewedFork;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeSet;

/// One commit of a live body, in commit order: who made it and its receipt,
/// or why it names no one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyCommitView {
    /// The actor whose receipt it carries; `None` when it carries none.
    pub actor: Option<String>,
    pub receipt: Option<TextCommitReceipt>,
    /// Why `actor` is `None`.
    pub reason: Option<OfficeBodyCommitGap>,
}

/// Why a body commit names no actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeBodyCommitGap {
    /// It carries no receipt the engine honours.
    ReceiptMissing,
}

impl OfficeBodyCommitView {
    pub fn of(receipt: Option<TextCommitReceipt>) -> Self {
        match receipt {
            Some(receipt) => Self {
                actor: Some(receipt.made_by.process.actor.to_hex()),
                receipt: Some(receipt),
                reason: None,
            },
            None => Self {
                actor: None,
                receipt: None,
                reason: Some(OfficeBodyCommitGap::ReceiptMissing),
            },
        }
    }
}

/// One DOCX table cell's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxCellView {
    pub row: usize,
    pub col: usize,
    pub text: String,
}

/// One DOCX block, its table cells listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxBlockView {
    pub id: String,
    pub kind: BodyBlockKind,
    pub role: Option<String>,
    pub imported: bool,
    pub locked: bool,
    pub text: String,
    /// The paragraph's text as runs of one mark set each.
    pub runs: Vec<DocxRun>,
    pub cells: Vec<DocxCellView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxStoryParagraphView {
    pub id: String,
    pub locked: bool,
    pub text: String,
    /// The paragraph's text as runs of one mark set each.
    pub runs: Vec<DocxRun>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxStoryCellParagraphView {
    pub id: String,
    pub locked: bool,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxStoryCellView {
    pub row: usize,
    pub col: usize,
    pub paragraphs: Vec<DocxStoryCellParagraphView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxStoryTableView {
    pub id: String,
    pub cells: Vec<DocxStoryCellView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxStoryView {
    pub scope: DocxStoryScope,
    pub paragraphs: Vec<DocxStoryParagraphView>,
    pub tables: Vec<DocxStoryTableView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxBodyView {
    pub blocks: Vec<DocxBlockView>,
    pub stories: Vec<DocxStoryView>,
}

/// One sheet, its cells in row-major order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XlsxSheetView {
    pub name: String,
    pub cells: Vec<BodyCell>,
    pub locked: Vec<XlsxArea>,
    /// Its tables, each with its header and totals rows.
    pub tables: Vec<XlsxTable>,
    /// Whether its tab shows: visible, hidden or veryHidden.
    pub visibility: XlsxSheetVisibility,
    /// The conditional formats the body added, by id.
    pub conditional_formats: Vec<BodyConditionalFormat>,
    /// The rows with their own height (points) or format, and the column
    /// ranges with their own width (characters) or format.
    pub rows: Vec<XlsxLines>,
    pub columns: Vec<XlsxLines>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XlsxBodyView {
    pub date1904: bool,
    pub sheets: Vec<XlsxSheetView>,
    pub names: Vec<BodyName>,
    pub styles: Vec<XlsxStyle>,
    /// The cell formats the body composed.
    pub formats: Vec<BodyFormat>,
}

/// `vault.artifacts.body.read`: the typed body, by format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum OfficeBodyView {
    Docx { body: DocxBodyView },
    Xlsx { body: XlsxBodyView },
    Pptx { body: DeckBodyView },
}

impl From<XlsxBody> for XlsxBodyView {
    fn from(body: XlsxBody) -> Self {
        Self {
            date1904: body.date1904,
            sheets: body
                .sheets
                .into_iter()
                .map(|sheet| XlsxSheetView {
                    name: sheet.name,
                    cells: sheet.cells.into_values().collect(),
                    locked: sheet.locked,
                    tables: sheet.tables,
                    visibility: sheet.visibility,
                    conditional_formats: sheet
                        .conditional
                        .into_iter()
                        .map(|(id, format)| BodyConditionalFormat { id, format })
                        .collect(),
                    rows: sheet.rows,
                    columns: sheet.columns,
                })
                .collect(),
            names: body.names.into_values().collect(),
            styles: body.styles,
            formats: body
                .formats
                .into_iter()
                .map(|(id, format)| BodyFormat { id, format })
                .collect(),
        }
    }
}
