//! The DOCX face of a live office body (ARCH-0075, "the body is the truth, the
//! file is a projection"). A plain block read feeds the import; the projection
//! writes a body's changes back into the imported package as one guarded,
//! tracked Word revision through the same gate as [`crate::revise`]. The body
//! itself (its Loro document, actors and forks) lives in the engine; this module
//! knows only DOCX.

use crate::{ArchiveLimits, DoceditError, Document, preflight_with_limits, revise_with_limits};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use stemma::view::{BlockRole, BlockView, SegmentView, TrackStatus};

/// One top-level block of the imported document, in document order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DocxBlock {
    /// The document's stable block id: the body's id for it and the projection's target.
    pub id: String,
    pub kind: DocxBlockKind,
    /// The paragraph role token a replace or insert authors with.
    pub role: Option<String>,
    /// The current redline reading of a paragraph; empty for other blocks.
    pub text: String,
    /// A table's anchor cells in row-major order; empty for other blocks.
    pub cells: Vec<DocxCell>,
    /// Why the body may not edit this block. Its content would not survive a
    /// whole-paragraph tracked replace, so the body keeps it read-only.
    pub locked: Option<DocxLock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocxBlockKind {
    Paragraph,
    Heading(u8),
    Table,
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DocxCell {
    pub row: usize,
    pub col: usize,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocxLock {
    /// The block carries pending tracked changes; another author's revision is
    /// never resolved as a side effect of an export.
    Tracked,
    /// The paragraph holds fields, links, images or other inline anchors.
    Anchors,
    /// The paragraph's typed-in enumeration label is part of its text.
    LiteralPrefix,
    /// An opaque block has no editable text.
    Opaque,
}

/// Read the top-level blocks of a DOCX package within the caller's archive limits.
pub fn read_docx_blocks(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<Vec<DocxBlock>, DoceditError> {
    preflight_with_limits(bytes, limits)?;
    let document = Document::parse(bytes)?;
    Ok(document.read().blocks.iter().map(block).collect())
}

fn block(view: &BlockView) -> DocxBlock {
    let kind = match view.role {
        BlockRole::Paragraph => DocxBlockKind::Paragraph,
        BlockRole::Heading { level } => DocxBlockKind::Heading(level),
        BlockRole::Table => DocxBlockKind::Table,
        _ => DocxBlockKind::Opaque,
    };
    let locked = if tracked(view) {
        Some(DocxLock::Tracked)
    } else if kind == DocxBlockKind::Opaque {
        Some(DocxLock::Opaque)
    } else if view.literal_prefix.is_some() {
        Some(DocxLock::LiteralPrefix)
    } else if view
        .segments
        .iter()
        .any(|segment| !matches!(segment, SegmentView::Text { .. }))
    {
        Some(DocxLock::Anchors)
    } else {
        None
    };
    DocxBlock {
        id: view.id.to_string(),
        kind,
        role: view.role_token.clone(),
        text: if kind == DocxBlockKind::Table {
            String::new()
        } else {
            view.text.clone()
        },
        cells: view
            .cells
            .iter()
            .map(|cell| DocxCell {
                row: cell.row,
                col: cell.col,
                text: cell.text.clone(),
            })
            .collect(),
        locked,
    }
}

fn tracked(view: &BlockView) -> bool {
    !matches!(view.block_status, TrackStatus::Normal)
        || !matches!(view.paragraph_mark_status, TrackStatus::Normal)
        || view.segments.iter().any(|segment| match segment {
            SegmentView::Text {
                status,
                format_revision,
                ..
            } => !matches!(status, TrackStatus::Normal) || format_revision.is_some(),
            SegmentView::Opaque { status, .. } => !matches!(status, TrackStatus::Normal),
            #[allow(unreachable_patterns)]
            _ => true,
        })
}

/// One body-to-file change against the imported blocks, applied in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DocxChange {
    /// Replace a paragraph's text, keeping its role.
    SetText {
        block: String,
        text: String,
    },
    /// Replace one table cell's text.
    SetCell {
        block: String,
        row: usize,
        col: usize,
        text: String,
    },
    /// Move an imported block beside another.
    Move {
        block: String,
        anchor: DocxAnchor,
    },
    /// New paragraphs beside an imported block.
    Insert {
        anchor: DocxAnchor,
        paragraphs: Vec<DocxParagraph>,
    },
    Delete {
        block: String,
    },
}

/// A place beside an imported block, as the native writer addresses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocxAnchor {
    After(String),
    Before(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxParagraph {
    pub role: Option<String>,
    pub text: String,
}

/// The one revision every change of a projection is authored under. The date
/// is pinned by the caller, so a projection never reads the clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxRevision {
    pub author: String,
    /// RFC 3339.
    pub date: String,
    /// Group id stamped on every tracked change of the projection.
    pub group: String,
}

/// Project `changes` onto the imported `source` package as one tracked revision.
/// No changes return the source bytes unchanged. A stale guard, an unknown
/// block or a broken output fails closed; unknown XML outside the edited
/// blocks is retained by the native writer.
pub fn project_docx(
    source: &[u8],
    changes: &[DocxChange],
    revision: &DocxRevision,
    limits: ArchiveLimits,
) -> Result<Vec<u8>, DoceditError> {
    if changes.is_empty() {
        return Ok(source.to_vec());
    }
    preflight_with_limits(source, limits)?;
    let view = Document::parse(source)?.read();
    let find = |id: &str| {
        view.blocks
            .iter()
            .find(|block| block.id.to_string() == id)
            .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown block {id}")))
    };
    let anchor = |anchor: &DocxAnchor| {
        let (id, position) = match anchor {
            DocxAnchor::After(id) => (id, "after"),
            DocxAnchor::Before(id) => (id, "before"),
        };
        find(id).map(|block| json!({"anchor": block.id.to_string(), "position": position}))
    };
    let mut ops: Vec<Value> = Vec::with_capacity(changes.len());
    for change in changes {
        ops.push(match change {
            DocxChange::SetText { block, text } => {
                let block = find(block)?;
                json!({
                    "op": "replace",
                    "target": block.id.to_string(),
                    "guard": block.guard,
                    "content": paragraph(block.role_token.as_deref(), text),
                })
            }
            DocxChange::SetCell {
                block,
                row,
                col,
                text,
            } => json!({
                "op": "table_op",
                "target": find(block)?.id.to_string(),
                "table_op": {"kind": "set_cell_text", "row_index": row, "col_index": col, "text": text},
            }),
            DocxChange::Move { block, anchor: to } => json!({
                "op": "move",
                "target": find(block)?.id.to_string(),
                "destination": anchor(to)?,
            }),
            DocxChange::Insert {
                anchor: at,
                paragraphs,
            } => json!({
                "op": "insert",
                "target": anchor(at)?,
                "content": paragraphs
                    .iter()
                    .map(|new| paragraph(new.role.as_deref(), &new.text))
                    .collect::<Vec<_>>(),
            }),
            DocxChange::Delete { block } => {
                let block = find(block)?;
                json!({"op": "delete", "target": block.id.to_string(), "guard": block.guard})
            }
        });
    }
    let transaction = json!({
        "ops": ops,
        "revision": {"author": revision.author, "date": revision.date, "apply_op_id": revision.group},
    });
    revise_with_limits(source, &transaction.to_string(), limits)
}

fn paragraph(role: Option<&str>, text: &str) -> Value {
    let content: Vec<Value> = if text.is_empty() {
        Vec::new()
    } else {
        vec![json!({"type": "text", "text": text})]
    };
    json!({"type": "paragraph", "role": role, "content": content})
}
