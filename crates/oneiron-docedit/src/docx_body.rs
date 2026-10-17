//! The DOCX face of a live office body (ARCH-0075, "the body is the truth, the
//! file is a projection"). A plain block read feeds the import; the projection
//! writes a body's changes back into the imported package as one guarded,
//! tracked Word revision through the same gate as [`crate::revise`]. The body
//! itself (its Loro document, actors and forks) lives in the engine; this module
//! knows only DOCX.

use crate::{ArchiveLimits, DoceditError, Document, preflight_with_limits, revise_with_limits};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use similar::{Algorithm, DiffOp, capture_diff_slices};
use stemma::view::{BlockRole, BlockView, SegmentView, TextMark, TrackStatus};

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
    /// The paragraph's text as runs of one mark set each, joining to `text`.
    /// Empty for other blocks and for a paragraph whose text segments do not
    /// read as its text (a pending tracked change).
    pub runs: Vec<DocxRun>,
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

/// A stretch of paragraph text under one set of inline marks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxRun {
    pub text: String,
    /// Sorted, without repeats.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub marks: Vec<DocxMark>,
}

/// The inline marks Word's comprehension view carries and a tracked
/// formatting change writes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DocxMark {
    Bold,
    Italic,
    Underline,
    Strike,
    Subscript,
    Superscript,
}

impl DocxMark {
    pub const ALL: [Self; 6] = [
        Self::Bold,
        Self::Italic,
        Self::Underline,
        Self::Strike,
        Self::Subscript,
        Self::Superscript,
    ];

    /// The mark's name on the revision wire and in the body.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Bold => "bold",
            Self::Italic => "italic",
            Self::Underline => "underline",
            Self::Strike => "strike",
            Self::Subscript => "subscript",
            Self::Superscript => "superscript",
        }
    }

    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mark| mark.key() == key)
    }

    /// The mark a run cannot carry alongside this one: a run sits at one
    /// baseline.
    #[must_use]
    pub const fn baseline_pair(self) -> Option<Self> {
        match self {
            Self::Subscript => Some(Self::Superscript),
            Self::Superscript => Some(Self::Subscript),
            _ => None,
        }
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// Runs in canonical form: no empty run, marks sorted and unique, and no two
/// neighbours under the same marks.
#[must_use]
pub fn canonical_runs(runs: impl IntoIterator<Item = DocxRun>) -> Vec<DocxRun> {
    let mut out: Vec<DocxRun> = Vec::new();
    for mut run in runs {
        if run.text.is_empty() {
            continue;
        }
        run.marks.sort_unstable();
        run.marks.dedup();
        match out.last_mut() {
            Some(last) if last.marks == run.marks => last.text.push_str(&run.text),
            _ => out.push(run),
        }
    }
    out
}

/// The text a run list reads as.
#[must_use]
pub fn runs_text(runs: &[DocxRun]) -> String {
    runs.iter().map(|run| run.text.as_str()).collect()
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
    let text = if kind == DocxBlockKind::Table {
        String::new()
    } else {
        view.text.clone()
    };
    let runs = match kind {
        DocxBlockKind::Paragraph | DocxBlockKind::Heading(_) => {
            let runs = source_runs(view);
            if runs_text(&runs) == text {
                runs
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    };
    DocxBlock {
        id: view.id.to_string(),
        kind,
        role: view.role_token.clone(),
        text,
        runs,
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

/// A paragraph's text segments as canonical runs.
fn source_runs(view: &BlockView) -> Vec<DocxRun> {
    canonical_runs(view.segments.iter().filter_map(|segment| match segment {
        SegmentView::Text { text, marks, .. } => Some(DocxRun {
            text: text.clone(),
            marks: marks.iter().copied().map(text_mark).collect(),
        }),
        _ => None,
    }))
}

fn text_mark(mark: TextMark) -> DocxMark {
    match mark {
        TextMark::Bold => DocxMark::Bold,
        TextMark::Italic => DocxMark::Italic,
        TextMark::Underline => DocxMark::Underline,
        TextMark::Strike => DocxMark::Strike,
        TextMark::Subscript => DocxMark::Subscript,
        TextMark::Superscript => DocxMark::Superscript,
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
    /// Replace a paragraph's text and inline marks, keeping its role. A mark
    /// that changes on text the paragraph keeps lands as a tracked formatting
    /// change; new text carries its own marks on top of its neighbour's.
    SetRuns {
        block: String,
        runs: Vec<DocxRun>,
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
    /// The text as marked runs, joining to `text`; empty when no run carries
    /// a mark.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<DocxRun>,
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
        match change {
            DocxChange::SetText { block, text } => {
                let block = find(block)?;
                ops.push(json!({
                    "op": "replace",
                    "target": block.id.to_string(),
                    "guard": block.guard,
                    "content": paragraph(block.role_token.as_deref(), text),
                }));
            }
            DocxChange::SetRuns { block, runs } => {
                let block = find(block)?;
                // Formatting first: the guard pins text, not marks, so the
                // replace after it still reads the block it was read against.
                ops.extend(formats(block, runs)?);
                if runs_text(runs) != block.text {
                    ops.push(json!({
                        "op": "replace",
                        "target": block.id.to_string(),
                        "guard": block.guard,
                        "content": marked_paragraph(block.role_token.as_deref(), runs),
                    }));
                }
            }
            DocxChange::SetCell {
                block,
                row,
                col,
                text,
            } => ops.push(json!({
                "op": "table_op",
                "target": find(block)?.id.to_string(),
                "table_op": {"kind": "set_cell_text", "row_index": row, "col_index": col, "text": text},
            })),
            DocxChange::Move { block, anchor: to } => ops.push(json!({
                "op": "move",
                "target": find(block)?.id.to_string(),
                "destination": anchor(to)?,
            })),
            DocxChange::Insert {
                anchor: at,
                paragraphs,
            } => {
                let content = paragraphs
                    .iter()
                    .map(new_paragraph)
                    .collect::<Result<Vec<_>, _>>()?;
                ops.push(json!({"op": "insert", "target": anchor(at)?, "content": content}));
            }
            DocxChange::Delete { block } => {
                let block = find(block)?;
                ops.push(json!({"op": "delete", "target": block.id.to_string(), "guard": block.guard}));
            }
        }
    }
    if ops.is_empty() {
        return Ok(source.to_vec());
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

fn new_paragraph(new: &DocxParagraph) -> Result<Value, DoceditError> {
    if new.runs.is_empty() {
        Ok(paragraph(new.role.as_deref(), &new.text))
    } else if runs_text(&new.runs) == new.text {
        Ok(marked_paragraph(new.role.as_deref(), &new.runs))
    } else {
        Err(DoceditError::InvalidTransaction(
            "a new paragraph's runs do not read as its text".to_owned(),
        ))
    }
}

fn marked_paragraph(role: Option<&str>, runs: &[DocxRun]) -> Value {
    let content: Vec<Value> = runs
        .iter()
        .filter(|run| !run.text.is_empty())
        .map(|run| {
            let marks: Vec<Value> = run
                .marks
                .iter()
                .map(|mark| json!({"type": mark.key()}))
                .collect();
            json!({"type": "text", "text": run.text, "marks": marks})
        })
        .collect();
    json!({"type": "paragraph", "role": role, "content": content})
}

/// The tracked formatting changes that move the source paragraph's marks to
/// `runs` on the text both keep, aligned by a character diff. Each changed
/// stretch is addressed by its text and its copy among that text's repeats.
fn formats(block: &BlockView, runs: &[DocxRun]) -> Result<Vec<Value>, DoceditError> {
    let source = source_runs(block);
    if runs_text(&source) != block.text {
        return Err(DoceditError::InvalidTransaction(format!(
            "block {} does not read as plain runs",
            block.id
        )));
    }
    let (old, old_marks) = flatten(&source);
    let (new, new_marks) = flatten(runs);
    // Per source character: the marks it gains, and the marks it loses.
    let mut patch = vec![(0u8, 0u8); old.len()];
    for op in capture_diff_slices(Algorithm::Myers, &old, &new) {
        if let DiffOp::Equal {
            old_index,
            new_index,
            len,
        } = op
        {
            for offset in 0..len {
                let was = old_marks[old_index + offset];
                let now = new_marks[new_index + offset];
                patch[old_index + offset] = (now & !was, was & !now);
            }
        }
    }
    let mut ops = Vec::new();
    let mut start = 0;
    while start < old.len() {
        let change = patch[start];
        let end = start
            + patch[start..]
                .iter()
                .take_while(|other| **other == change)
                .count();
        if change != (0, 0) {
            let expect: String = old[start..end].iter().collect();
            let occurrence = copy(&block.text, &expect, start).ok_or_else(|| {
                DoceditError::InvalidTransaction(format!(
                    "block {}: a mark change on text its paragraph cannot address",
                    block.id
                ))
            })?;
            let mut marks = Map::new();
            for mark in DocxMark::ALL {
                if change.0 & mark.bit() != 0 {
                    marks.insert(mark.key().to_owned(), Value::Bool(true));
                }
                if change.1 & mark.bit() != 0 {
                    marks.insert(mark.key().to_owned(), Value::Bool(false));
                }
            }
            ops.push(json!({
                "op": "set_format",
                "target": block.id.to_string(),
                "expect": expect,
                "occurrence": occurrence,
                "semantic_hash": block.guard,
                "marks": marks,
            }));
        }
        start = end;
    }
    Ok(ops)
}

/// Each character of `runs` with its marks as bits.
fn flatten(runs: &[DocxRun]) -> (Vec<char>, Vec<u8>) {
    let mut chars = Vec::new();
    let mut marks = Vec::new();
    for run in runs {
        let bits = run.marks.iter().fold(0, |bits, mark| bits | mark.bit());
        for ch in run.text.chars() {
            chars.push(ch);
            marks.push(bits);
        }
    }
    (chars, marks)
}

/// The 1-based copy of `needle` that starts at character `at` of `haystack`,
/// among its non-overlapping matches, as the formatting verb counts them.
fn copy(haystack: &str, needle: &str, at: usize) -> Option<usize> {
    let (mut chars, mut byte) = (0, 0);
    for (index, (start, _)) in haystack.match_indices(needle).enumerate() {
        chars += haystack[byte..start].chars().count();
        byte = start;
        if chars >= at {
            return (chars == at).then_some(index + 1);
        }
    }
    None
}
