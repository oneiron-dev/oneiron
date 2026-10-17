//! The DOCX face of a live office body (ARCH-0075, "the body is the truth, the
//! file is a projection"). A plain block read feeds the import; the projection
//! writes a body's changes back into the imported package as one guarded,
//! tracked Word revision through the same gate as [`crate::revise`]. The body
//! itself (its Loro document, actors and forks) lives in the engine; this module
//! knows only DOCX.

use crate::{ArchiveLimits, DoceditError, Document, preflight_with_limits};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use similar::{Algorithm, DiffOp, capture_diff_slices};
use stemma::edit::EditTransaction;
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
    /// change, as does a Word mark new text takes from its neighbour that the
    /// body does not carry.
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
    let document = Document::parse(source)?;
    let view = document.read();
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
    let mut patches = Vec::new();
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
                // Formatting goes first, as a pass of its own: the guard pins
                // text, not marks, so the replace after it still reads the
                // block it was read against.
                if let Some(patch) = kept_marks(block, runs)? {
                    patches.push((block, patch));
                }
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
    if patches.is_empty() && ops.is_empty() {
        return Ok(source.to_vec());
    }
    let mut edited = document;
    if !patches.is_empty() {
        edited = remark(&edited, &patches, revision).ok_or_else(|| {
            DoceditError::InvalidTransaction(
                "a mark change on text its paragraph cannot address".to_owned(),
            )
        })?;
    }
    if !ops.is_empty() {
        edited = edited.apply(&native(ops, revision)?)?;
    }
    if let Some(remarked) = inherited(&edited, changes, revision) {
        edited = remarked;
    }
    crate::export_redline(&edited, limits)
}

/// `ops` as one tracked transaction under the projection's revision.
fn native(ops: Vec<Value>, revision: &DocxRevision) -> Result<EditTransaction, DoceditError> {
    let transaction = json!({
        "ops": ops,
        "revision": {"author": revision.author, "date": revision.date, "apply_op_id": revision.group},
    });
    crate::parse_native_revision(&transaction.to_string())
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

/// Per character of the source paragraph, the marks it gains and loses where
/// the body keeps it, aligned by a character diff. None when no kept mark
/// changes.
fn kept_marks(block: &BlockView, runs: &[DocxRun]) -> Result<Option<Vec<(u8, u8)>>, DoceditError> {
    let letters = letters(block);
    let old: Vec<char> = letters.iter().map(|letter| letter.ch).collect();
    if old.iter().collect::<String>() != block.text {
        return Err(DoceditError::InvalidTransaction(format!(
            "block {} does not read as plain runs",
            block.id
        )));
    }
    let (new, new_marks) = flatten(runs);
    let mut patch = vec![(0u8, 0u8); old.len()];
    for op in capture_diff_slices(Algorithm::Myers, &old, &new) {
        if let DiffOp::Equal {
            old_index,
            new_index,
            len,
        } = op
        {
            for offset in 0..len {
                let was = letters[old_index + offset].marks;
                let now = new_marks[new_index + offset];
                patch[old_index + offset] = (now & !was, was & !now);
            }
        }
    }
    Ok(patch
        .iter()
        .any(|change| *change != (0, 0))
        .then_some(patch))
}

/// Stemma's replace lays a new run's marks over its neighbour's Word
/// formatting, so text the body typed unmarked beside a bold word arrives
/// bold, and text typed at a paragraph's start takes the marks after it. This
/// pass gives each edited paragraph the body's marks again, except on a
/// character whose formatting the projection already changed. A paragraph
/// that no longer reads as its body, or a pass that cannot land, keeps the
/// replace as written.
fn inherited(
    edited: &Document,
    changes: &[DocxChange],
    revision: &DocxRevision,
) -> Option<Document> {
    let view = edited.read();
    let patches: Vec<_> = changes
        .iter()
        .filter_map(|change| {
            let DocxChange::SetRuns { block, runs } = change else {
                return None;
            };
            let block = live(&view.blocks, block)?;
            let letters = letters(block);
            let kept: Vec<usize> = (0..letters.len())
                .filter(|&at| {
                    !matches!(
                        letters[at].status,
                        TrackStatus::Deleted(_) | TrackStatus::InsertedThenDeleted { .. }
                    )
                })
                .collect();
            let (text, want) = flatten(runs);
            if !kept.iter().map(|&at| letters[at].ch).eq(text) {
                return None;
            }
            let mut patch = vec![(0u8, 0u8); letters.len()];
            for (&at, &now) in kept.iter().zip(&want) {
                let was = letters[at].marks;
                if !letters[at].revised {
                    patch[at] = (now & !was, was & !now);
                }
            }
            patch
                .iter()
                .any(|change| *change != (0, 0))
                .then_some((block, patch))
        })
        .collect();
    if patches.is_empty() {
        return None;
    }
    remark(edited, &patches, revision)
}

/// Apply tracked mark changes as one pass, each patch running over its
/// paragraph's [`letters`]. A changed stretch is addressed whole, or a
/// character at a time when it starts inside an overlapping repeat of its own
/// text. A pass that misses or lands elsewhere (a bookmark inside a stretch
/// splits the runs stemma matches within) is redone a character at a time,
/// which always addresses exactly. None when neither pass lands.
fn remark(
    document: &Document,
    patches: &[(&BlockView, Vec<(u8, u8)>)],
    revision: &DocxRevision,
) -> Option<Document> {
    [false, true].into_iter().find_map(|split| {
        let ops: Vec<Value> = patches
            .iter()
            .flat_map(|(block, patch)| set_formats(block, patch, split))
            .collect();
        let next = document.apply(&native(ops, revision).ok()?).ok()?;
        let view = next.read();
        patches
            .iter()
            .all(|(block, patch)| {
                let want = letters(block)
                    .into_iter()
                    .zip(patch)
                    .map(|(letter, (gain, lose))| (letter.ch, (letter.marks | gain) & !lose));
                live(&view.blocks, &block.id.to_string()).is_some_and(|landed| {
                    letters(landed)
                        .into_iter()
                        .map(|letter| (letter.ch, letter.marks))
                        .eq(want)
                })
            })
            .then_some(next)
    })
}

/// The `set_format` ops that move `block`'s letters by `patch`: one per
/// changed stretch within a tracked segment, or one per character when
/// `split`.
fn set_formats(block: &BlockView, patch: &[(u8, u8)], split: bool) -> Vec<Value> {
    let letters = letters(block);
    let len = patch.len().min(letters.len());
    let mut ops = Vec::new();
    let mut start = 0;
    while start < len {
        let change = patch[start];
        let end = if split {
            start + 1
        } else {
            start
                + patch[start..len]
                    .iter()
                    .zip(&letters[start..len])
                    .take_while(|(other, letter)| {
                        **other == change && letter.status == letters[start].status
                    })
                    .count()
        };
        if change != (0, 0) {
            match occurrence(&letters, start, end) {
                Some(copy) => ops.push(set_format(block, &letters[start..end], copy, change)),
                // One character always has a copy of its own.
                None => ops.extend((start..end).filter_map(|at| {
                    let copy = occurrence(&letters, at, at + 1)?;
                    Some(set_format(block, &letters[at..=at], copy, change))
                })),
            }
        }
        start = end;
    }
    ops
}

fn set_format(
    block: &BlockView,
    letters: &[Letter<'_>],
    occurrence: usize,
    (gain, lose): (u8, u8),
) -> Value {
    let mut marks = Map::new();
    for mark in DocxMark::ALL {
        if gain & mark.bit() != 0 {
            marks.insert(mark.key().to_owned(), Value::Bool(true));
        }
        if lose & mark.bit() != 0 {
            marks.insert(mark.key().to_owned(), Value::Bool(false));
        }
    }
    json!({
        "op": "set_format",
        "target": block.id.to_string(),
        "expect": letters.iter().map(|letter| letter.ch).collect::<String>(),
        "occurrence": occurrence,
        "semantic_hash": block.guard,
        "marks": marks,
    })
}

/// One character of a paragraph's text segments, deleted ones included, in
/// the order stemma's formatting verb numbers its matches.
struct Letter<'a> {
    ch: char,
    /// Its marks as bits.
    marks: u8,
    status: &'a TrackStatus,
    /// It already carries a pending formatting change.
    revised: bool,
}

fn letters(block: &BlockView) -> Vec<Letter<'_>> {
    let mut letters = Vec::new();
    for segment in &block.segments {
        if let SegmentView::Text {
            text,
            status,
            marks,
            format_revision,
            ..
        } = segment
        {
            let bits = marks
                .iter()
                .fold(0, |bits, mark| bits | text_mark(*mark).bit());
            letters.extend(text.chars().map(|ch| Letter {
                ch,
                marks: bits,
                status,
                revised: format_revision.is_some(),
            }));
        }
    }
    letters
}

/// The 1-based copy of `letters[start..end]` as stemma's formatting verb
/// numbers them: non-overlapping matches within each tracked segment, the
/// segments in order. None when the stretch starts inside an overlapping
/// repeat of its own text.
fn occurrence(letters: &[Letter<'_>], start: usize, end: usize) -> Option<usize> {
    let expect: String = letters[start..end].iter().map(|letter| letter.ch).collect();
    let (mut earlier, mut from) = (0, 0);
    while from < letters.len() {
        let to = from
            + letters[from..]
                .iter()
                .take_while(|letter| letter.status == letters[from].status)
                .count();
        let text: String = letters[from..to].iter().map(|letter| letter.ch).collect();
        if start < to {
            return copy(&text, &expect, start - from).map(|copy| earlier + copy);
        }
        earlier += text.matches(expect.as_str()).count();
        from = to;
    }
    None
}

/// The block `id` names in an edited document, unless a move or a delete
/// left it pending.
fn live<'a>(blocks: &'a [BlockView], id: &str) -> Option<&'a BlockView> {
    blocks
        .iter()
        .find(|block| block.id.to_string() == id && block.block_status == TrackStatus::Normal)
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
