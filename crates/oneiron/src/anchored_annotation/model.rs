//! Domain types: A1 ranges, format-typed locators, anchors, thread/comment/brief
//! structs, and the re-anchor op vocabulary.

use super::codec::validate_locator_text;
use super::reanchor::{col_to_letters, parse_a1_cell};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};

/// CLAIM predicate for a thread head (anchor + lifecycle state + drift).
pub const ANNOTATION_THREAD_PREDICATE: &str = "annotation.thread";

/// CLAIM predicate for one append-only comment in a thread.
pub const ANNOTATION_COMMENT_PREDICATE: &str = "annotation.comment";

/// CLAIM predicate recording that a thread was assigned into a task-brief.
pub const ANNOTATION_BRIEF_PREDICATE: &str = "annotation.brief";

/// Maximum byte length of a single comment body.
pub const ANNOTATION_COMMENT_TEXT_MAX_BYTES: usize = 16 * 1024;

/// Maximum byte length of a locator sheet / paragraph-path / shape-id field.
pub const ANNOTATION_LOCATOR_TEXT_MAX_BYTES: usize = 1024;

/// Maximum byte length of a stored A1 range string.
pub const ANNOTATION_LOCATOR_RANGE_MAX_BYTES: usize = 64;

pub(super) const FORMAT_XLSX: &str = "xlsx";

pub(super) const FORMAT_DOCX: &str = "docx";

pub(super) const FORMAT_PPTX: &str = "pptx";

pub(super) const STATE_OPEN: &str = "open";

pub(super) const STATE_RESOLVED: &str = "resolved";

// ---------------------------------------------------------------------------
// A1 ranges + format-typed locators
// ---------------------------------------------------------------------------

/// A rectangular xlsx cell range in 1-based inclusive `(col, row)` coordinates.
///
/// `B2:D5` parses to `{col_start: 2, col_end: 4, row_start: 2, row_end: 5}`;
/// a single cell `B2` parses to a 1x1 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct A1Range {
    /// 1-based inclusive first column.
    pub col_start: u32,
    /// 1-based inclusive last column.
    pub col_end: u32,
    /// 1-based inclusive first row.
    pub row_start: u32,
    /// 1-based inclusive last row.
    pub row_end: u32,
}

impl A1Range {
    /// Builds a range, rejecting non-positive bounds or start > end.
    #[must_use]
    pub fn new(col_start: u32, col_end: u32, row_start: u32, row_end: u32) -> Option<Self> {
        if col_start == 0 || row_start == 0 || col_start > col_end || row_start > row_end {
            return None;
        }
        Some(Self {
            col_start,
            col_end,
            row_start,
            row_end,
        })
    }

    /// Parses an A1 range (`B2:D5`) or single cell (`B2`), normalizing the
    /// corner order so start ≤ end on both axes.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if let Some((lhs, rhs)) = text.split_once(':') {
            let (c1, r1) = parse_a1_cell(lhs.trim())?;
            let (c2, r2) = parse_a1_cell(rhs.trim())?;
            Self::new(c1.min(c2), c1.max(c2), r1.min(r2), r1.max(r2))
        } else {
            let (col, row) = parse_a1_cell(text)?;
            Self::new(col, col, row, row)
        }
    }

    /// Renders the canonical A1 string (`B2` for a 1x1 range, else `B2:D5`).
    #[must_use]
    pub fn to_a1(&self) -> String {
        let start = format!("{}{}", col_to_letters(self.col_start), self.row_start);
        if self.col_start == self.col_end && self.row_start == self.row_end {
            start
        } else {
            format!("{start}:{}{}", col_to_letters(self.col_end), self.row_end)
        }
    }
}

/// A format-typed anchor locator.
///
/// Only the xlsx locator is parsed and re-anchored in P1. The docx and pptx
/// variants are registered locator TYPES (OF-368 D9 P2/P3) so anchors carry
/// them losslessly, but their span parsing and re-anchoring are deferred; a
/// version bump treats a non-xlsx locator as non-mappable (drifted) rather than
/// guessing a new position.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Locator {
    /// xlsx `{sheet, A1-range}` — IMPLEMENTED.
    Xlsx {
        /// Worksheet name.
        sheet: String,
        /// Cell range.
        range: A1Range,
    },
    /// docx `{para_path, char_span}` — TYPE registered, parsing deferred.
    Docx {
        /// Paragraph path within the document body.
        para_path: String,
        /// Inclusive character-span start.
        char_start: u64,
        /// Exclusive character-span end.
        char_end: u64,
    },
    /// pptx `{slide, shape_id}` — TYPE registered, parsing deferred.
    Pptx {
        /// 1-based slide index.
        slide: u64,
        /// Shape identifier on the slide.
        shape_id: String,
    },
}

impl Locator {
    /// Builds an xlsx locator, validating the sheet name and A1 range.
    pub fn xlsx(sheet: impl Into<String>, range: &str) -> Result<Self> {
        let sheet = sheet.into();
        validate_locator_text(&sheet, "xlsx locator sheet")?;
        if range.len() > ANNOTATION_LOCATOR_RANGE_MAX_BYTES {
            return Err(Error::Artifact(ArtifactError::InvalidAnchor(
                "xlsx locator range is too long",
            )));
        }
        let range = A1Range::parse(range).ok_or(Error::Artifact(ArtifactError::InvalidAnchor(
            "xlsx locator range is not A1",
        )))?;
        Ok(Self::Xlsx { sheet, range })
    }

    /// Builds a docx locator (span parsing deferred; bounds validated only).
    pub fn docx(para_path: impl Into<String>, char_start: u64, char_end: u64) -> Result<Self> {
        let para_path = para_path.into();
        validate_locator_text(&para_path, "docx locator para_path")?;
        if char_start > char_end {
            return Err(Error::Artifact(ArtifactError::InvalidAnchor(
                "docx locator char span is inverted",
            )));
        }
        Ok(Self::Docx {
            para_path,
            char_start,
            char_end,
        })
    }

    /// Builds a pptx locator (shape resolution deferred; fields validated only).
    pub fn pptx(slide: u64, shape_id: impl Into<String>) -> Result<Self> {
        let shape_id = shape_id.into();
        validate_locator_text(&shape_id, "pptx locator shape_id")?;
        if slide == 0 {
            return Err(Error::Artifact(ArtifactError::InvalidAnchor(
                "pptx locator slide must be 1-based",
            )));
        }
        Ok(Self::Pptx { slide, shape_id })
    }

    /// The format discriminator string.
    #[must_use]
    pub fn format(&self) -> &'static str {
        match self {
            Self::Xlsx { .. } => FORMAT_XLSX,
            Self::Docx { .. } => FORMAT_DOCX,
            Self::Pptx { .. } => FORMAT_PPTX,
        }
    }
}

/// An anchor: the artifact version a locator resolves against.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Anchor {
    /// The blob artifact this anchor lands on.
    pub artifact_id: EntityId,
    /// The artifact version the locator resolves against.
    pub version: u64,
    /// The format-typed position within that version.
    pub locator: Locator,
}

impl Anchor {
    /// Builds an anchor.
    #[must_use]
    pub fn new(artifact_id: EntityId, version: u64, locator: Locator) -> Self {
        Self {
            artifact_id,
            version,
            locator,
        }
    }
}

/// A thread's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Open / unresolved.
    Open,
    /// Resolved.
    Resolved,
}

impl ThreadState {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Open => STATE_OPEN,
            Self::Resolved => STATE_RESOLVED,
        }
    }

    pub(super) fn parse(text: &str) -> Option<Self> {
        match text {
            STATE_OPEN => Some(Self::Open),
            STATE_RESOLVED => Some(Self::Resolved),
            _ => None,
        }
    }
}

/// Records that a thread could not be re-anchored across a version bump and is
/// pinned to its original version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriftMarker {
    /// The new artifact version at which re-anchoring failed.
    pub drifted_at_version: u64,
    /// The version the thread stays pinned to (its origin).
    pub pinned_version: u64,
}

/// A reconstructed thread head.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnnotationThread {
    /// Stable thread identity.
    pub thread_id: EntityId,
    /// The current anchor. When drifted, `anchor.version` is the pinned origin.
    pub anchor: Anchor,
    /// The version the thread was first opened against.
    pub origin_version: u64,
    /// Lifecycle state.
    pub state: ThreadState,
    /// Drift status; `Some` means the anchor is pinned to its origin version.
    pub drift: Option<DriftMarker>,
    /// The `Active` head claim id (the supersession target for state changes).
    pub head_claim_id: EntityId,
}

impl AnnotationThread {
    /// Whether the thread's anchor has drifted off its original position.
    #[must_use]
    pub fn is_drifted(&self) -> bool {
        self.drift.is_some()
    }
}

/// One append-only comment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnnotationComment {
    /// The thread this comment belongs to.
    pub thread_id: EntityId,
    /// Author entity ref.
    pub author: EntityId,
    /// Comment body.
    pub text: String,
    /// Authored time (engine clock).
    pub at: u64,
    /// The comment's claim id.
    pub claim_id: EntityId,
}

/// The task-brief a thread assignment produces (OF-368 D4).
///
/// The brief is a productivity `TASK` entity plus a `brief:`-prefixed
/// correlation ref that downstream receipts/attempts project on (the B2 RS4
/// brief-rooted projection). It carries the anchor payload, the thread text,
/// and the `artifact@version` so the assigned agent has the full ask.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TaskBrief {
    /// The `brief:<thread hex>` correlation ref.
    pub brief_ref: String,
    /// The productivity TASK entity id.
    pub task_id: EntityId,
    /// The source thread.
    pub thread_id: EntityId,
    /// The anchor payload (artifact + version + locator).
    pub anchor: Anchor,
    /// The artifact version the anchor resolves against.
    pub artifact_version: u64,
    /// The concatenated thread transcript.
    pub thread_text: String,
    /// The assignee/@mention target, if one was given.
    pub assignee: Option<EntityId>,
}

// ---------------------------------------------------------------------------
// Re-anchor replay (D2 / D5 hook) — RECONCILIATION SEAM for ARTL-3
// ---------------------------------------------------------------------------

/// A minimal edit operation the re-anchor replay understands.
///
/// # Reconciliation with ARTL-3 (ONE-1553 / ONE-1554)
///
/// The canonical `EditManifest` type belongs to ARTL-3's edit-manifest
/// producer. This enum is deliberately NOT that type: it is the minimal subset
/// re-anchoring needs. ARTL-3 exposes [`crate::edit_roundtrip::AnchorEffect`]
/// as its self-contained reconciliation surface (one per structural op), and
/// ARTL-4 (settle, ONE-1554) lowers a manifest's anchor effects onto these
/// variants through [`From<&crate::edit_roundtrip::AnchorEffect>`], rather than
/// duplicating the manifest shape here. Rows and columns are 1-based; `count`
/// is a positive unit count.
///
/// The row/column/move variants were the original minimal subset; the two
/// sheet-level variants ([`ReanchorOp::RenameSheet`] /
/// [`ReanchorOp::RemoveSheet`]) were added with the ARTL-4 lowering so a
/// manifest that renames or deletes a sheet re-maps or drifts anchors on that
/// sheet rather than silently leaving them pinned to a stale sheet name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReanchorOp {
    /// Insert `count` rows above `at_row` on `sheet`.
    InsertRows {
        /// Target sheet.
        sheet: String,
        /// 1-based row the insertion happens above.
        at_row: u32,
        /// Number of rows inserted.
        count: u32,
    },
    /// Delete `count` rows starting at `at_row` on `sheet`.
    DeleteRows {
        /// Target sheet.
        sheet: String,
        /// 1-based first deleted row.
        at_row: u32,
        /// Number of rows deleted.
        count: u32,
    },
    /// Insert `count` columns left of `at_col` on `sheet`.
    InsertCols {
        /// Target sheet.
        sheet: String,
        /// 1-based column the insertion happens left of.
        at_col: u32,
        /// Number of columns inserted.
        count: u32,
    },
    /// Delete `count` columns starting at `at_col` on `sheet`.
    DeleteCols {
        /// Target sheet.
        sheet: String,
        /// 1-based first deleted column.
        at_col: u32,
        /// Number of columns deleted.
        count: u32,
    },
    /// Move the rectangular `from` range to `to` on `sheet`.
    MoveRange {
        /// Target sheet.
        sheet: String,
        /// Source range.
        from: A1Range,
        /// Destination range (same shape as `from`).
        to: A1Range,
    },
    /// Overwrite the values in `range` on `sheet` (no positional effect).
    WriteCells {
        /// Target sheet.
        sheet: String,
        /// The written range.
        range: A1Range,
    },
    /// Rename `from` to `to`. Anchors on `from` follow to the new sheet name.
    RenameSheet {
        /// The sheet name before the rename (the op's target).
        from: String,
        /// The sheet name after the rename.
        to: String,
    },
    /// Remove `sheet`. Anchors on it are destroyed and drift.
    RemoveSheet {
        /// The removed sheet (the op's target).
        sheet: String,
    },
}

impl ReanchorOp {
    /// The sheet an op targets — the name replay matches against the anchor's
    /// current sheet. For a rename this is the pre-rename (`from`) name.
    pub(super) fn sheet(&self) -> &str {
        match self {
            Self::InsertRows { sheet, .. }
            | Self::DeleteRows { sheet, .. }
            | Self::InsertCols { sheet, .. }
            | Self::DeleteCols { sheet, .. }
            | Self::MoveRange { sheet, .. }
            | Self::WriteCells { sheet, .. }
            | Self::RemoveSheet { sheet } => sheet,
            Self::RenameSheet { from, .. } => from,
        }
    }
}

/// The outcome of replaying an edit manifest against one locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReanchorOutcome {
    /// The anchor mapped to a new locator.
    Mapped(Locator),
    /// The anchor is non-mappable and must be marked drifted.
    Drifted,
}

/// Summary of a re-anchor sweep across one version bump.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ReanchorSummary {
    /// Threads whose anchors were re-mapped to the new version.
    pub remapped: Vec<AnnotationThread>,
    /// Threads whose anchors drifted and are now pinned to their origin.
    pub drifted: Vec<AnnotationThread>,
}
