//! ARTL-2 (OF-368 D2/D3/D4): anchored-comment threads over versioned blob
//! artifacts, plus thread → task-brief conversion.
//!
//! # Type-byte decision (OF-368 open question #4)
//!
//! Anchored-comment threads ride the **existing CLAIM band (type byte 0)** as
//! predicate-typed claims. They do NOT get their own StructuralKind type byte.
//!
//! Reasoning: OF-368 D3 rules that "comment threads are claims … CRDT-synced
//! like any claim". A CLAIM already carries every axis a thread needs —
//! author provenance (the `WriteEnvelope` actor + `ClaimSource`), an approval
//! axis, a lifecycle axis (`Active`/`Superseded`/`Retracted`), a world/scope
//! filter, and automatic Loro CRDT replication (CLAIM is not on any sync
//! skip-list). Minting a fresh entity-type byte would fork all of that and
//! re-implement serialization, sync mirroring, provenance, and consent for no
//! gain — exactly what "the viewer is disposable, memory is not" warns against.
//! It also matches two live precedents: the ARTL-1 `blob.version` LEDGER event
//! is a predicate-typed CLAIM (not a new byte), and the OF-367 context-receipt
//! field-set (ONE-1544) rode the existing receipt spine rather than minting a
//! new `receipt_kind`. So this unit registers three predicates in the CLAIM
//! band instead of a type byte.
//!
//! # Model
//!
//! A thread is identified by a `thread_id` ([`EntityId`]). All of a thread's
//! claims take the blob artifact entity as their `subj` (the same subject the
//! `blob.version` claim uses), so every thread + comment + brief for a workbook
//! is reachable through one `claims_for_subject(artifact_id)` sweep — the read
//! path a viewer overlay and a post-restart reload both use.
//!
//! * [`ANNOTATION_THREAD_PREDICATE`] — the thread **head**: anchor (locator +
//!   the version it resolves against), lifecycle state (open/resolved), origin
//!   version, and drift status. Mutable state is modeled by **superseding** the
//!   head with a new head claim, so exactly one head per thread stays `Active`.
//! * [`ANNOTATION_COMMENT_PREDICATE`] — one **append-only** comment. Comments
//!   are never superseded; author provenance rides both the comment value and
//!   the claim envelope.
//! * [`ANNOTATION_BRIEF_PREDICATE`] — the durable record that a thread was
//!   assigned into a task-brief (D4). The assignment is engine memory, never
//!   viewer-local.
//!
//! # Re-anchoring (D2 / D5 replay hook)
//!
//! On a new artifact version the anchors re-map by replaying the edit-manifest
//! ([`replay_locator`]). A non-mappable anchor is marked **DRIFTED** and pins to
//! its original version rather than lying about position. The op vocabulary
//! ([`ReanchorOp`]) is a MINIMAL local representation — see its docs for the
//! ARTL-3 reconciliation seam.

use rmpv::Value;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
use crate::error::{Error, Result};
use crate::types::{
    ClaimCandidate, ENTITY_ID_LEN, ENTITY_TYPE_TASK, EdgeActorClass, EdgeKind, EntityId, TaskRole,
    TimeRange, WriteActor, WriteEnvelope, WriteProvenance,
};

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

const KEY_THREAD_ID: &str = "thread_id";
const KEY_ORIGIN_VERSION: &str = "origin_version";
const KEY_ANCHOR_VERSION: &str = "anchor_version";
const KEY_STATE: &str = "state";
const KEY_LOCATOR: &str = "locator";
const KEY_DRIFT: &str = "drift";
const KEY_DRIFTED_AT_VERSION: &str = "drifted_at_version";
const KEY_PINNED_VERSION: &str = "pinned_version";
const KEY_AUTHOR: &str = "author";
const KEY_TEXT: &str = "text";
const KEY_AT: &str = "at";
const KEY_TASK_ID: &str = "task_id";
const KEY_BRIEF_REF: &str = "brief_ref";
const KEY_ASSIGNEE: &str = "assignee";
const KEY_TRANSCRIPT: &str = "transcript";

const KEY_FORMAT: &str = "format";
const KEY_SHEET: &str = "sheet";
const KEY_RANGE: &str = "range";
const KEY_PARA_PATH: &str = "para_path";
const KEY_CHAR_START: &str = "char_start";
const KEY_CHAR_END: &str = "char_end";
const KEY_SLIDE: &str = "slide";
const KEY_SHAPE_ID: &str = "shape_id";

const FORMAT_XLSX: &str = "xlsx";
const FORMAT_DOCX: &str = "docx";
const FORMAT_PPTX: &str = "pptx";

const STATE_OPEN: &str = "open";
const STATE_RESOLVED: &str = "resolved";

/// Task role byte for the productivity `role` body ("role": <byte>).
const TASK_BODY_ROLE_KEY: &str = "role";

/// Weight for the `AssignedTo` / `Mentions` edge a brief writes.
const BRIEF_ASSIGN_EDGE_WEIGHT: f32 = 1.0;

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
            return Err(Error::InvalidAnchor("xlsx locator range is too long"));
        }
        let range =
            A1Range::parse(range).ok_or(Error::InvalidAnchor("xlsx locator range is not A1"))?;
        Ok(Self::Xlsx { sheet, range })
    }

    /// Builds a docx locator (span parsing deferred; bounds validated only).
    pub fn docx(para_path: impl Into<String>, char_start: u64, char_end: u64) -> Result<Self> {
        let para_path = para_path.into();
        validate_locator_text(&para_path, "docx locator para_path")?;
        if char_start > char_end {
            return Err(Error::InvalidAnchor("docx locator char span is inverted"));
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
            return Err(Error::InvalidAnchor("pptx locator slide must be 1-based"));
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
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => STATE_OPEN,
            Self::Resolved => STATE_RESOLVED,
        }
    }

    fn parse(text: &str) -> Option<Self> {
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
/// correlation ref that downstream receipts/jobs project on (the B2 RS4
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
/// # Reconciliation seam (ARTL-3 / ONE-1553)
///
/// The canonical `EditManifest` type belongs to ARTL-3's edit-manifest
/// producer. This enum is deliberately NOT that type: it is the minimal subset
/// re-anchoring needs — whole row/column insert/delete, a rectangular range
/// move, and a cell-write marker. When ARTL-3 lands, reconcile by adding a
/// `From<EditManifestOp>` (or a thin adapter) that lowers its ops into these
/// variants, rather than duplicating the manifest shape here. Rows and columns
/// are 1-based; `count` is a positive unit count.
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
}

impl ReanchorOp {
    fn sheet(&self) -> &str {
        match self {
            Self::InsertRows { sheet, .. }
            | Self::DeleteRows { sheet, .. }
            | Self::InsertCols { sheet, .. }
            | Self::DeleteCols { sheet, .. }
            | Self::MoveRange { sheet, .. }
            | Self::WriteCells { sheet, .. } => sheet,
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

/// Replays a sequence of edit ops against a locator, returning its new position
/// or [`ReanchorOutcome::Drifted`] when the anchored region is destroyed or
/// becomes ambiguous. Ops on a different sheet leave the locator untouched.
///
/// Only xlsx locators are replayed in P1; any other locator format is treated
/// as non-mappable so the thread pins to its origin version rather than being
/// silently repositioned.
#[must_use]
pub fn replay_locator(locator: &Locator, ops: &[ReanchorOp]) -> ReanchorOutcome {
    let Locator::Xlsx { sheet, range } = locator else {
        return ReanchorOutcome::Drifted;
    };
    let mut cur = *range;
    for op in ops {
        if op.sheet() != sheet {
            continue;
        }
        match op {
            ReanchorOp::InsertRows { at_row, count, .. } => {
                if *count == 0 || *at_row == 0 {
                    continue;
                }
                match axis_insert(cur.row_start, cur.row_end, *at_row, *count) {
                    Some((start, end)) => {
                        cur.row_start = start;
                        cur.row_end = end;
                    }
                    None => return ReanchorOutcome::Drifted,
                }
            }
            ReanchorOp::DeleteRows { at_row, count, .. } => {
                if *count == 0 || *at_row == 0 {
                    continue;
                }
                match axis_delete(cur.row_start, cur.row_end, *at_row, *count) {
                    Some((start, end)) => {
                        cur.row_start = start;
                        cur.row_end = end;
                    }
                    None => return ReanchorOutcome::Drifted,
                }
            }
            ReanchorOp::InsertCols { at_col, count, .. } => {
                if *count == 0 || *at_col == 0 {
                    continue;
                }
                match axis_insert(cur.col_start, cur.col_end, *at_col, *count) {
                    Some((start, end)) => {
                        cur.col_start = start;
                        cur.col_end = end;
                    }
                    None => return ReanchorOutcome::Drifted,
                }
            }
            ReanchorOp::DeleteCols { at_col, count, .. } => {
                if *count == 0 || *at_col == 0 {
                    continue;
                }
                match axis_delete(cur.col_start, cur.col_end, *at_col, *count) {
                    Some((start, end)) => {
                        cur.col_start = start;
                        cur.col_end = end;
                    }
                    None => return ReanchorOutcome::Drifted,
                }
            }
            ReanchorOp::MoveRange { from, to, .. } => {
                if range_contains(from, &cur) {
                    let d_col = i64::from(to.col_start) - i64::from(from.col_start);
                    let d_row = i64::from(to.row_start) - i64::from(from.row_start);
                    match translate(&cur, d_col, d_row) {
                        Some(moved) => cur = moved,
                        None => return ReanchorOutcome::Drifted,
                    }
                } else if ranges_overlap(from, &cur) {
                    // Partial overlap is ambiguous: never guess a position.
                    return ReanchorOutcome::Drifted;
                }
            }
            ReanchorOp::WriteCells { .. } => {}
        }
    }
    ReanchorOutcome::Mapped(Locator::Xlsx {
        sheet: sheet.clone(),
        range: cur,
    })
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

// Axis transforms shared by the row and column cases. Bounds are 1-based.
// Arithmetic is checked: an anchor sitting near `u32::MAX` that a large insert
// (or delete-band) would push past the grid is non-mappable, so these return
// `None` and the caller drifts the thread rather than wrapping (release) or
// panicking (debug) into a corrupt locator.

fn axis_insert(start: u32, end: u32, at: u32, count: u32) -> Option<(u32, u32)> {
    let new_start = if start >= at {
        start.checked_add(count)?
    } else {
        start
    };
    let new_end = if end >= at {
        end.checked_add(count)?
    } else {
        end
    };
    Some((new_start, new_end))
}

fn axis_delete(start: u32, end: u32, at: u32, count: u32) -> Option<(u32, u32)> {
    let del_start = at;
    let del_end = at.checked_add(count)?.checked_sub(1)?;
    let new_start = if start < del_start {
        start
    } else if start > del_end {
        start - count
    } else {
        // Start sits inside the deleted band; it collapses to the band's edge.
        del_start
    };
    let new_end = if end < del_start {
        end
    } else if end > del_end {
        end - count
    } else {
        // End sits inside the deleted band; the last surviving row/col is just
        // before the band. If there is none, the whole region is destroyed.
        del_start.checked_sub(1)?
    };
    if new_start > new_end {
        None
    } else {
        Some((new_start, new_end))
    }
}

fn translate(range: &A1Range, d_col: i64, d_row: i64) -> Option<A1Range> {
    let col_start = u32::try_from(i64::from(range.col_start) + d_col).ok()?;
    let col_end = u32::try_from(i64::from(range.col_end) + d_col).ok()?;
    let row_start = u32::try_from(i64::from(range.row_start) + d_row).ok()?;
    let row_end = u32::try_from(i64::from(range.row_end) + d_row).ok()?;
    A1Range::new(col_start, col_end, row_start, row_end)
}

fn ranges_overlap(a: &A1Range, b: &A1Range) -> bool {
    a.col_start <= b.col_end
        && b.col_start <= a.col_end
        && a.row_start <= b.row_end
        && b.row_start <= a.row_end
}

fn range_contains(outer: &A1Range, inner: &A1Range) -> bool {
    outer.col_start <= inner.col_start
        && inner.col_end <= outer.col_end
        && outer.row_start <= inner.row_start
        && inner.row_end <= outer.row_end
}

fn parse_a1_cell(text: &str) -> Option<(u32, u32)> {
    if text.is_empty() {
        return None;
    }
    let split = text.bytes().position(|b| b.is_ascii_digit())?;
    let (letters, digits) = text.split_at(split);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let col = letters_to_col(letters)?;
    let row: u32 = digits.parse().ok()?;
    if row == 0 { None } else { Some((col, row)) }
}

fn letters_to_col(letters: &str) -> Option<u32> {
    if letters.is_empty() {
        return None;
    }
    let mut col: u32 = 0;
    for byte in letters.bytes() {
        if !byte.is_ascii_alphabetic() {
            return None;
        }
        let upper = byte.to_ascii_uppercase();
        col = col
            .checked_mul(26)?
            .checked_add(u32::from(upper - b'A') + 1)?;
    }
    Some(col)
}

fn col_to_letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        let rem = (col - 1) % 26;
        out.push(b'A' + u8::try_from(rem).unwrap_or(0));
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Value codecs
// ---------------------------------------------------------------------------

fn validate_locator_text(text: &str, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > ANNOTATION_LOCATOR_TEXT_MAX_BYTES {
        return Err(match context {
            "xlsx locator sheet" => Error::InvalidAnchor("xlsx locator sheet is empty or too long"),
            "docx locator para_path" => {
                Error::InvalidAnchor("docx locator para_path is empty or too long")
            }
            _ => Error::InvalidAnchor("pptx locator shape_id is empty or too long"),
        });
    }
    Ok(())
}

fn encode_locator(locator: &Locator) -> Value {
    match locator {
        Locator::Xlsx { sheet, range } => Value::Map(vec![
            (Value::from(KEY_FORMAT), Value::from(FORMAT_XLSX)),
            (Value::from(KEY_SHEET), Value::from(sheet.as_str())),
            (Value::from(KEY_RANGE), Value::from(range.to_a1())),
        ]),
        Locator::Docx {
            para_path,
            char_start,
            char_end,
        } => Value::Map(vec![
            (Value::from(KEY_FORMAT), Value::from(FORMAT_DOCX)),
            (Value::from(KEY_PARA_PATH), Value::from(para_path.as_str())),
            (Value::from(KEY_CHAR_START), Value::from(*char_start)),
            (Value::from(KEY_CHAR_END), Value::from(*char_end)),
        ]),
        Locator::Pptx { slide, shape_id } => Value::Map(vec![
            (Value::from(KEY_FORMAT), Value::from(FORMAT_PPTX)),
            (Value::from(KEY_SLIDE), Value::from(*slide)),
            (Value::from(KEY_SHAPE_ID), Value::from(shape_id.as_str())),
        ]),
    }
}

fn decode_locator(value: &Value) -> Result<Locator> {
    let format = map_str(value, KEY_FORMAT)?;
    match format {
        FORMAT_XLSX => {
            let sheet = map_str(value, KEY_SHEET)?.to_owned();
            let range = map_str(value, KEY_RANGE)?;
            Locator::xlsx(sheet, range)
        }
        FORMAT_DOCX => {
            let para_path = map_str(value, KEY_PARA_PATH)?.to_owned();
            let char_start = map_u64(value, KEY_CHAR_START)?;
            let char_end = map_u64(value, KEY_CHAR_END)?;
            Locator::docx(para_path, char_start, char_end)
        }
        FORMAT_PPTX => {
            let slide = map_u64(value, KEY_SLIDE)?;
            let shape_id = map_str(value, KEY_SHAPE_ID)?.to_owned();
            Locator::pptx(slide, shape_id)
        }
        _ => Err(Error::InvalidAnchor("unknown locator format")),
    }
}

struct ThreadHead {
    thread_id: EntityId,
    origin_version: u64,
    anchor_version: u64,
    state: ThreadState,
    locator: Locator,
    drift: Option<DriftMarker>,
}

fn encode_thread_head_value(head: &ThreadHead) -> Value {
    let mut entries = vec![
        (
            Value::from(KEY_THREAD_ID),
            Value::Binary(head.thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_ORIGIN_VERSION),
            Value::from(head.origin_version),
        ),
        (
            Value::from(KEY_ANCHOR_VERSION),
            Value::from(head.anchor_version),
        ),
        (Value::from(KEY_STATE), Value::from(head.state.as_str())),
        (Value::from(KEY_LOCATOR), encode_locator(&head.locator)),
    ];
    if let Some(drift) = head.drift {
        entries.push((
            Value::from(KEY_DRIFT),
            Value::Map(vec![
                (
                    Value::from(KEY_DRIFTED_AT_VERSION),
                    Value::from(drift.drifted_at_version),
                ),
                (
                    Value::from(KEY_PINNED_VERSION),
                    Value::from(drift.pinned_version),
                ),
            ]),
        ));
    }
    Value::Map(entries)
}

fn decode_thread_head(value: &Value) -> Result<ThreadHead> {
    let thread_id = map_entity(value, KEY_THREAD_ID)?;
    let origin_version = map_u64(value, KEY_ORIGIN_VERSION)?;
    let anchor_version = map_u64(value, KEY_ANCHOR_VERSION)?;
    let state = ThreadState::parse(map_str(value, KEY_STATE)?)
        .ok_or(Error::InvalidAnchor("thread state is unknown"))?;
    let locator = decode_locator(
        map_get(value, KEY_LOCATOR).ok_or(Error::InvalidAnchor("thread head missing locator"))?,
    )?;
    let drift = match map_get(value, KEY_DRIFT) {
        None | Some(Value::Nil) => None,
        Some(drift_value) => Some(DriftMarker {
            drifted_at_version: map_u64(drift_value, KEY_DRIFTED_AT_VERSION)?,
            pinned_version: map_u64(drift_value, KEY_PINNED_VERSION)?,
        }),
    };
    Ok(ThreadHead {
        thread_id,
        origin_version,
        anchor_version,
        state,
        locator,
        drift,
    })
}

fn encode_comment_value(thread_id: &EntityId, author: &EntityId, text: &str, at: u64) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_THREAD_ID),
            Value::Binary(thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_AUTHOR),
            Value::Binary(author.as_bytes().to_vec()),
        ),
        (Value::from(KEY_TEXT), Value::from(text)),
        (Value::from(KEY_AT), Value::from(at)),
    ])
}

fn decode_comment(value: &Value, claim_id: EntityId) -> Result<AnnotationComment> {
    Ok(AnnotationComment {
        thread_id: map_entity(value, KEY_THREAD_ID)?,
        author: map_entity(value, KEY_AUTHOR)?,
        text: map_str(value, KEY_TEXT)?.to_owned(),
        at: map_u64(value, KEY_AT)?,
        claim_id,
    })
}

fn encode_brief_value(
    thread_id: &EntityId,
    task_id: &EntityId,
    brief_ref: &str,
    anchor_version: u64,
    locator: &Locator,
    assignee: Option<&EntityId>,
    transcript: &str,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_THREAD_ID),
            Value::Binary(thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_TASK_ID),
            Value::Binary(task_id.as_bytes().to_vec()),
        ),
        (Value::from(KEY_BRIEF_REF), Value::from(brief_ref)),
        (Value::from(KEY_ANCHOR_VERSION), Value::from(anchor_version)),
        (Value::from(KEY_LOCATOR), encode_locator(locator)),
        (
            Value::from(KEY_ASSIGNEE),
            assignee.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (Value::from(KEY_TRANSCRIPT), Value::from(transcript)),
    ])
}

fn decode_brief_value(value: &Value, artifact_id: EntityId) -> Result<TaskBrief> {
    let thread_id = map_entity(value, KEY_THREAD_ID)?;
    let task_id = map_entity(value, KEY_TASK_ID)?;
    let brief_ref = map_str(value, KEY_BRIEF_REF)?.to_owned();
    let anchor_version = map_u64(value, KEY_ANCHOR_VERSION)?;
    let locator = decode_locator(
        map_get(value, KEY_LOCATOR).ok_or(Error::InvalidAnchor("brief missing locator"))?,
    )?;
    let assignee = match map_get(value, KEY_ASSIGNEE) {
        None | Some(Value::Nil) => None,
        Some(_) => Some(map_entity(value, KEY_ASSIGNEE)?),
    };
    let thread_text = map_str(value, KEY_TRANSCRIPT)?.to_owned();
    Ok(TaskBrief {
        brief_ref,
        task_id,
        thread_id,
        anchor: Anchor {
            artifact_id,
            version: anchor_version,
            locator,
        },
        artifact_version: anchor_version,
        thread_text,
        assignee,
    })
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, entry_value)| entry_value)
}

fn map_str<'a>(value: &'a Value, key: &'static str) -> Result<&'a str> {
    map_get(value, key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidAnchor(key))
}

fn map_u64(value: &Value, key: &'static str) -> Result<u64> {
    map_get(value, key)
        .and_then(Value::as_u64)
        .ok_or(Error::InvalidAnchor(key))
}

fn map_entity(value: &Value, key: &'static str) -> Result<EntityId> {
    let Some(Value::Binary(bytes)) = map_get(value, key) else {
        return Err(Error::InvalidAnchor(key));
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidAnchor(key))?;
    EntityId::from_bytes(raw).map_err(|_| Error::InvalidAnchor(key))
}

fn annotation_stances(actor_class: EdgeActorClass) -> (ClaimSource, ClaimApprovalStatus) {
    match actor_class {
        EdgeActorClass::Human => (ClaimSource::UserStated, ClaimApprovalStatus::Auto),
        EdgeActorClass::Agent => (ClaimSource::Generated, ClaimApprovalStatus::Proposed),
        EdgeActorClass::System => (ClaimSource::Observed, ClaimApprovalStatus::Auto),
    }
}

fn annotation_envelope(actor: WriteActor, op: &'static str) -> Result<WriteEnvelope> {
    let (source, approval) = annotation_stances(actor.actor_class());
    let provenance = WriteProvenance::new(Value::Map(vec![
        (Value::from("surface"), Value::from("anchored_annotation")),
        (Value::from("op"), Value::from(op)),
    ]))?;
    Ok(WriteEnvelope::new(actor, source, provenance, approval))
}

fn task_role_body(role: TaskRole) -> Result<Vec<u8>> {
    let value = Value::Map(vec![(
        Value::from(TASK_BODY_ROLE_KEY),
        Value::from(role.role_byte()),
    )]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .map_err(|_| Error::InvariantViolation("TASK role body MessagePack encode failed"))?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Vault surface
// ---------------------------------------------------------------------------

impl Vault {
    /// Opens an anchored-comment thread with its first comment.
    ///
    /// Writes the thread head and the opening comment as CLAIMs on the blob
    /// artifact entity in one transaction. The anchor version must resolve to a
    /// real version in the artifact's chain.
    pub fn open_annotation_thread(
        &self,
        anchor: &Anchor,
        author: WriteActor,
        first_comment: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AnnotationThread> {
        self.require_anchor_version(&anchor.artifact_id, anchor.version)?;
        validate_comment_text(first_comment)?;

        let thread_id = EntityId::now();
        let head_claim_id = EntityId::now();
        let comment_claim_id = EntityId::now();
        let head = ThreadHead {
            thread_id,
            origin_version: anchor.version,
            anchor_version: anchor.version,
            state: ThreadState::Open,
            locator: anchor.locator.clone(),
            drift: None,
        };
        let head_envelope = annotation_envelope(author, "open_thread")?;
        let comment_envelope = annotation_envelope(author, "comment")?;
        let author_id = author.entity_ref();

        self.with_write_txn(|wtxn| {
            self.batch_in()
                .claim_candidate(
                    &head_claim_id,
                    ClaimCandidate::new(
                        ANNOTATION_THREAD_PREDICATE,
                        ClaimSubject::Entity(anchor.artifact_id),
                        encode_thread_head_value(&head),
                        1.0,
                    ),
                    &head_envelope,
                    occurred,
                    learned_at,
                )
                .claim_candidate(
                    &comment_claim_id,
                    ClaimCandidate::new(
                        ANNOTATION_COMMENT_PREDICATE,
                        ClaimSubject::Entity(anchor.artifact_id),
                        encode_comment_value(&thread_id, &author_id, first_comment, learned_at),
                        1.0,
                    ),
                    &comment_envelope,
                    occurred,
                    learned_at,
                )
                .apply(wtxn)
        })?;

        Ok(AnnotationThread {
            thread_id,
            anchor: anchor.clone(),
            origin_version: anchor.version,
            state: ThreadState::Open,
            drift: None,
            head_claim_id,
        })
    }

    /// Appends a comment to an existing thread.
    pub fn add_annotation_comment(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
        author: WriteActor,
        text: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AnnotationComment> {
        validate_comment_text(text)?;
        // Fail closed if the thread does not exist for this artifact.
        self.get_annotation_thread(artifact_id, thread_id)?
            .ok_or(Error::AnnotationThreadNotFound)?;

        let claim_id = EntityId::now();
        let envelope = annotation_envelope(author, "comment")?;
        let author_id = author.entity_ref();
        self.with_write_txn(|wtxn| {
            self.batch_in()
                .claim_candidate(
                    &claim_id,
                    ClaimCandidate::new(
                        ANNOTATION_COMMENT_PREDICATE,
                        ClaimSubject::Entity(*artifact_id),
                        encode_comment_value(thread_id, &author_id, text, learned_at),
                        1.0,
                    ),
                    &envelope,
                    occurred,
                    learned_at,
                )
                .apply(wtxn)
        })?;

        Ok(AnnotationComment {
            thread_id: *thread_id,
            author: author_id,
            text: text.to_owned(),
            at: learned_at,
            claim_id,
        })
    }

    /// Transitions a thread's lifecycle state (open ⇄ resolved) by superseding
    /// its head with an updated head claim.
    ///
    /// The new head write and the old head supersession share ONE write
    /// transaction, so if the supersession's fail-closed guards reject (e.g. an
    /// agent claim trying to supersede human-stated truth) nothing persists —
    /// the original head stays the single live head and no orphan claim is left
    /// behind.
    pub fn set_annotation_thread_state(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
        state: ThreadState,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<AnnotationThread> {
        let thread = self
            .get_annotation_thread(artifact_id, thread_id)?
            .ok_or(Error::AnnotationThreadNotFound)?;
        let head = ThreadHead {
            thread_id: *thread_id,
            origin_version: thread.origin_version,
            anchor_version: thread.anchor.version,
            state,
            locator: thread.anchor.locator.clone(),
            drift: thread.drift,
        };
        let new_head_id = self.with_write_txn(|wtxn| {
            let new_head_id = self.write_thread_head_in_txn(
                wtxn,
                artifact_id,
                &head,
                actor,
                "set_state",
                occurred,
                learned_at,
            )?;
            self.supersede_claim_in_txn(wtxn, &new_head_id, &thread.head_claim_id, learned_at)?;
            Ok(new_head_id)
        })?;
        Ok(AnnotationThread {
            thread_id: *thread_id,
            anchor: thread.anchor,
            origin_version: thread.origin_version,
            state,
            drift: thread.drift,
            head_claim_id: new_head_id,
        })
    }

    /// Reads a single thread head, or `None` if no live thread with that id is
    /// anchored on the artifact.
    pub fn get_annotation_thread(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
    ) -> Result<Option<AnnotationThread>> {
        let mut best: Option<(EntityId, ThreadHead)> = None;
        for (claim_id, body) in self.active_annotation_claims(artifact_id)? {
            if body.predicate != ANNOTATION_THREAD_PREDICATE {
                continue;
            }
            let head = match decode_thread_head(&body.value) {
                Ok(head) => head,
                Err(err) => {
                    warn_malformed_annotation_claim(claim_id, &body.predicate, &err);
                    continue;
                }
            };
            if head.thread_id != *thread_id {
                continue;
            }
            // Newest head (by UUIDv7 id) wins, so a torn supersede that left two
            // Active heads still resolves to the latest write.
            if best.as_ref().is_none_or(|(id, _)| claim_id > *id) {
                best = Some((claim_id, head));
            }
        }
        Ok(best.map(|(claim_id, head)| thread_from_head(*artifact_id, claim_id, head)))
    }

    /// Lists all live thread heads anchored on an artifact.
    pub fn annotation_threads_for_artifact(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<AnnotationThread>> {
        // Group by thread id, keeping the newest Active head per thread.
        let mut heads: Vec<(EntityId, EntityId, ThreadHead)> = Vec::new();
        for (claim_id, body) in self.active_annotation_claims(artifact_id)? {
            if body.predicate != ANNOTATION_THREAD_PREDICATE {
                continue;
            }
            let head = match decode_thread_head(&body.value) {
                Ok(head) => head,
                Err(err) => {
                    warn_malformed_annotation_claim(claim_id, &body.predicate, &err);
                    continue;
                }
            };
            match heads.iter_mut().find(|(tid, _, _)| *tid == head.thread_id) {
                Some((_, existing_id, existing_head)) if claim_id > *existing_id => {
                    *existing_id = claim_id;
                    *existing_head = head;
                }
                Some(_) => {}
                None => heads.push((head.thread_id, claim_id, head)),
            }
        }
        let mut threads: Vec<AnnotationThread> = heads
            .into_iter()
            .map(|(_, claim_id, head)| thread_from_head(*artifact_id, claim_id, head))
            .collect();
        threads.sort_by_key(|thread| thread.thread_id);
        Ok(threads)
    }

    /// Reads a thread's comments, ordered by authored time then claim id.
    pub fn annotation_thread_comments(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
    ) -> Result<Vec<AnnotationComment>> {
        let mut comments = Vec::new();
        for (claim_id, body) in self.active_annotation_claims(artifact_id)? {
            if body.predicate != ANNOTATION_COMMENT_PREDICATE {
                continue;
            }
            let comment = match decode_comment(&body.value, claim_id) {
                Ok(comment) => comment,
                Err(err) => {
                    warn_malformed_annotation_claim(claim_id, &body.predicate, &err);
                    continue;
                }
            };
            if comment.thread_id != *thread_id {
                continue;
            }
            comments.push(comment);
        }
        comments.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.claim_id.cmp(&b.claim_id)));
        Ok(comments)
    }

    /// Re-anchors every live, non-drifted thread on the artifact whose anchor
    /// resolves against `from_version`, replaying `ops` (the edit-manifest for
    /// the `from_version → to_version` bump).
    ///
    /// A mappable anchor advances to `to_version` with its new locator; a
    /// non-mappable one is marked DRIFTED and stays pinned to `from_version`,
    /// never silently repositioned. Each change writes the new head and
    /// supersedes the old one in ONE write transaction, so a rejected
    /// supersession leaves that thread's original head live with no orphan.
    ///
    /// `to_version` must resolve to a real version in the artifact's chain
    /// (the same guard thread-open applies), so a replay against a not-yet-
    /// appended or bogus version writes no heads pointing at nonexistent
    /// versions.
    #[expect(clippy::too_many_arguments)]
    pub fn reanchor_annotation_threads(
        &self,
        artifact_id: &EntityId,
        from_version: u64,
        to_version: u64,
        ops: &[ReanchorOp],
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<ReanchorSummary> {
        self.require_anchor_version(artifact_id, to_version)?;
        let mut summary = ReanchorSummary::default();
        for thread in self.annotation_threads_for_artifact(artifact_id)? {
            if thread.is_drifted() || thread.anchor.version != from_version {
                continue;
            }
            let (head, drifted) = match replay_locator(&thread.anchor.locator, ops) {
                ReanchorOutcome::Mapped(locator) => (
                    ThreadHead {
                        thread_id: thread.thread_id,
                        origin_version: thread.origin_version,
                        anchor_version: to_version,
                        state: thread.state,
                        locator,
                        drift: None,
                    },
                    false,
                ),
                ReanchorOutcome::Drifted => (
                    ThreadHead {
                        thread_id: thread.thread_id,
                        origin_version: thread.origin_version,
                        anchor_version: from_version,
                        state: thread.state,
                        locator: thread.anchor.locator.clone(),
                        drift: Some(DriftMarker {
                            drifted_at_version: to_version,
                            pinned_version: from_version,
                        }),
                    },
                    true,
                ),
            };
            let new_head_id = self.with_write_txn(|wtxn| {
                let new_head_id = self.write_thread_head_in_txn(
                    wtxn,
                    artifact_id,
                    &head,
                    actor,
                    "reanchor",
                    occurred,
                    learned_at,
                )?;
                self.supersede_claim_in_txn(wtxn, &new_head_id, &thread.head_claim_id, learned_at)?;
                Ok(new_head_id)
            })?;
            let updated = thread_from_head(*artifact_id, new_head_id, head);
            if drifted {
                summary.drifted.push(updated);
            } else {
                summary.remapped.push(updated);
            }
        }
        Ok(summary)
    }

    /// Converts a thread into a task-brief (OF-368 D4).
    ///
    /// Writes a productivity `TASK` entity, a durable `annotation.brief` claim
    /// linking the thread to that task with the anchor payload, and — when an
    /// assignee is supplied — an `AssignedTo` edge. Returns the assembled brief
    /// carrying the anchor, the thread transcript, and the `artifact@version`.
    ///
    /// The transcript snapshot taken at assignment time is persisted IN the
    /// brief claim value, so the handed-off brief is stable: comments appended
    /// after the assignment do not change what
    /// [`Vault::annotation_brief_for_thread`] reconstructs.
    pub fn assign_annotation_thread_to_brief(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
        assignee: Option<EntityId>,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<TaskBrief> {
        let thread = self
            .get_annotation_thread(artifact_id, thread_id)?
            .ok_or(Error::AnnotationThreadNotFound)?;
        let comments = self.annotation_thread_comments(artifact_id, thread_id)?;
        let thread_text = comments
            .iter()
            .map(|comment| comment.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let task_id = EntityId::now();
        let brief_claim_id = EntityId::now();
        let brief_ref = format!("brief:{}", thread_id.to_hex());
        let task_body = task_role_body(TaskRole::Task)?;
        let brief_envelope = annotation_envelope(actor, "assign_brief")?;
        let brief_value = encode_brief_value(
            thread_id,
            &task_id,
            &brief_ref,
            thread.anchor.version,
            &thread.anchor.locator,
            assignee.as_ref(),
            &thread_text,
        );

        self.with_write_txn(|wtxn| {
            let mut batch = self
                .batch_in()
                .put(&task_id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body)
                .claim_candidate(
                    &brief_claim_id,
                    ClaimCandidate::new(
                        ANNOTATION_BRIEF_PREDICATE,
                        ClaimSubject::Entity(*artifact_id),
                        brief_value,
                        1.0,
                    ),
                    &brief_envelope,
                    occurred,
                    learned_at,
                );
            if let Some(assignee_id) = assignee {
                batch = batch.edge(
                    &task_id,
                    EdgeKind::AssignedTo,
                    &assignee_id,
                    BRIEF_ASSIGN_EDGE_WEIGHT,
                );
            }
            batch.apply(wtxn)
        })?;

        let artifact_version = thread.anchor.version;
        Ok(TaskBrief {
            brief_ref,
            task_id,
            thread_id: *thread_id,
            anchor: thread.anchor,
            artifact_version,
            thread_text,
            assignee,
        })
    }

    /// Reconstructs the durable brief for `thread_id` from its persisted
    /// `annotation.brief` claim, or `None` if the thread was never assigned.
    ///
    /// The returned brief carries the transcript snapshot captured at
    /// assignment time (stored in the claim value), so it is stable against
    /// comments appended after the assignment — the handed-off ask does not
    /// silently rewrite itself. When a thread was assigned more than once the
    /// newest brief (by UUIDv7 claim id) wins.
    pub fn annotation_brief_for_thread(
        &self,
        artifact_id: &EntityId,
        thread_id: &EntityId,
    ) -> Result<Option<TaskBrief>> {
        let mut best: Option<(EntityId, TaskBrief)> = None;
        for (claim_id, body) in self.active_annotation_claims(artifact_id)? {
            if body.predicate != ANNOTATION_BRIEF_PREDICATE {
                continue;
            }
            let brief = match decode_brief_value(&body.value, *artifact_id) {
                Ok(brief) => brief,
                Err(err) => {
                    warn_malformed_annotation_claim(claim_id, &body.predicate, &err);
                    continue;
                }
            };
            if brief.thread_id != *thread_id {
                continue;
            }
            if best.as_ref().is_none_or(|(id, _)| claim_id > *id) {
                best = Some((claim_id, brief));
            }
        }
        Ok(best.map(|(_, brief)| brief))
    }

    /// Writes a fresh thread-head claim inside the caller's write transaction
    /// and returns its id. Kept txn-composable (rather than opening its own
    /// txn) so the head write and the paired [`Vault::supersede_claim_in_txn`]
    /// of the old head commit or roll back together.
    #[expect(clippy::too_many_arguments)]
    fn write_thread_head_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        head: &ThreadHead,
        actor: WriteActor,
        op: &'static str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let claim_id = EntityId::now();
        let envelope = annotation_envelope(actor, op)?;
        let value = encode_thread_head_value(head);
        self.batch_in()
            .claim_candidate(
                &claim_id,
                ClaimCandidate::new(
                    ANNOTATION_THREAD_PREDICATE,
                    ClaimSubject::Entity(*artifact_id),
                    value,
                    1.0,
                ),
                &envelope,
                occurred,
                learned_at,
            )
            .apply(wtxn)?;
        Ok(claim_id)
    }

    fn require_anchor_version(&self, artifact_id: &EntityId, version: u64) -> Result<()> {
        if version == 0 {
            return Err(Error::InvalidAnchor("anchor version must be at least 1"));
        }
        let head = self
            .blob_artifact_head(artifact_id)?
            .ok_or(Error::InvalidAnchor("anchor artifact has no versions"))?;
        if version > head.version {
            return Err(Error::InvalidAnchor(
                "anchor version is beyond the artifact head",
            ));
        }
        Ok(())
    }

    /// The live-read cohort of annotation claims on `artifact_id`: only claims
    /// that pass the engine's standard read gate
    /// ([`crate::claim::claim_surfaceable`] — `appr ∈ {auto, approved}`,
    /// `life = active`, not stale).
    ///
    /// Gating here (rather than on bare `life = active`) keeps agent-authored
    /// `Proposed` heads and stale claims out of every live read that flows
    /// through this helper — thread + comment reads, brief assignment, and
    /// newest-head selection — so a non-admitted head can never override an
    /// admitted one on read. History / consent-review still goes through the
    /// ungated [`crate::Vault::get_claim`] door.
    fn active_annotation_claims(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut out = Vec::new();
        for claim_id in self.claims_for_subject(artifact_id)? {
            let Some(body) = self.get_claim(&claim_id)? else {
                continue;
            };
            if crate::claim::claim_surfaceable(&body) && is_annotation_predicate(&body.predicate) {
                out.push((claim_id, body));
            }
        }
        Ok(out)
    }
}

/// Quarantines a single malformed annotation claim value on a read path.
///
/// Annotation predicates ride the generic CLAIM band, so a malformed value can
/// be written through the generic claim API. Failing the whole listing on one
/// such value would let a single garbage claim take down every thread/comment
/// read for the artifact, so the read helpers skip the bad value (tracing it)
/// and keep serving the well-formed claims.
fn warn_malformed_annotation_claim(claim_id: EntityId, predicate: &str, err: &Error) {
    tracing::warn!(
        claim_id = %claim_id.to_hex(),
        predicate,
        error = ?err,
        "skipping malformed annotation claim value on read",
    );
}

fn is_annotation_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        ANNOTATION_THREAD_PREDICATE | ANNOTATION_COMMENT_PREDICATE | ANNOTATION_BRIEF_PREDICATE
    )
}

fn thread_from_head(
    artifact_id: EntityId,
    head_claim_id: EntityId,
    head: ThreadHead,
) -> AnnotationThread {
    AnnotationThread {
        thread_id: head.thread_id,
        anchor: Anchor {
            artifact_id,
            version: head.anchor_version,
            locator: head.locator,
        },
        origin_version: head.origin_version,
        state: head.state,
        drift: head.drift,
        head_claim_id,
    }
}

fn validate_comment_text(text: &str) -> Result<()> {
    if text.is_empty() {
        return Err(Error::InvalidAnchor("comment text must be non-empty"));
    }
    if text.len() > ANNOTATION_COMMENT_TEXT_MAX_BYTES {
        return Err(Error::InvalidAnchor("comment text is too long"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use crate::types::{ENTITY_TYPE_PERSON, HnswConfig, TextAnalyzerConfig, VaultConfig};

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config.text_analyzer = TextAnalyzerConfig::default();
        config
    }

    fn test_time(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    /// Mirrors `test_util::open_test_vault_with`'s fixture cleanup for tests
    /// that open a vault directly (to reopen the same path).
    fn clear_default_policy_manifest(vault: &Vault) {
        let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
        vault
            .with_write_txn(|wtxn| {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
                Ok(())
            })
            .expect("clear default policy manifest");
    }

    fn put_actor(vault: &Vault, at: u64) -> WriteActor {
        let actor_id = EntityId::now();
        vault
            .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(at), at, b"human")
            .expect("put actor");
        WriteActor::new(actor_id, EdgeActorClass::Human)
    }

    fn put_agent_actor(vault: &Vault, at: u64) -> WriteActor {
        let actor_id = EntityId::now();
        vault
            .put_entity(&actor_id, ENTITY_TYPE_PERSON, test_time(at), at, b"agent")
            .expect("put agent actor");
        WriteActor::new(actor_id, EdgeActorClass::Agent)
    }

    fn put_workbook(vault: &Vault, actor: WriteActor, at: u64) -> EntityId {
        let artifact_id = EntityId::now();
        vault
            .put_blob_artifact(
                &artifact_id,
                &BlobArtifactBody::new(
                    "forecast.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ),
                test_time(at),
                at,
            )
            .expect("put workbook");
        vault
            .append_blob_artifact_version(
                &artifact_id,
                b"workbook bytes v1",
                &BlobVersionProvenance::UserUpload,
                actor,
                test_time(at),
                at,
            )
            .expect("append v1");
        artifact_id
    }

    fn xlsx_anchor(artifact_id: EntityId, version: u64, sheet: &str, range: &str) -> Anchor {
        Anchor::new(
            artifact_id,
            version,
            Locator::xlsx(sheet, range).expect("xlsx locator"),
        )
    }

    /// The ids of every LIVE (`life = active`) thread-head claim on the
    /// artifact, regardless of approval — the ungated cohort, so tests can
    /// prove the read gate reduces it and that no orphan head leaked.
    fn live_thread_head_claim_ids(vault: &Vault, artifact_id: &EntityId) -> Vec<EntityId> {
        let mut ids = Vec::new();
        for claim_id in vault
            .claims_for_subject(artifact_id)
            .expect("claims for subject")
        {
            let Some(body) = vault.get_claim(&claim_id).expect("get claim") else {
                continue;
            };
            if body.predicate == ANNOTATION_THREAD_PREDICATE
                && body.lifecycle == crate::claim::ClaimLifecycleStatus::Active
            {
                ids.push(claim_id);
            }
        }
        ids
    }

    #[test]
    fn a1_range_round_trips_and_normalizes() {
        assert_eq!(
            A1Range::parse("B2").map(|r| r.to_a1()).as_deref(),
            Some("B2")
        );
        assert_eq!(
            A1Range::parse("b2:d5").map(|r| r.to_a1()).as_deref(),
            Some("B2:D5")
        );
        // Reversed corners normalize.
        assert_eq!(
            A1Range::parse("D5:B2").map(|r| r.to_a1()).as_deref(),
            Some("B2:D5")
        );
        assert_eq!(A1Range::parse("AA1").map(|r| r.col_start), Some(27));
        assert_eq!(A1Range::parse(""), None);
        assert_eq!(A1Range::parse("2B"), None);
        assert_eq!(A1Range::parse("B0"), None);
    }

    #[test]
    fn replay_moves_anchor_on_row_insert_and_delete() {
        let locator = Locator::xlsx("Sheet1", "B5:D8").expect("locator");
        // Insert 2 rows above row 3: the anchored block shifts down by 2.
        let inserted = replay_locator(
            &locator,
            &[ReanchorOp::InsertRows {
                sheet: "Sheet1".to_owned(),
                at_row: 3,
                count: 2,
            }],
        );
        assert_eq!(
            inserted,
            ReanchorOutcome::Mapped(Locator::xlsx("Sheet1", "B7:D10").expect("locator"))
        );
        // Delete 2 rows above the block: it shifts up by 2.
        let deleted = replay_locator(
            &locator,
            &[ReanchorOp::DeleteRows {
                sheet: "Sheet1".to_owned(),
                at_row: 1,
                count: 2,
            }],
        );
        assert_eq!(
            deleted,
            ReanchorOutcome::Mapped(Locator::xlsx("Sheet1", "B3:D6").expect("locator"))
        );
        // Edits on another sheet do not move the anchor.
        let other_sheet = replay_locator(
            &locator,
            &[ReanchorOp::DeleteRows {
                sheet: "Sheet2".to_owned(),
                at_row: 1,
                count: 4,
            }],
        );
        assert_eq!(other_sheet, ReanchorOutcome::Mapped(locator));
    }

    #[test]
    fn replay_drifts_when_region_destroyed_or_ambiguous() {
        let locator = Locator::xlsx("Sheet1", "B5:C6").expect("locator");
        // Deleting every anchored row destroys the region.
        let destroyed = replay_locator(
            &locator,
            &[ReanchorOp::DeleteRows {
                sheet: "Sheet1".to_owned(),
                at_row: 5,
                count: 2,
            }],
        );
        assert_eq!(destroyed, ReanchorOutcome::Drifted);
        // A partial move overlap is ambiguous.
        let ambiguous = replay_locator(
            &locator,
            &[ReanchorOp::MoveRange {
                sheet: "Sheet1".to_owned(),
                from: A1Range::parse("C6:E9").expect("from"),
                to: A1Range::parse("H6:J9").expect("to"),
            }],
        );
        assert_eq!(ambiguous, ReanchorOutcome::Drifted);
        // Non-xlsx locators are non-mappable under the xlsx replay.
        let docx = Locator::docx("body/p[3]", 0, 12).expect("docx");
        assert_eq!(replay_locator(&docx, &[]), ReanchorOutcome::Drifted);
    }

    // Acceptance test 1: a thread is engine memory, not viewer state — it
    // survives the viewer (process) dying and reloads from disk.
    #[test]
    fn thread_survives_viewer_death() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path();
        let (thread_id, artifact_id) = {
            let vault = Vault::open(path, test_config())?;
            clear_default_policy_manifest(&vault);
            let actor = put_actor(&vault, 10);
            let artifact_id = put_workbook(&vault, actor, 10);
            let thread = vault.open_annotation_thread(
                &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
                actor,
                "Please double-check this quarter's totals.",
                test_time(11),
                11,
            )?;
            vault.add_annotation_comment(
                &artifact_id,
                &thread.thread_id,
                actor,
                "Agreed, the Q3 column looks off.",
                test_time(12),
                12,
            )?;
            (thread.thread_id, artifact_id)
        };

        // The viewer is gone; reopen the vault from disk.
        let reopened = Vault::open(path, test_config())?;
        let thread = reopened
            .get_annotation_thread(&artifact_id, &thread_id)?
            .expect("thread persisted");
        assert_eq!(thread.state, ThreadState::Open);
        assert_eq!(thread.anchor.version, 1);
        assert_eq!(
            thread.anchor.locator,
            Locator::xlsx("Sheet1", "B2:C4").expect("locator")
        );
        let comments = reopened.annotation_thread_comments(&artifact_id, &thread_id)?;
        assert_eq!(comments.len(), 2);
        assert_eq!(
            comments[0].text,
            "Please double-check this quarter's totals."
        );
        assert_eq!(comments[1].text, "Agreed, the Q3 column looks off.");
        Ok(())
    }

    // Acceptance test 2: a manifest replay across a version bump moves an
    // anchor to its new position.
    #[test]
    fn reanchor_moves_anchor_across_version_bump() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "B5:D8"),
            actor,
            "Anchor me at B5:D8.",
            test_time(11),
            11,
        )?;
        // Bump to v2, inserting two rows above row 1 (the block slides down).
        vault.append_blob_artifact_version(
            &artifact_id,
            b"workbook bytes v2",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(12),
            12,
        )?;
        let summary = vault.reanchor_annotation_threads(
            &artifact_id,
            1,
            2,
            &[ReanchorOp::InsertRows {
                sheet: "Sheet1".to_owned(),
                at_row: 1,
                count: 2,
            }],
            actor,
            test_time(12),
            12,
        )?;
        assert_eq!(summary.remapped.len(), 1);
        assert!(summary.drifted.is_empty());

        let moved = vault
            .get_annotation_thread(&artifact_id, &thread.thread_id)?
            .expect("thread");
        assert!(!moved.is_drifted());
        assert_eq!(moved.anchor.version, 2);
        assert_eq!(
            moved.anchor.locator,
            Locator::xlsx("Sheet1", "B7:D10").expect("locator")
        );
        // The reader collapses to a single live head after the supersede.
        assert_eq!(
            vault.annotation_threads_for_artifact(&artifact_id)?.len(),
            1
        );
        Ok(())
    }

    // Acceptance test 3: a non-mappable anchor becomes DRIFTED, pinned to its
    // original version — never silently repositioned.
    #[test]
    fn nonmappable_anchor_is_marked_drifted() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "B5:C6"),
            actor,
            "This region gets deleted.",
            test_time(11),
            11,
        )?;
        vault.append_blob_artifact_version(
            &artifact_id,
            b"workbook bytes v2",
            &BlobVersionProvenance::UserUpload,
            actor,
            test_time(12),
            12,
        )?;
        // Delete exactly the anchored rows: the region is destroyed.
        let summary = vault.reanchor_annotation_threads(
            &artifact_id,
            1,
            2,
            &[ReanchorOp::DeleteRows {
                sheet: "Sheet1".to_owned(),
                at_row: 5,
                count: 2,
            }],
            actor,
            test_time(12),
            12,
        )?;
        assert!(summary.remapped.is_empty());
        assert_eq!(summary.drifted.len(), 1);

        let drifted = vault
            .get_annotation_thread(&artifact_id, &thread.thread_id)?
            .expect("thread");
        assert!(drifted.is_drifted());
        // Pinned to the ORIGINAL version with the ORIGINAL locator — no lie.
        assert_eq!(drifted.anchor.version, 1);
        assert_eq!(
            drifted.anchor.locator,
            Locator::xlsx("Sheet1", "B5:C6").expect("locator")
        );
        let marker = drifted.drift.expect("drift marker");
        assert_eq!(marker.pinned_version, 1);
        assert_eq!(marker.drifted_at_version, 2);
        Ok(())
    }

    // Acceptance test 4: an assigned thread yields a task-brief carrying the
    // anchor payload + thread text + artifact@version.
    #[test]
    fn assigned_thread_yields_task_brief() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
            actor,
            "Please recompute the totals column.",
            test_time(11),
            11,
        )?;
        vault.add_annotation_comment(
            &artifact_id,
            &thread.thread_id,
            actor,
            "Use the new tax rate.",
            test_time(12),
            12,
        )?;
        let agent_id = EntityId::now();
        vault.put_entity(&agent_id, ENTITY_TYPE_PERSON, test_time(10), 10, b"agent")?;

        let brief = vault.assign_annotation_thread_to_brief(
            &artifact_id,
            &thread.thread_id,
            Some(agent_id),
            actor,
            test_time(13),
            13,
        )?;

        assert_eq!(brief.thread_id, thread.thread_id);
        assert_eq!(brief.assignee, Some(agent_id));
        // Anchor payload.
        assert_eq!(brief.anchor.artifact_id, artifact_id);
        assert_eq!(brief.anchor.version, 1);
        assert_eq!(
            brief.anchor.locator,
            Locator::xlsx("Sheet1", "B2:C4").expect("locator")
        );
        // artifact@version.
        assert_eq!(brief.artifact_version, 1);
        // Thread text (both comments, in order).
        assert_eq!(
            brief.thread_text,
            "Please recompute the totals column.\nUse the new tax rate."
        );
        assert!(brief.brief_ref.starts_with("brief:"));
        // The TASK entity is a real productivity task.
        assert_eq!(
            vault.get_entity_type(&brief.task_id)?,
            Some(ENTITY_TYPE_TASK)
        );
        Ok(())
    }

    #[test]
    fn resolve_supersedes_thread_head() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "A1"),
            actor,
            "Resolve me.",
            test_time(11),
            11,
        )?;
        let resolved = vault.set_annotation_thread_state(
            &artifact_id,
            &thread.thread_id,
            ThreadState::Resolved,
            actor,
            test_time(12),
            12,
        )?;
        assert_eq!(resolved.state, ThreadState::Resolved);
        assert_ne!(resolved.head_claim_id, thread.head_claim_id);
        // Exactly one live head remains after the supersede.
        let live = vault.annotation_threads_for_artifact(&artifact_id)?;
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].state, ThreadState::Resolved);
        Ok(())
    }

    #[test]
    fn open_thread_rejects_bad_anchor_version() {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        // Version 2 does not exist yet (head is v1).
        let err = vault
            .open_annotation_thread(
                &xlsx_anchor(artifact_id, 2, "Sheet1", "A1"),
                actor,
                "no such version",
                test_time(11),
                11,
            )
            .expect_err("anchor beyond head must fail");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAnchor);
    }

    // PR #397 fix 1: the live-read gate ([`claim_surfaceable`]) hides an
    // agent-authored (Proposed) head, so it can never override an admitted
    // human head via newest-UUID-wins selection.
    #[test]
    fn agent_proposed_head_does_not_override_human_head() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let human = put_actor(&vault, 10);
        let agent = put_agent_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, human, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
            human,
            "Human-opened, stays Open.",
            test_time(11),
            11,
        )?;

        // An agent writes a SECOND live head for the same thread, flipping the
        // state to Resolved. It lands `Active` but only `Proposed`.
        let agent_head = ThreadHead {
            thread_id: thread.thread_id,
            origin_version: thread.origin_version,
            anchor_version: thread.anchor.version,
            state: ThreadState::Resolved,
            locator: thread.anchor.locator.clone(),
            drift: thread.drift,
        };
        let agent_head_id = vault.with_write_txn(|wtxn| {
            vault.write_thread_head_in_txn(
                wtxn,
                &artifact_id,
                &agent_head,
                agent,
                "set_state",
                test_time(12),
                12,
            )
        })?;
        // The agent head really is a live-but-unadmitted second head.
        let agent_body = vault.get_claim(&agent_head_id)?.expect("agent head claim");
        assert_eq!(
            agent_body.lifecycle,
            crate::claim::ClaimLifecycleStatus::Active
        );
        assert_eq!(agent_body.approval, ClaimApprovalStatus::Proposed);
        // Both heads are live (ungated); the gate must pick only the human one.
        assert_eq!(live_thread_head_claim_ids(&vault, &artifact_id).len(), 2);

        let read = vault
            .get_annotation_thread(&artifact_id, &thread.thread_id)?
            .expect("thread");
        assert_eq!(read.state, ThreadState::Open);
        assert_eq!(read.head_claim_id, thread.head_claim_id);
        let listed = vault.annotation_threads_for_artifact(&artifact_id)?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, ThreadState::Open);
        assert_eq!(listed[0].head_claim_id, thread.head_claim_id);
        Ok(())
    }

    // PR #397 fix 2: the new-head write and the old-head supersession share one
    // txn, so a supersession the source-trust guard rejects (an agent claim
    // superseding human-stated truth) persists NOTHING — the original head
    // stays the single live head and no orphan claim is left behind.
    #[test]
    fn agent_supersede_rejected_leaves_original_head_live() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let human = put_actor(&vault, 10);
        let agent = put_agent_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, human, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "A1"),
            human,
            "Human truth.",
            test_time(11),
            11,
        )?;

        // An agent resolving the human-opened thread supersedes human-stated
        // truth: the guard rejects and the whole txn rolls back.
        let err = vault
            .set_annotation_thread_state(
                &artifact_id,
                &thread.thread_id,
                ThreadState::Resolved,
                agent,
                test_time(12),
                12,
            )
            .expect_err("agent cannot supersede human-stated head");
        assert!(matches!(err, Error::InvalidClaimBody(_)));

        // Original head still live and single; the rejected head left no orphan.
        assert_eq!(
            live_thread_head_claim_ids(&vault, &artifact_id),
            vec![thread.head_claim_id]
        );
        let read = vault
            .get_annotation_thread(&artifact_id, &thread.thread_id)?
            .expect("thread");
        assert_eq!(read.state, ThreadState::Open);
        assert_eq!(read.head_claim_id, thread.head_claim_id);
        Ok(())
    }

    // PR #397 fix 3: reanchor axis math is checked — an anchor near u32::MAX
    // that an insert (or delete band) would push past the grid drifts rather
    // than wrapping (release) or panicking (debug) into a corrupt locator.
    #[test]
    fn reanchor_math_drifts_near_u32_max_instead_of_wrapping() {
        let near_max = format!("B{}:B{}", u32::MAX - 5, u32::MAX);
        let locator = Locator::xlsx("Sheet1", &near_max).expect("locator");
        // Inserting rows below the anchor would shift it past u32::MAX.
        let insert_overflow = replay_locator(
            &locator,
            &[ReanchorOp::InsertRows {
                sheet: "Sheet1".to_owned(),
                at_row: 1,
                count: 10,
            }],
        );
        assert_eq!(insert_overflow, ReanchorOutcome::Drifted);
        // A delete band whose `at + count - 1` overflows is also non-mappable.
        let delete_overflow = replay_locator(
            &locator,
            &[ReanchorOp::DeleteRows {
                sheet: "Sheet1".to_owned(),
                at_row: u32::MAX,
                count: 10,
            }],
        );
        assert_eq!(delete_overflow, ReanchorOutcome::Drifted);
    }

    // PR #397 fix 4: reanchor validates `to_version` against the artifact's
    // version chain (the same guard thread-open applies) before writing any
    // head, so a replay against a not-yet-appended version writes nothing.
    #[test]
    fn reanchor_to_nonexistent_version_errors_and_writes_no_head() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "B5:D8"),
            actor,
            "Anchor me.",
            test_time(11),
            11,
        )?;

        // v2 was never appended (head is still v1): reanchoring 1 -> 2 must fail.
        let err = vault
            .reanchor_annotation_threads(
                &artifact_id,
                1,
                2,
                &[ReanchorOp::InsertRows {
                    sheet: "Sheet1".to_owned(),
                    at_row: 1,
                    count: 2,
                }],
                actor,
                test_time(12),
                12,
            )
            .expect_err("reanchor to nonexistent version must fail");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAnchor);

        // No replacement head was written; the original head is untouched.
        assert_eq!(
            live_thread_head_claim_ids(&vault, &artifact_id),
            vec![thread.head_claim_id]
        );
        let unchanged = vault
            .get_annotation_thread(&artifact_id, &thread.thread_id)?
            .expect("thread");
        assert_eq!(unchanged.anchor.version, 1);
        assert_eq!(unchanged.head_claim_id, thread.head_claim_id);
        assert!(!unchanged.is_drifted());
        Ok(())
    }

    // PR #397 fix 5: one malformed annotation.thread claim (writable through
    // the generic claim API) is skipped on read instead of taking down the
    // whole listing.
    #[test]
    fn malformed_thread_claim_is_skipped_on_listing() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
            actor,
            "A well-formed thread.",
            test_time(11),
            11,
        )?;

        // A garbage annotation.thread claim whose value is not a decodable head.
        let garbage_id = EntityId::now();
        let envelope = annotation_envelope(actor, "open_thread")?;
        vault.with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate(
                    &garbage_id,
                    ClaimCandidate::new(
                        ANNOTATION_THREAD_PREDICATE,
                        ClaimSubject::Entity(artifact_id),
                        Value::from("not a thread head"),
                        1.0,
                    ),
                    &envelope,
                    test_time(12),
                    12,
                )
                .apply(wtxn)
        })?;
        // The garbage really is a live annotation.thread claim on the artifact.
        assert_eq!(live_thread_head_claim_ids(&vault, &artifact_id).len(), 2);

        // The listing skips the garbage and still serves the valid thread.
        let threads = vault.annotation_threads_for_artifact(&artifact_id)?;
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].thread_id, thread.thread_id);
        assert!(
            vault
                .get_annotation_thread(&artifact_id, &thread.thread_id)?
                .is_some()
        );
        Ok(())
    }

    // PR #397 fix 6: the transcript snapshot is persisted in the brief claim,
    // so a comment appended after assignment does not rewrite the handed-off
    // transcript that `annotation_brief_for_thread` reconstructs.
    #[test]
    fn persisted_brief_transcript_is_stable_after_later_comment() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = put_actor(&vault, 10);
        let artifact_id = put_workbook(&vault, actor, 10);
        let thread = vault.open_annotation_thread(
            &xlsx_anchor(artifact_id, 1, "Sheet1", "B2:C4"),
            actor,
            "First note.",
            test_time(11),
            11,
        )?;

        let brief = vault.assign_annotation_thread_to_brief(
            &artifact_id,
            &thread.thread_id,
            None,
            actor,
            test_time(12),
            12,
        )?;
        assert_eq!(brief.thread_text, "First note.");

        // A comment added AFTER assignment must not change the durable brief.
        vault.add_annotation_comment(
            &artifact_id,
            &thread.thread_id,
            actor,
            "Later addendum.",
            test_time(13),
            13,
        )?;
        let persisted = vault
            .annotation_brief_for_thread(&artifact_id, &thread.thread_id)?
            .expect("persisted brief");
        assert_eq!(persisted.thread_text, "First note.");
        assert_eq!(persisted.brief_ref, brief.brief_ref);
        assert_eq!(persisted.task_id, brief.task_id);
        assert_eq!(persisted.anchor.version, 1);
        assert_eq!(persisted.anchor.locator, thread.anchor.locator);
        // The live thread does carry the new comment; only the snapshot froze.
        assert_eq!(
            vault
                .annotation_thread_comments(&artifact_id, &thread.thread_id)?
                .len(),
            2
        );
        Ok(())
    }
}
