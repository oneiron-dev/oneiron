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
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::edit_roundtrip::{AnchorEffect, Axis, CellRef, RangeRef, StructuralShift};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::types::{TaskRole, TimeRange};
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;

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
    fn sheet(&self) -> &str {
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

/// Lowers an ARTL-3 [`AnchorEffect`] — the self-contained reconciliation surface
/// the edit manifest exposes, one per structural op — onto the minimal
/// [`ReanchorOp`] the replay understands (ONE-1554). This is the reconciliation
/// the module docs call for: ARTL-4 (settle) replays a manifest's anchor effects
/// onto the artifact's threads by mapping each through here.
impl From<&AnchorEffect> for ReanchorOp {
    fn from(effect: &AnchorEffect) -> Self {
        match effect {
            AnchorEffect::Shift(shift) => shift_to_reanchor_op(shift),
            AnchorEffect::RangeMoved { sheet, from, to } => Self::MoveRange {
                sheet: sheet.clone(),
                from: range_ref_to_a1(from),
                to: move_dest_to_a1(from, *to),
            },
            AnchorEffect::SheetRenamed { from, to } => Self::RenameSheet {
                from: from.clone(),
                to: to.clone(),
            },
            AnchorEffect::SheetRemoved { name } => Self::RemoveSheet {
                sheet: name.clone(),
            },
        }
    }
}

/// A positive-magnitude row/column shift becomes an insert; a negative one a
/// delete. A zero delta maps to a zero-`count` insert, which the replay skips.
fn shift_to_reanchor_op(shift: &StructuralShift) -> ReanchorOp {
    let sheet = shift.sheet.clone();
    let at = shift.at;
    // Saturate rather than panic on a pathological magnitude; a saturated count
    // that overflows the grid drifts the anchor, the safe outcome.
    let count = u32::try_from(shift.delta.unsigned_abs()).unwrap_or(u32::MAX);
    match (shift.axis, shift.delta >= 0) {
        (Axis::Row, true) => ReanchorOp::InsertRows {
            sheet,
            at_row: at,
            count,
        },
        (Axis::Row, false) => ReanchorOp::DeleteRows {
            sheet,
            at_row: at,
            count,
        },
        (Axis::Column, true) => ReanchorOp::InsertCols {
            sheet,
            at_col: at,
            count,
        },
        (Axis::Column, false) => ReanchorOp::DeleteCols {
            sheet,
            at_col: at,
            count,
        },
    }
}

/// The 1x1 A1 fallback used when a manifest corner is degenerate — unreachable
/// for a validated manifest (ARTL-3 rejects 0-indexed and inverted ranges), but
/// keeps the lowering total and panic-free.
fn a1_unit() -> A1Range {
    A1Range::new(1, 1, 1, 1).expect("A1 is a valid 1x1 range")
}

fn range_ref_to_a1(range: &RangeRef) -> A1Range {
    A1Range::new(
        range.start.col,
        range.end.col,
        range.start.row,
        range.end.row,
    )
    .unwrap_or_else(a1_unit)
}

/// The destination range a move lands on: the source range's shape translated so
/// its top-left corner sits at `to`.
fn move_dest_to_a1(from: &RangeRef, to: CellRef) -> A1Range {
    let width = from.end.col.saturating_sub(from.start.col);
    let height = from.end.row.saturating_sub(from.start.row);
    A1Range::new(
        to.col,
        to.col.saturating_add(width),
        to.row,
        to.row.saturating_add(height),
    )
    .unwrap_or_else(a1_unit)
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
/// A [`ReanchorOp::RenameSheet`] retargets the locator's sheet name so later
/// ops in the same replay still match it; a [`ReanchorOp::RemoveSheet`] on the
/// anchor's sheet destroys it and drifts, never leaving a thread pinned to a
/// stale sheet name.
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
    // The anchor's sheet name is mutable across the replay: a rename retargets
    // it so subsequent ops still match, and the final Mapped carries it.
    let mut cur_sheet = sheet.clone();
    for op in ops {
        if op.sheet() != cur_sheet.as_str() {
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
                    // Partial source overlap is ambiguous: never guess a position.
                    return ReanchorOutcome::Drifted;
                } else if ranges_overlap(to, &cur) {
                    // The anchor sits (partly) at the move's DESTINATION but is not
                    // part of the moved content, so that content was overwritten by
                    // the move. Its cells no longer hold what the anchor named — drift
                    // rather than point at replaced content.
                    return ReanchorOutcome::Drifted;
                }
            }
            ReanchorOp::WriteCells { .. } => {}
            ReanchorOp::RenameSheet { to, .. } => {
                cur_sheet = to.clone();
            }
            ReanchorOp::RemoveSheet { .. } => return ReanchorOutcome::Drifted,
        }
    }
    ReanchorOutcome::Mapped(Locator::Xlsx {
        sheet: cur_sheet,
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

pub(crate) fn encode_locator(locator: &Locator) -> Value {
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

pub(crate) fn decode_locator(value: &Value) -> Result<Locator> {
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
        Ok(threads_from_active_claims(
            *artifact_id,
            self.active_annotation_claims(artifact_id)?,
        ))
    }

    /// Transaction-composable [`Vault::annotation_threads_for_artifact`]: reads
    /// the live thread heads through the caller's txn (settle's re-anchor sweep).
    fn annotation_threads_for_artifact_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
    ) -> Result<Vec<AnnotationThread>> {
        Ok(threads_from_active_claims(
            *artifact_id,
            self.active_annotation_claims_in_txn(rtxn, artifact_id)?,
        ))
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
            let (head, drifted) = plan_reanchored_head(&thread, from_version, to_version, ops);
            // Each thread's head write + old-head supersede share ONE txn, so a
            // rejected supersede leaves that thread's original head live.
            let new_head_id = self.with_write_txn(|wtxn| {
                self.apply_reanchor_head_in_txn(
                    wtxn,
                    artifact_id,
                    &thread,
                    &head,
                    actor,
                    occurred,
                    learned_at,
                )
            })?;
            push_reanchor_result(
                &mut summary,
                thread_from_head(*artifact_id, new_head_id, head),
                drifted,
            );
        }
        Ok(summary)
    }

    /// Transaction-composable re-anchor sweep: replays `ops` onto every live,
    /// non-drifted thread at `from_version`, writing all head updates through the
    /// caller's `wtxn`. ARTL-4 settle-select drives this so the re-anchor commits
    /// atomically with the version append and the consume-once ledger insert —
    /// a crash rolls the whole settle back rather than pinning threads to the old
    /// version. `to_version` is validated against the head visible in `wtxn`, so
    /// the version the same txn just appended resolves.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn reanchor_annotation_threads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        from_version: u64,
        to_version: u64,
        ops: &[ReanchorOp],
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<ReanchorSummary> {
        self.require_anchor_version_in_txn(&*wtxn, artifact_id, to_version)?;
        let mut summary = ReanchorSummary::default();
        let threads = self.annotation_threads_for_artifact_in_txn(&*wtxn, artifact_id)?;
        for thread in threads {
            if thread.is_drifted() || thread.anchor.version != from_version {
                continue;
            }
            let (head, drifted) = plan_reanchored_head(&thread, from_version, to_version, ops);
            let new_head_id = self.apply_reanchor_head_in_txn(
                wtxn,
                artifact_id,
                &thread,
                &head,
                actor,
                occurred,
                learned_at,
            )?;
            push_reanchor_result(
                &mut summary,
                thread_from_head(*artifact_id, new_head_id, head),
                drifted,
            );
        }
        Ok(summary)
    }

    /// Writes one re-anchored head and supersedes the thread's prior head in the
    /// caller's txn, returning the new head claim id.
    #[expect(clippy::too_many_arguments)]
    fn apply_reanchor_head_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        thread: &AnnotationThread,
        head: &ThreadHead,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let new_head_id = self.write_thread_head_in_txn(
            wtxn,
            artifact_id,
            head,
            actor,
            "reanchor",
            occurred,
            learned_at,
        )?;
        self.supersede_claim_in_txn(wtxn, &new_head_id, &thread.head_claim_id, learned_at)?;
        Ok(new_head_id)
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
        let rtxn = self.store.env.read_txn()?;
        self.require_anchor_version_in_txn(&rtxn, artifact_id, version)
    }

    /// Transaction-composable [`Vault::require_anchor_version`]: validates the
    /// target version against the artifact head read through the caller's txn,
    /// so settle sees the version it just appended in the same write txn.
    fn require_anchor_version_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<()> {
        if version == 0 {
            return Err(Error::InvalidAnchor("anchor version must be at least 1"));
        }
        let head =
            crate::blob_artifact::read_blob_artifact_head_in_txn(&self.store, rtxn, artifact_id)?
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
        let rtxn = self.store.env.read_txn()?;
        self.active_annotation_claims_in_txn(&rtxn, artifact_id)
    }

    /// Transaction-composable [`Vault::active_annotation_claims`]: reads the
    /// live-read annotation cohort through the caller's txn, so settle can gather
    /// threads inside the same write txn that appends the version.
    fn active_annotation_claims_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact_id: &EntityId,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut out = Vec::new();
        for claim_id in self.claims_for_subject_in_txn(rtxn, artifact_id)? {
            let Some(body) = self.get_claim_in_txn(rtxn, &claim_id)? else {
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

/// Computes the re-anchored head for one thread across a `from → to` version
/// bump: a mappable anchor advances to `to_version` with its new locator; a
/// non-mappable one drifts and stays pinned to `from_version`. Returns the new
/// head and whether it drifted. Pure — the caller writes it.
fn plan_reanchored_head(
    thread: &AnnotationThread,
    from_version: u64,
    to_version: u64,
    ops: &[ReanchorOp],
) -> (ThreadHead, bool) {
    match replay_locator(&thread.anchor.locator, ops) {
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
    }
}

fn push_reanchor_result(summary: &mut ReanchorSummary, thread: AnnotationThread, drifted: bool) {
    if drifted {
        summary.drifted.push(thread);
    } else {
        summary.remapped.push(thread);
    }
}

/// Groups a live-read annotation claim cohort into one [`AnnotationThread`] per
/// thread id (newest Active head wins on a torn supersede), skipping non-thread
/// predicates and malformed heads. Shared by the own-txn and in-txn listers.
fn threads_from_active_claims(
    artifact_id: EntityId,
    claims: Vec<(EntityId, ClaimBody)>,
) -> Vec<AnnotationThread> {
    let mut heads: Vec<(EntityId, EntityId, ThreadHead)> = Vec::new();
    for (claim_id, body) in claims {
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
        .map(|(_, claim_id, head)| thread_from_head(artifact_id, claim_id, head))
        .collect();
    threads.sort_by_key(|thread| thread.thread_id);
    threads
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
mod tests;
