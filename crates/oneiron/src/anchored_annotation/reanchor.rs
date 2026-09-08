//! Edit-manifest lowering, locator replay math, and the re-anchor sweep (own-txn
//! plus caller-txn).

use super::codec::ThreadHead;
use super::model::{
    A1Range, AnnotationThread, DriftMarker, Locator, ReanchorOp, ReanchorOutcome, ReanchorSummary,
};
use super::threads::thread_from_head;
use crate::Vault;
use crate::edit_roundtrip::{AnchorEffect, Axis, CellRef, RangeRef, StructuralShift};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

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

pub(super) fn parse_a1_cell(text: &str) -> Option<(u32, u32)> {
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

pub(super) fn col_to_letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        let rem = (col - 1) % 26;
        out.push(b'A' + u8::try_from(rem).unwrap_or(0));
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

impl Vault {
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
