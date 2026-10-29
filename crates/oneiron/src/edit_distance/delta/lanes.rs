//! The three delta capture lanes plus the precedence chooser; pure over inputs.

use rmpv::Value;

use crate::edit_distance::RetainedProposal;
use crate::edit_distance::myers::myers_line_diff;
use crate::error::{Error, Result};

use super::endpoint::{EndpointRef, MeasuredEnd};
use super::op_stream::read_window;
use super::schema::{AmendmentDelta, DeltaSource, OpsSummary, engine_ver};
use crate::error::ArtifactError;

/// Traversal depth cap for [`delta_from_field_diff`]. Past it, a subtree is
/// compared as one opaque leaf: a Δ is telemetry, and no telemetry number is
/// worth a stack overflow on a body whose nesting the caller did not choose.
pub(super) const MAX_FIELD_DIFF_DEPTH: u32 = 64;

// ---------------------------------------------------------------------------
// Lane 1 — recorded ops
// ---------------------------------------------------------------------------

/// Measures a Δ from the authored op stream of ED-00's finalized window, read
/// out of the proposal's retained document (FIX 7820).
///
/// `ins`/`del` sum the insert and delete runs of EVERY recorded change, so
/// text the decider typed and then replaced is counted twice — deliberately.
/// That churn is the recorded-ops lane's whole advantage over comparing the
/// two endpoints, and it is what the miner reads as effort. Runs scattered
/// through one change stay separate runs.
///
/// `kept` is the proposal text still standing at finalize. Moves are paired
/// from the runs themselves: a deleted run of proposal text and an inserted
/// run that survived with the same collapsed content left `del` and `ins`
/// once each and are charged in `moved` at the move discount. Every count is
/// exact, so `approx` is never set.
///
/// Both refs name the artifact's document at the window's two versions.
///
/// # Errors
///
/// [`ArtifactError::DeltaCaptureUnavailable`] when the retained document, or
/// a version the window names in it, no longer reads. There is no fallback
/// measurement under this lane's name.
pub fn delta_from_recorded_ops(retained: &RetainedProposal) -> Result<AmendmentDelta> {
    let document = retained.document().map_err(|_| {
        Error::Artifact(ArtifactError::DeltaCaptureUnavailable(
            "the proposal's retained document does not read",
        ))
    })?;
    let record = &retained.record;
    let runs = read_window(document, record)?;
    let ops_summary = OpsSummary {
        ins: runs.ins,
        del: runs.del,
        kept: runs.kept,
        moved: runs.moved,
        approx: false,
    };
    Ok(AmendmentDelta {
        proposed_ref: EndpointRef::proposal(record.artifact_ref, &record.proposed_ref),
        final_ref: EndpointRef::proposal(record.artifact_ref, &record.final_ref),
        source: DeltaSource::RecordedOps,
        d_norm: ops_summary.d_norm(runs.before_len, runs.after_len),
        ops_summary,
        engine_ver: engine_ver(),
    })
}

// ---------------------------------------------------------------------------
// Lane 2 — field diff
// ---------------------------------------------------------------------------

/// Measures a Δ by walking two canonical-MessagePack bodies as trees and
/// counting changed LEAVES.
///
/// A leaf at the same path that differs is one deletion AND one insertion —
/// the field was rewritten, not merely touched — so a body where every field
/// changed scores `d_norm == 1`, matching the character lane's full-rewrite
/// score.
///
/// Arrays are compared POSITIONALLY: a reordered list reads as changes until
/// a move-detecting producer lands (see [`OpsSummary`]). Identity-topology
/// bodies canonicalize their arrays at the encode door, so their order is
/// meaning, not accident.
///
/// Each ref names the retained source its body was read from, with the
/// body's blake3 beside it as a check value.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] when either side is not decodable MessagePack.
pub fn delta_from_field_diff(
    proposed: MeasuredEnd<'_, [u8]>,
    finalized: MeasuredEnd<'_, [u8]>,
) -> Result<AmendmentDelta> {
    let before = decode_body(proposed.content)?;
    let after = decode_body(finalized.content)?;
    let mut counts = LeafCounts::default();
    diff_values(&before, &after, 0, &mut counts);
    let ops_summary = OpsSummary {
        ins: counts.ins,
        del: counts.del,
        kept: counts.kept,
        moved: 0,
        approx: false,
    };
    Ok(AmendmentDelta {
        proposed_ref: proposed.at.with_content(proposed.content),
        final_ref: finalized.at.with_content(finalized.content),
        source: DeltaSource::FieldDiff,
        d_norm: ops_summary.d_norm(counts.before, counts.after),
        ops_summary,
        engine_ver: engine_ver(),
    })
}

fn decode_body(bytes: &[u8]) -> Result<Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::CorruptedIndex("amendment delta body"))?;
    if cursor.is_empty() {
        Ok(value)
    } else {
        Err(Error::CorruptedIndex("amendment delta body"))
    }
}

#[derive(Default)]
struct LeafCounts {
    ins: u32,
    del: u32,
    kept: u32,
    before: u32,
    after: u32,
}

impl LeafCounts {
    /// Charges a whole subtree present only on the before side.
    fn removed_subtree(&mut self, value: &Value) {
        let leaves = leaf_count(value);
        self.del = self.del.saturating_add(leaves);
        self.before = self.before.saturating_add(leaves);
    }

    /// Charges a whole subtree present only on the after side.
    fn added_subtree(&mut self, value: &Value) {
        let leaves = leaf_count(value);
        self.ins = self.ins.saturating_add(leaves);
        self.after = self.after.saturating_add(leaves);
    }
}

fn diff_values(before: &Value, after: &Value, depth: u32, counts: &mut LeafCounts) {
    if depth < MAX_FIELD_DIFF_DEPTH {
        match (before, after) {
            (Value::Map(left), Value::Map(right)) => {
                diff_maps(left, right, depth, counts);
                return;
            }
            (Value::Array(left), Value::Array(right)) => {
                diff_arrays(left, right, depth, counts);
                return;
            }
            _ => {}
        }
    }
    if before == after {
        counts.kept = counts.kept.saturating_add(1);
        counts.before = counts.before.saturating_add(1);
        counts.after = counts.after.saturating_add(1);
    } else {
        counts.removed_subtree(before);
        counts.added_subtree(after);
    }
}

fn diff_maps(
    left: &[(Value, Value)],
    right: &[(Value, Value)],
    depth: u32,
    counts: &mut LeafCounts,
) {
    for (key, value) in left {
        match right.iter().find(|(other, _)| other == key) {
            Some((_, other)) => diff_values(value, other, depth + 1, counts),
            None => counts.removed_subtree(value),
        }
    }
    for (key, value) in right {
        if !left.iter().any(|(other, _)| other == key) {
            counts.added_subtree(value);
        }
    }
}

fn diff_arrays(left: &[Value], right: &[Value], depth: u32, counts: &mut LeafCounts) {
    let shared = left.len().min(right.len());
    for index in 0..shared {
        diff_values(&left[index], &right[index], depth + 1, counts);
    }
    for value in &left[shared..] {
        counts.removed_subtree(value);
    }
    for value in &right[shared..] {
        counts.added_subtree(value);
    }
}

/// Leaves under `value`. An empty map or array has none: adding one changes
/// no field, and charging it as change would score a no-op body rewrite.
fn leaf_count(value: &Value) -> u32 {
    match value {
        Value::Map(entries) => entries.iter().fold(0, |total: u32, (_, value)| {
            total.saturating_add(leaf_count(value))
        }),
        Value::Array(values) => values.iter().fold(0, |total: u32, value| {
            total.saturating_add(leaf_count(value))
        }),
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Lane 3 — reconstructed
// ---------------------------------------------------------------------------

/// Measures a Δ by diffing the two endpoint TEXTS line by line, then
/// character by character inside each changed region, for an edit that
/// arrived with no op log and no structured body — a human editing outside
/// the gated proposal flow.
///
/// Last in precedence for a reason: the endpoints are all it has, so churn
/// (text typed and then replaced) is invisible to it, and a rewrite that
/// happens to land back on the proposed text scores zero. Relocated lines
/// land in [`OpsSummary::moved`] at
/// [`MOVE_DISCOUNT`](crate::edit_distance::myers::MOVE_DISCOUNT) rather than
/// being charged twice as a deletion and an insertion; layout-only changes
/// (whitespace, re-wrapping) are not changes.
///
/// Each ref names the retained source its text was read from, with the
/// text's blake3 beside it as a check value — the same contract the
/// field-diff lane keeps.
#[must_use]
pub fn delta_from_reconstructed(
    before: MeasuredEnd<'_, str>,
    after: MeasuredEnd<'_, str>,
) -> AmendmentDelta {
    let diff = myers_line_diff(before.content, after.content);
    AmendmentDelta {
        proposed_ref: before.at.with_content(before.content.as_bytes()),
        final_ref: after.at.with_content(after.content.as_bytes()),
        source: DeltaSource::Reconstructed,
        d_norm: diff.d_norm,
        ops_summary: diff.ops,
        engine_ver: engine_ver(),
    }
}

// ---------------------------------------------------------------------------
// Chooser
// ---------------------------------------------------------------------------

/// What a caller can offer the chooser — every lane it could measure, not the
/// one it wants. Picking is [`capture_delta_best`]'s job, and keeping that
/// choice out of the caller is the whole point of the type.
pub struct DeltaCaptureContext<'a> {
    /// ED-00's finalized op window with its retained document, when the
    /// artifact rode one.
    pub recorded: Option<&'a RetainedProposal>,
    /// `(proposed, finalized)` canonical-MessagePack bodies.
    pub bodies: Option<(MeasuredEnd<'a, [u8]>, MeasuredEnd<'a, [u8]>)>,
    /// `(before, after)` endpoint texts, for an edit that rode neither.
    pub texts: Option<(MeasuredEnd<'a, str>, MeasuredEnd<'a, str>)>,
}

impl<'a> DeltaCaptureContext<'a> {
    /// Context for two structured bodies.
    #[must_use]
    pub const fn from_bodies(
        proposed: MeasuredEnd<'a, [u8]>,
        finalized: MeasuredEnd<'a, [u8]>,
    ) -> Self {
        Self {
            recorded: None,
            bodies: Some((proposed, finalized)),
            texts: None,
        }
    }

    /// Context for two endpoint texts — the out-of-band edit.
    #[must_use]
    pub const fn from_texts(before: MeasuredEnd<'a, str>, after: MeasuredEnd<'a, str>) -> Self {
        Self {
            recorded: None,
            bodies: None,
            texts: Some((before, after)),
        }
    }
}

/// Captures the best Δ the context supports: `recorded_ops > field_diff >
/// reconstructed` (ruling r2 — Myers is never preferred when ops exist). A
/// recorded window whose document no longer reads yields to the next lane
/// offered, under that lane's own name.
///
/// # Errors
///
/// [`ArtifactError::DeltaCaptureUnavailable`](crate::error::ArtifactError::DeltaCaptureUnavailable) when the context offers no lane that measures.
/// Callers treat it as telemetry loss, never as a failed approval.
pub fn capture_delta_best(ctx: DeltaCaptureContext<'_>) -> Result<AmendmentDelta> {
    if let Some(recorded) = ctx.recorded
        && let Ok(delta) = delta_from_recorded_ops(recorded)
    {
        return Ok(delta);
    }
    if let Some((proposed, finalized)) = ctx.bodies {
        return delta_from_field_diff(proposed, finalized);
    }
    if let Some((before, after)) = ctx.texts {
        return Ok(delta_from_reconstructed(before, after));
    }
    Err(Error::Artifact(ArtifactError::DeltaCaptureUnavailable(
        "context offers no lane",
    )))
}
