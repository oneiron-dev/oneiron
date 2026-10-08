//! The three delta capture lanes plus the precedence chooser; pure over inputs.

use std::ops::Range;

use rmpv::Value;

use crate::edit_distance::FinalizedProposalText;
use crate::edit_distance::myers::{collapse_whitespace, myers_line_diff};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

use super::schema::{AmendmentDelta, DeltaSource, OpsSummary, engine_ver, u32_saturating};
use crate::error::ArtifactError;

/// Traversal depth cap for [`delta_from_field_diff`]. Past it, a subtree is
/// compared as one opaque leaf: a Δ is telemetry, and no telemetry number is
/// worth a stack overflow on a body whose nesting the caller did not choose.
pub(super) const MAX_FIELD_DIFF_DEPTH: u32 = 64;

// ---------------------------------------------------------------------------
// Lane 1 — recorded ops
// ---------------------------------------------------------------------------

/// Measures a Δ by replaying ED-00's finalized op window.
///
/// `ins`/`del` sum the changed region of EVERY recorded change, so text the
/// decider typed and then replaced is counted twice — deliberately. That
/// churn is the recorded-ops lane's whole advantage over comparing the two
/// endpoints, and it is what the miner reads as effort.
///
/// `kept` is measured at the ENDPOINTS instead (the proposal text still
/// standing at finalize), because summing per-change survivals would count
/// the untouched remainder once per change.
///
/// Every text is measured in its whitespace-collapsed form, and a change
/// that touches only whitespace (its texts hold the same non-whitespace
/// characters in the same order) is layout and records nothing, however the
/// log grouped it.
///
/// Moves are paired at the endpoints by the reconstructed lane's own
/// instrument ([`myers_line_diff`]): a line that left one place and arrived
/// at another must have been removed and added somewhere in the op log, so
/// its characters come out of `del` and `ins` once each and are charged in
/// `moved` at the move discount instead. The replay tracks which characters
/// the log itself typed, so a pair is capped at the proposal text the log
/// removed and the typed text that survives to finalize. Text typed and then
/// deleted is churn: it is in neither cap, so it keeps its full price however
/// the log split it. The caps are totals, not positions: where a move's line
/// repeats the characters around it, the log can show less than the line,
/// and a proposal character deleted and retyped there can still raise the
/// move toward the line's weight.
///
/// The per-change region is the span between the common prefix and the
/// common suffix — one contiguous edit. A change that scatters edits across
/// a line reads as one wider region, which under-counts `kept` and never
/// under-counts `ins`/`del`.
#[must_use]
pub fn delta_from_recorded_ops(finalized: &FinalizedProposalText) -> AmendmentDelta {
    let log = LoggedMass::replay(finalized);
    let window = CharAffix::between(
        &collapse_whitespace(&finalized.proposed_text),
        &collapse_whitespace(&finalized.final_text),
    );
    let endpoints = myers_line_diff(&finalized.proposed_text, &finalized.final_text).ops;
    let moved = endpoints
        .moved
        .min(log.ins - log.churn_ins)
        .min(log.del - log.churn_del);
    let ops_summary = OpsSummary {
        ins: log.ins - moved,
        del: log.del - moved,
        kept: window.common(),
        moved,
        approx: endpoints.approx && moved > 0,
    };
    AmendmentDelta {
        proposed_ref: bytes_to_hex_lower(finalized.proposed_ref.as_bytes()),
        final_ref: bytes_to_hex_lower(finalized.final_ref.as_bytes()),
        source: DeltaSource::RecordedOps,
        d_norm: ops_summary.d_norm(window.before_len, window.after_len),
        ops_summary,
        engine_ver: engine_ver(),
    }
}

/// What the op log removed and added, and how much of each was churn: text
/// the log typed and then removed again.
struct LoggedMass {
    ins: u32,
    del: u32,
    /// Typed characters that do not survive to the last change.
    churn_ins: u32,
    /// Removed characters that the log itself had typed.
    churn_del: u32,
}

impl LoggedMass {
    fn replay(finalized: &FinalizedProposalText) -> Self {
        let mut mass = Self {
            ins: 0,
            del: 0,
            churn_ins: 0,
            churn_del: 0,
        };
        // `typed[i]`: whether character `i` of the current collapsed text was
        // typed by a recorded change rather than proposed.
        let mut typed: Vec<bool> = Vec::new();
        for (_, span) in &finalized.ops_by_actor {
            let before = collapse_whitespace(&span.before_text);
            let after = collapse_whitespace(&span.after_text);
            let affix = CharAffix::between(&before, &after);
            // The replay seam chains each change onto the last; a log that
            // does not chain restarts provenance at this change.
            if typed.len() != affix.before_len as usize {
                typed = vec![false; affix.before_len as usize];
            }
            let layout_only = before
                .chars()
                .filter(|c| !c.is_whitespace())
                .eq(after.chars().filter(|c| !c.is_whitespace()));
            let region = affix.prefix as usize..(affix.before_len - affix.suffix) as usize;
            let added = affix.added() as usize;
            let arrived: Vec<bool> = if layout_only {
                carry_provenance(&before, &after, &typed, region.clone(), added)
            } else {
                vec![true; added]
            };
            let removed_typed = typed[region.clone()].iter().filter(|t| **t).count();
            typed.splice(region, arrived).for_each(drop);
            if layout_only {
                continue;
            }
            mass.del = mass.del.saturating_add(affix.removed());
            mass.ins = mass.ins.saturating_add(affix.added());
            mass.churn_del = mass.churn_del.saturating_add(u32_saturating(removed_typed));
        }
        let survived = u32_saturating(typed.iter().filter(|t| **t).count());
        mass.churn_ins = mass.ins.saturating_sub(survived);
        mass
    }
}

/// The provenance of a layout-only change's arrived region: it moves no
/// character, so each non-whitespace character keeps its flag, and a space
/// keeps the flag of the space that stood between the same two characters
/// (a new space is layout, not typed text).
fn carry_provenance(
    before: &str,
    after: &str,
    typed: &[bool],
    region: Range<usize>,
    added: usize,
) -> Vec<bool> {
    let start = region.start;
    let mut letters: Vec<bool> = Vec::new();
    let mut spaces: Vec<Option<bool>> = vec![None];
    for (c, flag) in before.chars().skip(region.start).zip(&typed[region]) {
        if c.is_whitespace() {
            if let Some(gap) = spaces.last_mut() {
                *gap = Some(*flag);
            }
        } else {
            letters.push(*flag);
            spaces.push(None);
        }
    }
    let mut seen = 0;
    after
        .chars()
        .skip(start)
        .take(added)
        .map(|c| {
            if c.is_whitespace() {
                spaces.get(seen).copied().flatten().unwrap_or(false)
            } else {
                seen += 1;
                letters.get(seen - 1).copied().unwrap_or(false)
            }
        })
        .collect()
}

/// Two strings split at their common prefix and suffix, in CHARACTERS —
/// bytes would let a multi-byte edit report a fractional change.
struct CharAffix {
    prefix: u32,
    suffix: u32,
    before_len: u32,
    after_len: u32,
}

impl CharAffix {
    fn between(before: &str, after: &str) -> Self {
        let before: Vec<char> = before.chars().collect();
        let after: Vec<char> = after.chars().collect();
        let prefix = before
            .iter()
            .zip(&after)
            .take_while(|(left, right)| left == right)
            .count();
        // The prefix and suffix must not overlap on the shorter side, or a
        // repeated run ("aaa" -> "aaaaa") would report negative change.
        let overlap_budget = before.len().min(after.len()) - prefix;
        let suffix = before
            .iter()
            .rev()
            .zip(after.iter().rev())
            .take(overlap_budget)
            .take_while(|(left, right)| left == right)
            .count();
        Self {
            prefix: u32_saturating(prefix),
            suffix: u32_saturating(suffix),
            before_len: u32_saturating(before.len()),
            after_len: u32_saturating(after.len()),
        }
    }

    const fn common(&self) -> u32 {
        self.prefix.saturating_add(self.suffix)
    }

    const fn removed(&self) -> u32 {
        self.before_len.saturating_sub(self.common())
    }

    const fn added(&self) -> u32 {
        self.after_len.saturating_sub(self.common())
    }
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
/// # Errors
///
/// [`Error::CorruptedIndex`] when either side is not decodable MessagePack.
pub fn delta_from_field_diff(proposed: &[u8], finalized: &[u8]) -> Result<AmendmentDelta> {
    let before = decode_body(proposed)?;
    let after = decode_body(finalized)?;
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
        proposed_ref: bytes_to_hex_lower(blake3::hash(proposed).as_bytes()),
        final_ref: bytes_to_hex_lower(blake3::hash(finalized).as_bytes()),
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
/// The refs are the two texts' own blake3 hashes, so a consumer can verify
/// the pair it was handed — the same contract the field-diff lane keeps.
#[must_use]
pub fn delta_from_reconstructed(before: &str, after: &str) -> AmendmentDelta {
    let diff = myers_line_diff(before, after);
    AmendmentDelta {
        proposed_ref: bytes_to_hex_lower(blake3::hash(before.as_bytes()).as_bytes()),
        final_ref: bytes_to_hex_lower(blake3::hash(after.as_bytes()).as_bytes()),
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
    /// ED-00's finalized op window, when the artifact rode one.
    pub recorded: Option<&'a FinalizedProposalText>,
    /// `(proposed, finalized)` canonical-MessagePack bodies.
    pub bodies: Option<(&'a [u8], &'a [u8])>,
    /// `(before, after)` endpoint texts, for an edit that rode neither.
    pub texts: Option<(&'a str, &'a str)>,
}

impl<'a> DeltaCaptureContext<'a> {
    /// Context for two structured bodies.
    #[must_use]
    pub const fn from_bodies(proposed: &'a [u8], finalized: &'a [u8]) -> Self {
        Self {
            recorded: None,
            bodies: Some((proposed, finalized)),
            texts: None,
        }
    }

    /// Context for two endpoint texts — the out-of-band edit.
    #[must_use]
    pub const fn from_texts(before: &'a str, after: &'a str) -> Self {
        Self {
            recorded: None,
            bodies: None,
            texts: Some((before, after)),
        }
    }
}

/// Captures the best Δ the context supports: `recorded_ops > field_diff >
/// reconstructed` (ruling r2 — Myers is never preferred when ops exist).
///
/// # Errors
///
/// [`ArtifactError::DeltaCaptureUnavailable`](crate::error::ArtifactError::DeltaCaptureUnavailable) when the context offers no lane at all.
/// Callers treat it as telemetry loss, never as a failed approval.
pub fn capture_delta_best(ctx: &DeltaCaptureContext<'_>) -> Result<AmendmentDelta> {
    if let Some(recorded) = ctx.recorded {
        return Ok(delta_from_recorded_ops(recorded));
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
