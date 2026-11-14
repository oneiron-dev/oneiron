//! Moved from `crates/oneiron/src/edit_distance/delta/schema.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::edit_distance::myers::MOVE_DISCOUNT;
use serde::Deserialize;
use serde::Serialize;

/// How an [`AmendmentDelta`] was measured. Ordered by precedence, and the
/// token is pinned: a receipt's Δ payload carries it on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaSource {
    /// Replayed from ED-00's recorded op window.
    RecordedOps,
    /// Structured per-field diff of two canonical-MessagePack bodies.
    FieldDiff,
    /// Reconstructed after the fact by diffing the two endpoint texts.
    Reconstructed,
}

impl DeltaSource {
    /// The pinned on-disk token for this lane.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordedOps => "recorded_ops",
            Self::FieldDiff => "field_diff",
            Self::Reconstructed => "reconstructed",
        }
    }
}

/// The edit mass behind a Δ, in the unit its lane counts: CHARACTERS of the
/// whitespace-normalized text for [`DeltaSource::RecordedOps`] and
/// [`DeltaSource::Reconstructed`], LEAVES for [`DeltaSource::FieldDiff`].
///
/// `moved` is the discount channel: a producer that DETECTS a move records
/// the relocated units here and leaves them out of `ins`/`del`, so relocated
/// content is charged once and cheaply instead of twice at full price. Both
/// text lanes detect moved lines; the field-diff lane compares arrays
/// positionally and reports `0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsSummary {
    /// Units inserted.
    pub ins: u32,
    /// Units deleted.
    pub del: u32,
    /// Units the amendment left standing.
    pub kept: u32,
    /// Units relocated rather than rewritten (see the type docs).
    pub moved: u32,
    /// Whether the producer hit its own cost cap, leaving these counts an
    /// upper BOUND rather than an exact script.
    ///
    /// Only the text lanes can set it: the Myers trace is the only capped
    /// work in the module, and the recorded-ops lane pairs its moves with it.
    /// It rides the Δ onto disk because a consumer reading a capped diff as
    /// exact is the one way this telemetry lies.
    pub approx: bool,
}

impl OpsSummary {
    /// `clamp(edit_mass / (len_before + len_after), 0, 1)` — the ONE ratified
    /// ED metric, with `edit_mass = ins + del + 2 · MOVE_DISCOUNT · moved`.
    ///
    /// Every producer normalizes HERE so no two lanes can drift into
    /// different numbers. Two properties the callers depend on:
    ///
    /// * The denominator SUMS the two lengths rather than taking the max,
    ///   because a rewritten unit is one deletion AND one insertion: a full
    ///   replacement scores exactly `1`, where a max denominator would score
    ///   it `2`.
    /// * A zero-length window scores `0`. Nothing changed, because there was
    ///   nothing to change.
    #[must_use]
    pub fn d_norm(self, len_before: u32, len_after: u32) -> f32 {
        let window = len_before.saturating_add(len_after);
        if window == 0 {
            return 0.0;
        }
        let ratio = self.edit_mass() / f64::from(window);
        ratio.clamp(0.0, 1.0) as f32
    }

    /// The edit mass `d_norm` normalizes. A relocated unit costs
    /// `2 · MOVE_DISCOUNT` where the delete-plus-insert it stands in for
    /// would cost `2`.
    #[must_use]
    pub fn edit_mass(self) -> f64 {
        let relocated = f64::from(2.0 * MOVE_DISCOUNT) * f64::from(self.moved);
        f64::from(self.ins) + f64::from(self.del) + relocated
    }
}
