//! Moved from `crates/oneiron/src/learning/judge.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The score map from an old judge's scale to its successor's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeConversion {
    pub from_judge: String,
    pub to_judge: String,
    /// Monotone `(old, new)` knots, ascending in `old`; scores between knots
    /// interpolate and scores past the ends clamp to the end knot.
    pub points: Vec<(f64, f64)>,
    /// How many overlap cases the map was fitted from.
    pub overlap_cases: u32,
    pub at: u64,
    /// Whether this map's chain from `from_judge` through the stored
    /// conversions resolves or loops; reporting only, recomputed on every
    /// record/withdraw — recording still succeeds when cyclic.
    pub chain: ConversionChainStatus,
}

impl JudgeConversion {
    /// Maps an old-judge score onto the new judge's scale.
    #[must_use]
    pub fn map(&self, x: f64) -> f64 {
        let Some(first) = self.points.first() else {
            return x;
        };
        if x <= first.0 {
            return first.1;
        }
        for pair in self.points.windows(2) {
            let ((x0, y0), (x1, y1)) = (pair[0], pair[1]);
            if x <= x1 {
                if x1 == x0 {
                    return y1;
                }
                return y0 + (x - x0) * (y1 - y0) / (x1 - x0);
            }
        }
        self.points.last().map_or(x, |last| last.1)
    }
}

/// Whether a conversion map's chain from its old judge resolves or loops.
/// Reporting only: recording still succeeds when cyclic, and the status is
/// recomputed on every record and withdraw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionChainStatus {
    /// The chain from `from_judge` through the stored conversions reaches a
    /// terminal judge.
    Valid,
    /// The chain loops back on itself; the lineage folds as unknown.
    Cyclic,
}
